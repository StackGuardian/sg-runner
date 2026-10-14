// Package guard is sg-steps-guard, a Docker authorization plugin the step
// broker serves to the runner's dockerd: it refuses to create workflow step
// containers there, as the runner runs steps as pods (a run controller
// without step broker support would otherwise run them in dockerd). See
// k8s/docs/steps-api.md, "Guard".
package guard

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
)

// PluginName is the plugin's name for dockerd (--authorization-plugin): its
// socket is <plugins dir>/<PluginName>.sock.
const PluginName = "sg-steps-guard"

// MediaType is the Docker plugin protocol's content type.
const MediaType = "application/vnd.docker.plugins.v1.2+json"

// StepLabel marks the containers the run controller creates for steps.
const StepLabel = "wfrunId"

// DenyMessage is what dockerd tells the caller of a refused step create.
const DenyMessage = "This runner runs workflow steps as Kubernetes pods and needs a run controller with " +
	"native step support (step broker client); refusing to start the step in dockerd."

// Request is the part of dockerd's authorization request the guard reads
// (github.com/docker/docker/pkg/authorization.Request).
type Request struct {
	RequestMethod string `json:"RequestMethod,omitempty"`
	RequestURI    string `json:"RequestUri,omitempty"`
	RequestBody   []byte `json:"RequestBody,omitempty"`
}

// Response is the plugin's answer.
type Response struct {
	Allow bool   `json:"Allow"`
	Msg   string `json:"Msg,omitempty"`
	Err   string `json:"Err,omitempty"`
}

// Manifest is the answer to Plugin.Activate.
type Manifest struct {
	Implements []string
}

var createRE = regexp.MustCompile(`^(/v[0-9.]+)?/containers/create$`)

// Decide answers an authorization request; warning is set when it allowed a
// container create it couldn't read.
func Decide(r Request) (resp Response, warning string) {
	allow := Response{Allow: true}
	if r.RequestMethod != http.MethodPost {
		return allow, ""
	}
	u, err := url.Parse(r.RequestURI)
	if err != nil || !createRE.MatchString(u.Path) {
		return allow, ""
	}
	// dockerd sends JSON bodies only (and no larger than its limit).
	if len(r.RequestBody) == 0 {
		return allow, "container create without a body: can't tell whether it's a step"
	}
	var body struct {
		Labels map[string]any
	}
	if err := json.Unmarshal(r.RequestBody, &body); err != nil {
		return allow, "container create with an unreadable body: " + err.Error()
	}
	if _, ok := body.Labels[StepLabel]; ok {
		return Response{Allow: false, Msg: DenyMessage}, ""
	}
	return allow, ""
}

// Handler serves the plugin protocol: activation, request authorization, and
// response authorization (always allowed).
func Handler(log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /Plugin.Activate", func(w http.ResponseWriter, r *http.Request) {
		write(w, Manifest{Implements: []string{"authz"}})
	})
	mux.HandleFunc("POST /AuthZPlugin.AuthZReq", func(w http.ResponseWriter, r *http.Request) {
		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			// Not dockerd's request: dockerd refuses the call on Err.
			write(w, Response{Err: "sg-steps-guard: unreadable authorization request: " + err.Error()})
			return
		}
		resp, warning := Decide(req)
		switch {
		case warning != "":
			log.Warn("guard: allowed "+warning, "method", req.RequestMethod, "uri", req.RequestURI)
		case !resp.Allow:
			log.Info("guard: refused a step container in dockerd", "uri", req.RequestURI)
		}
		write(w, resp)
	})
	mux.HandleFunc("POST /AuthZPlugin.AuthZRes", func(w http.ResponseWriter, r *http.Request) {
		write(w, Response{Allow: true})
	})
	return mux
}

func write(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", MediaType)
	_ = json.NewEncoder(w).Encode(v)
}

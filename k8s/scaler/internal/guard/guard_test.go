package guard

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Bodies as the run controller (docker-py) and the ECS agent send them,
// trimmed.
const (
	stepCreate = `{"Image":"registry.example.com/team/image:1.2","Cmd":["terraform","plan"],` +
		`"Env":["A=b"],"Labels":{"orgId":"/orgs/example-org","wfrunId":"/wfgrps/x/wfs/y/wfruns/z"},` +
		`"HostConfig":{"Binds":["/var/tmp/workspace/orgs/example-org/wfgrps/x/wfs/y/wfruns/z/shared:/mnt/sg_workspace"]}}`
	controllerCreate = `{"Image":"stackguardian/sg-run-controller:1","Labels":{` +
		`"com.amazonaws.ecs.cluster":"c","com.amazonaws.ecs.task-arn":"arn:aws:ecs:x","com.amazonaws.ecs.container-name":"run"},` +
		`"HostConfig":{"Binds":["/var/tmp/workspace:/var/tmp/workspace"]}}`
)

// dockerdRequest is an authorization request as dockerd marshals it: the
// body base64, under the key RequestUri.
func dockerdRequest(method, uri, body string) string {
	m := map[string]any{"User": "", "RequestMethod": method, "RequestUri": uri,
		"RequestHeaders": map[string]string{"Content-Type": "application/json"}}
	if body != "" {
		m["RequestBody"] = base64.StdEncoding.EncodeToString([]byte(body))
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func authz(t *testing.T, h http.Handler, raw string) Response {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/AuthZPlugin.AuthZReq", strings.NewReader(raw))
	req.Header.Set("Accept", MediaType)
	h.ServeHTTP(rec, req)
	var resp Response
	if rec.Code != 200 || rec.Header().Get("Content-Type") != MediaType || json.Unmarshal(rec.Body.Bytes(), &resp) != nil {
		t.Fatalf("AuthZReq %d %q %s", rec.Code, rec.Header().Get("Content-Type"), rec.Body)
	}
	return resp
}

func TestAuthZReq(t *testing.T) {
	logs := &bytes.Buffer{}
	h := Handler(slog.New(slog.NewJSONHandler(logs, nil)))
	for _, c := range []struct {
		name              string
		method, uri, body string
		allow             bool
	}{
		{"step create", "POST", "/v1.41/containers/create", stepCreate, false},
		{"step create, named", "POST", "/v1.47/containers/create?name=example-org-plan-0-1a2b", stepCreate, false},
		{"step create, unversioned", "POST", "/containers/create", stepCreate, false},
		{"step create, minor version", "POST", "/v1.4/containers/create?name=x&platform=linux", stepCreate, false},
		{"controller create", "POST", "/v1.44/containers/create?name=ecs-run-1", controllerCreate, true},
		{"no labels", "POST", "/v1.41/containers/create", `{"Image":"alpine","Labels":null}`, true},
		{"wfrunId elsewhere", "POST", "/v1.41/containers/create", `{"Image":"alpine","Env":["wfrunId=x"],"Labels":{"x":"wfrunId"}}`, true},
		{"no body", "POST", "/v1.41/containers/create", "", true},
		{"unreadable body", "POST", "/v1.41/containers/create", "{not json", true},
		{"start", "POST", "/v1.41/containers/abc/start", "", true},
		{"step-labeled exec", "POST", "/v1.41/containers/abc/exec", stepCreate, true},
		{"inspect", "GET", "/v1.41/containers/create", "", true},
		{"look-alike path", "POST", "/v1.41/containers/create/x", stepCreate, true},
		{"prefix path", "POST", "/foo/containers/create", stepCreate, true},
		{"list", "GET", "/v1.41/containers/json?all=1&filters=%7B%22label%22%3A%5B%22wfrunId%22%5D%7D", "", true},
		{"image pull", "POST", "/v1.41/images/create?fromImage=alpine", "", true},
	} {
		resp := authz(t, h, dockerdRequest(c.method, c.uri, c.body))
		if resp.Allow != c.allow || resp.Err != "" || (!resp.Allow && resp.Msg != DenyMessage) {
			t.Errorf("%s: %+v, want allow=%v", c.name, resp, c.allow)
		}
	}
	for _, want := range []string{"refused a step container", "without a body", "unreadable body"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("no %q in the log: %s", want, logs)
		}
	}
}

func TestDockerdShapes(t *testing.T) {
	// The exact key casing dockerd uses, with every field it sends.
	raw := `{"User":"","UserAuthNMethod":"","RequestMethod":"POST","RequestUri":"/v1.41/containers/create",` +
		`"RequestBody":"` + base64.StdEncoding.EncodeToString([]byte(stepCreate)) + `",` +
		`"RequestHeaders":{"Content-Type":"application/json","User-Agent":"docker-sdk-python/7.1.0"},` +
		`"RequestPeerCertificates":null,"ResponseStatusCode":0}`
	if resp := authz(t, Handler(slog.New(slog.NewJSONHandler(io.Discard, nil))), raw); resp.Allow {
		t.Errorf("step create allowed: %+v", resp)
	}
	// The response: Allow always present.
	b, _ := json.Marshal(Response{Allow: false})
	if string(b) != `{"Allow":false}` {
		t.Errorf("response %s", b)
	}
}

func TestProtocol(t *testing.T) {
	h := Handler(slog.New(slog.NewJSONHandler(io.Discard, nil)))
	do := func(path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", path, strings.NewReader(body)))
		return rec
	}
	if rec := do("/Plugin.Activate", ""); rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != `{"Implements":["authz"]}` ||
		rec.Header().Get("Content-Type") != MediaType {
		t.Errorf("activate %d %s", rec.Code, rec.Body)
	}
	// Responses are always allowed, even a step create's.
	if rec := do("/AuthZPlugin.AuthZRes", dockerdRequest("POST", "/v1.41/containers/create", stepCreate)); strings.TrimSpace(rec.Body.String()) != `{"Allow":true}` {
		t.Errorf("AuthZRes %s", rec.Body)
	}
	// Not dockerd: an error, which dockerd treats as a refusal.
	if rec := do("/AuthZPlugin.AuthZReq", "nope"); !strings.Contains(rec.Body.String(), `"Allow":false,"Err":"sg-steps-guard: unreadable`) {
		t.Errorf("garbage %s", rec.Body)
	}
	if rec := do("/Other", ""); rec.Code != 404 {
		t.Errorf("unknown endpoint %d", rec.Code)
	}
}

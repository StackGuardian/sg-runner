package sg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fakeRunnerToken = "sgrt_SUPERSECRET_runner_token_123"

const groupJSON = `{"msg": {
  "ResourceName": "rg",
  "RunnerToken": "` + fakeRunnerToken + `",
  "QueuedWorkflowsCount": 2,
  "MaxNumberOfRunners": 4,
  "ContainerInstances": [
    {"runnerId": "r-0", "status": "ACTIVE", "agentConnected": true,
     "runningTasksCount": 1, "pendingTasksCount": 1,
     "registeredResources": [{"name": "CPU", "integerValue": 2048}, {"name": "MEMORY", "integerValue": 4096}],
     "remainingResources": [{"name": "CPU", "integerValue": 1024}, {"name": "MEMORY", "integerValue": 3584}],
     "instanceDetails": [{"ComputerName": "sg-runner-0.sg-runner.sg-runner.svc.cluster.local"}]},
    {"runnerId": "vm-1", "status": "DRAINING", "agentConnected": false,
     "instanceDetails": [{"ComputerName": "ip-10-0-0-1"}]}
  ]}}`

func fakeSG(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return New(Credentials{Token: "node-token", Organization: "org", RunnerGroup: "rg", BaseAPI: srv.URL + "/api/v1/"}, nil), srv
}

func TestRunnerGroup(t *testing.T) {
	c, _ := fakeSG(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/orgs/org/runnergroups/rg/" ||
			r.URL.Query().Get("getActiveWorkflows") != "true" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
		}
		if got := r.Header.Get("Authorization"); got != "apikey node-token" {
			t.Errorf("Authorization = %q", got)
		}
		io.WriteString(w, groupJSON)
	})
	g, err := c.RunnerGroup(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if g.QueuedWorkflowsCount != 2 || g.MaxNumberOfRunners == nil || *g.MaxNumberOfRunners != 4 || len(g.ContainerInstances) != 2 {
		t.Fatalf("decoded %+v", g)
	}
	i := g.ContainerInstances[0]
	if i.RunnerID != "r-0" || !i.AgentConnected || i.RunningTasksCount+i.PendingTasksCount != 2 ||
		ResourceValue(i.RegisteredResources, "CPU") != 2048 || ResourceValue(i.RemainingResources, "MEMORY") != 3584 ||
		!strings.HasPrefix(i.ComputerName(), "sg-runner-0.") {
		t.Errorf("instance %+v", i)
	}
	if g.ContainerInstances[1].ComputerName() != "ip-10-0-0-1" || ResourceValue(nil, "CPU") != 0 {
		t.Error("second instance")
	}
}

func TestRunnerGroupNullMax(t *testing.T) {
	c, _ := fakeSG(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"msg": {"MaxNumberOfRunners": null, "ContainerInstances": null}}`)
	})
	g, err := c.RunnerGroup(context.Background())
	if err != nil || g.MaxNumberOfRunners != nil || g.QueuedWorkflowsCount != 0 {
		t.Fatalf("got %+v, %v", g, err)
	}
}

func TestSetRunnerStatus(t *testing.T) {
	var got map[string]string
	c, _ := fakeSG(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/orgs/org/runnergroups/rg/runner_status/" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("missing content type")
		}
		json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
	})
	if err := c.SetRunnerStatus(context.Background(), "r-1", "DRAINING"); err != nil {
		t.Fatal(err)
	}
	if got["Status"] != "DRAINING" || got["RunnerId"] != "r-1" {
		t.Errorf("payload %v", got)
	}
}

// Responses carry the runner token: no error may echo a body, whatever
// goes wrong.
func TestErrorsNeverLeakBodies(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"http 500": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(500)
			io.WriteString(w, groupJSON)
		},
		"http 403": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(403)
			io.WriteString(w, `{"msg":"`+fakeRunnerToken+`"}`)
		},
		"truncated json": func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, groupJSON[:len(groupJSON)-40])
		},
		"wrong type": func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"msg": {"QueuedWorkflowsCount": "`+fakeRunnerToken+`"}}`)
		},
		"syntax error after secret": func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"msg": {"RunnerToken": "`+fakeRunnerToken+`" x}}`)
		},
		"no msg": func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"RunnerToken": "`+fakeRunnerToken+`"}`)
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			log := slog.New(slog.NewJSONHandler(&logs, nil))
			c, _ := fakeSG(t, h)
			_, err := c.RunnerGroup(context.Background())
			if err == nil {
				t.Fatal("want an error")
			}
			log.Error("loop failed", "err", err)
			serr := c.SetRunnerStatus(context.Background(), "r", "ACTIVE")
			log.Error("status", "err", serr)
			for _, s := range []string{err.Error(), logs.String()} {
				if strings.Contains(s, fakeRunnerToken) || strings.Contains(s, "node-token") {
					t.Errorf("secret leaked: %s", s)
				}
			}
		})
	}
	var apiErr *APIError
	c, _ := fakeSG(t, cases["http 403"])
	if _, err := c.RunnerGroup(context.Background()); !errors.As(err, &apiErr) || apiErr.StatusCode != 403 {
		t.Errorf("want APIError 403, got %v", err)
	}
}

func TestUnreachable(t *testing.T) {
	c, srv := fakeSG(t, func(w http.ResponseWriter, r *http.Request) {})
	srv.Close()
	if _, err := c.RunnerGroup(context.Background()); err == nil || strings.Contains(err.Error(), "node-token") {
		t.Errorf("got %v", err)
	}
}

func TestLoadCredentials(t *testing.T) {
	dir := t.TempDir()
	write := func(k, v string) { os.WriteFile(filepath.Join(dir, k), []byte(v), 0o600) }
	if _, err := LoadCredentials(dir); err == nil {
		t.Error("want error without files")
	}
	write("SG_NODE_TOKEN", "tok\n")
	write("SG_ORGANIZATION", "org\n")
	write("SG_RUNNER_GROUP", "rg")
	c, err := LoadCredentials(dir)
	if err != nil || c != (Credentials{Token: "tok", Organization: "org", RunnerGroup: "rg", BaseAPI: DefaultBaseAPI}) {
		t.Fatalf("got %+v, %v", c, err)
	}
	write("SG_BASE_API", "https://example.test/api/v1\n")
	if c, _ := LoadCredentials(dir); c.BaseAPI != "https://example.test/api/v1" {
		t.Errorf("base = %q", c.BaseAPI)
	}
	write("SG_RUNNER_GROUP", " \n")
	if _, err := LoadCredentials(dir); err == nil {
		t.Error("want error for an empty runner group")
	}
}

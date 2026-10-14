package steps

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

type harness struct {
	t      *testing.T
	client *fake.Clientset
	s      *Server
	h      http.Handler
	now    time.Time
	logs   *bytes.Buffer
}

func newHarness(t *testing.T, objs ...runtime.Object) *harness {
	hs := &harness{t: t, client: fake.NewClientset(objs...), now: t0.Add(time.Minute), logs: &bytes.Buffer{}}
	hs.s = NewServer(testConfig(), hs.client, slog.New(slog.NewJSONHandler(hs.logs, nil)))
	hs.s.Now = func() time.Time { return hs.now }
	hs.s.Random = bytes.NewReader(bytes.Repeat([]byte{0, 1, 2, 3, 4, 5, 6, 7}, 64))
	hs.s.PollInterval = 5 * time.Millisecond
	hs.h = hs.s.Handler()
	return hs
}

func (hs *harness) do(method, target, body string) *httptest.ResponseRecorder {
	hs.t.Helper()
	rec := httptest.NewRecorder()
	hs.h.ServeHTTP(rec, httptest.NewRequest(method, target, strings.NewReader(body)))
	return rec
}

// wantError checks a JSON error response.
func wantError(t *testing.T, rec *httptest.ResponseRecorder, status int, reason string) {
	t.Helper()
	var e Error
	if rec.Code != status || json.Unmarshal(rec.Body.Bytes(), &e) != nil || e.Reason != reason || e.Message == "" ||
		rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("got %d %s, want %d %s", rec.Code, rec.Body, status, reason)
	}
}

func (hs *harness) pods() []corev1.Pod {
	l, err := hs.client.CoreV1().Pods("sg").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		hs.t.Fatal(err)
	}
	return l.Items
}

func (hs *harness) secretNames() []string {
	l, err := hs.client.CoreV1().Secrets("sg").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		hs.t.Fatal(err)
	}
	var out []string
	for _, s := range l.Items {
		out = append(out, s.Name)
	}
	return out
}

func requestJSON(t *testing.T, edit func(*Request)) string {
	r := testRequest()
	if edit != nil {
		edit(&r)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestHealthz(t *testing.T) {
	rec := newHarness(t).do("GET", "/healthz", "")
	if rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != `{"api":"v1"}` {
		t.Errorf("healthz %d %s", rec.Code, rec.Body)
	}
}

func TestUnknownRouteIsJSON(t *testing.T) {
	hs := newHarness(t)
	wantError(t, hs.do("GET", "/v2/steps", ""), 404, ReasonNotFound)
	wantError(t, hs.do("PUT", "/v1/steps", ""), 404, ReasonNotFound)
}

func TestCreate(t *testing.T) {
	hs := newHarness(t)
	body := requestJSON(t, func(r *Request) {
		r.RegistryAuth = &RegistryAuth{Registry: "registry.example.com", Username: "u", Password: "p"}
	})
	rec := hs.do("POST", "/v1/steps", body)
	var out map[string]string
	if rec.Code != 201 || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
		t.Fatalf("create %d %s", rec.Code, rec.Body)
	}
	id := out["id"]
	if id != "sg-runner-0-s-abcdefgh" {
		t.Errorf("id %q", id)
	}
	pods := hs.pods()
	if len(pods) != 1 || pods[0].Name != id || pods[0].Spec.ImagePullSecrets[0].Name != id+"-pull" {
		t.Errorf("pods %+v", pods)
	}
	if got := strings.Join(hs.secretNames(), ","); got != id+"-env,"+id+"-pull" {
		t.Errorf("secrets %s", got)
	}
	if strings.Contains(hs.logs.String(), "SG_WORKFLOW_RUN_PAYLOAD") || strings.Contains(hs.logs.String(), `"p"`) {
		t.Errorf("the env or the password got logged: %s", hs.logs)
	}

	// Unknown fields are fine: a newer controller may send more.
	hs.s.Random = bytes.NewReader(bytes.Repeat([]byte{9}, 16))
	rec = hs.do("POST", "/v1/steps", strings.Replace(requestJSON(t, nil), "{", `{"future":1,`, 1))
	if rec.Code != 201 {
		t.Errorf("unknown field: %d %s", rec.Code, rec.Body)
	}
	if got := hs.secretNames(); len(got) != 3 {
		t.Errorf("no pull Secret without registryAuth: %v", got)
	}
}

func TestCreateRejects(t *testing.T) {
	hs := newHarness(t)
	wantError(t, hs.do("POST", "/v1/steps", "{"), 400, ReasonInvalidRequest)
	wantError(t, hs.do("POST", "/v1/steps", `{"org":1}`), 400, ReasonInvalidRequest)
	wantError(t, hs.do("POST", "/v1/steps", requestJSON(t, func(r *Request) { r.Image = "" })), 400, ReasonInvalidRequest)
	wantError(t, hs.do("POST", "/v1/steps", requestJSON(t, func(r *Request) { r.Mounts[0].Source = "/var/tmp/workspace" })), 400, ReasonInvalidMount)
	wantError(t, hs.do("POST", "/v1/steps", requestJSON(t, func(r *Request) { r.Env["A B"] = "" })), 400, ReasonInvalidEnv)
	wantError(t, hs.do("POST", "/v1/steps", requestJSON(t, func(r *Request) {
		r.Env = map[string]string{"A": strings.Repeat("x", MaxEnvBytes)}
	})), 400, ReasonEnvTooLarge)
	wantError(t, hs.do("POST", "/v1/steps", requestJSON(t, func(r *Request) {
		r.Args = []string{strings.Repeat("x", maxBody)}
	})), 400, ReasonEnvTooLarge)
	if len(hs.pods()) != 0 || len(hs.secretNames()) != 0 {
		t.Errorf("a rejected request created objects")
	}
}

func TestCreateCleansUpWhenThePodFails(t *testing.T) {
	for _, failing := range []string{"pods", "secrets"} {
		hs := newHarness(t)
		calls := 0
		hs.client.PrependReactor("create", failing, func(a k8stesting.Action) (bool, runtime.Object, error) {
			// The env Secret goes through; the pull Secret or the pod fails.
			if calls++; failing == "secrets" && calls == 1 {
				return false, nil, nil
			}
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: failing}, "x", errors.New("quota"))
		})
		body := requestJSON(t, func(r *Request) { r.RegistryAuth = &RegistryAuth{Registry: "r", Username: "u", Password: "p"} })
		rec := hs.do("POST", "/v1/steps", body)
		wantError(t, rec, 500, ReasonKubernetesError)
		if names := hs.secretNames(); len(names) != 0 || len(hs.pods()) != 0 {
			t.Errorf("%s failing: left %v behind", failing, names)
		}
	}
}

func TestGet(t *testing.T) {
	started := t0.Add(10 * time.Second)
	other := pod(corev1.PodRunning, running(started))
	other.Name = "sg-runner-1-s-aaaaaaaa"
	unrelated := pod(corev1.PodRunning, running(started))
	unrelated.Name = "sg-runner-0"
	hs := newHarness(t, pod(corev1.PodRunning, running(started)), other, unrelated)

	rec := hs.do("GET", "/v1/steps/"+testID, "")
	want := `{"id":"sg-runner-0-s-7f3k9q2x","state":"running","exitCode":null,"reason":"","message":"",` +
		`"startedAt":"2026-10-14T10:00:10Z","finishedAt":null}`
	if rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != want {
		t.Errorf("get %d %s", rec.Code, rec.Body)
	}
	for _, id := range []string{"sg-runner-0-s-zzzzzzzz", other.Name, unrelated.Name, testID + "-env"} {
		wantError(t, hs.do("GET", "/v1/steps/"+id, ""), 404, ReasonNotFound)
	}

	hs.client.PrependReactor("get", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("connection refused")
	})
	wantError(t, hs.do("GET", "/v1/steps/"+testID, ""), 500, ReasonKubernetesError)
}

// graces records the grace periods of pod deletes.
func graces(hs *harness) *[]int64 {
	var out []int64
	hs.client.PrependReactor("delete", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		// Stops set a grace period; deletions of finished steps don't.
		if g := a.(k8stesting.DeleteActionImpl).DeleteOptions.GracePeriodSeconds; g != nil {
			out = append(out, *g)
		}
		return false, nil, nil
	})
	return &out
}

func TestStop(t *testing.T) {
	hs := newHarness(t, pod(corev1.PodRunning, running(t0)))
	g := graces(hs)
	wantError(t, hs.do("POST", "/v1/steps/sg-runner-0-s-zzzzzzzz/stop", `{"graceSeconds":5}`), 404, ReasonNotFound)
	wantError(t, hs.do("POST", "/v1/steps/"+testID+"/stop", `{"graceSeconds":-1}`), 400, ReasonInvalidRequest)
	if rec := hs.do("POST", "/v1/steps/"+testID+"/stop", `{"graceSeconds":5}`); rec.Code != 202 {
		t.Fatalf("stop %d %s", rec.Code, rec.Body)
	}
	if len(hs.pods()) != 0 {
		t.Error("stop left the pod")
	}
	// Its pod is gone: the step exited as killed.
	rec := hs.do("GET", "/v1/steps/"+testID, "")
	var st State
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &st) != nil || st.State != StateExited ||
		*st.ExitCode != 137 || st.Reason != ReasonStopped {
		t.Errorf("after stop %d %s", rec.Code, rec.Body)
	}
	// Stopping again is fine, with the default grace of 30s; 0 kills (almost)
	// right away.
	if rec := hs.do("POST", "/v1/steps/"+testID+"/stop", ""); rec.Code != 202 {
		t.Errorf("second stop %d %s", rec.Code, rec.Body)
	}
	hs0 := newHarness(t, pod(corev1.PodRunning, running(t0)))
	g0 := graces(hs0)
	hs0.do("POST", "/v1/steps/"+testID+"/stop", `{"graceSeconds":0}`)
	if len(*g) != 2 || (*g)[0] != 5 || (*g)[1] != 30 || len(*g0) != 1 || (*g0)[0] != 1 {
		t.Errorf("grace periods %v %v", *g, *g0)
	}
}

func TestStopKeepsTheExitCodeSeen(t *testing.T) {
	hs := newHarness(t, pod(corev1.PodFailed, terminated(2, "Error", t0, t0.Add(time.Minute))))
	if rec := hs.do("POST", "/v1/steps/"+testID+"/stop", `{"graceSeconds":0}`); rec.Code != 202 {
		t.Fatalf("stop %d %s", rec.Code, rec.Body)
	}
	var st State
	rec := hs.do("GET", "/v1/steps/"+testID, "")
	if json.Unmarshal(rec.Body.Bytes(), &st) != nil || st.State != StateExited || *st.ExitCode != 2 || st.Reason != "Error" {
		t.Errorf("after stop %s", rec.Body)
	}
}

// TestStopCatchesTheFinalExitCode: the kubelet's terminated status lasts a
// moment before the pod goes; the broker keeps it.
func TestStopCatchesTheFinalExitCode(t *testing.T) {
	hs := newHarness(t, pod(corev1.PodRunning, running(t0)))
	hs.s.StopPollInterval = 5 * time.Millisecond
	// A graceful delete keeps the pod until the kubelet is done.
	hs.client.PrependReactor("delete", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, nil
	})
	if rec := hs.do("POST", "/v1/steps/"+testID+"/stop", `{"graceSeconds":10}`); rec.Code != 202 {
		t.Fatalf("stop %d %s", rec.Code, rec.Body)
	}
	p := pod(corev1.PodFailed, terminated(143, "Error", t0, t0.Add(time.Minute)), deleting)
	if _, err := hs.client.CoreV1().Pods("sg").UpdateStatus(context.Background(), p, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	seen := func() bool {
		hs.s.mu.Lock()
		defer hs.s.mu.Unlock()
		last := hs.s.steps[testID].last
		return last.State == StateExited && *last.ExitCode == 143
	}
	for deadline := time.Now().Add(5 * time.Second); !seen(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the exit code was never caught")
		}
	}
	gvr := corev1.SchemeGroupVersion.WithResource("pods")
	if err := hs.client.Tracker().Delete(gvr, "sg", testID); err != nil {
		t.Fatal(err)
	}
	following := func() bool {
		hs.s.mu.Lock()
		defer hs.s.mu.Unlock()
		return hs.s.steps[testID].following
	}
	for deadline := time.Now().Add(5 * time.Second); following(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("still following a gone pod")
		}
	}
	var st State
	rec := hs.do("GET", "/v1/steps/"+testID, "")
	if json.Unmarshal(rec.Body.Bytes(), &st) != nil || st.State != StateExited || *st.ExitCode != 143 || st.Reason != "Error" {
		t.Errorf("after the pod went: %s", rec.Body)
	}
}

func TestStopRecordKeepsAnExit(t *testing.T) {
	c := int32(143)
	rec := &stepRecord{}
	rec.see(State{State: StateRunning})
	rec.see(State{State: StateExited, ExitCode: &c})
	rec.see(State{State: StateFailed, Reason: FailedPodDeleted})
	if rec.last.State != StateExited || *rec.last.ExitCode != 143 {
		t.Errorf("last %+v", rec.last)
	}
}

func TestDeletedWithoutStopIsNotFound(t *testing.T) {
	hs := newHarness(t, pod(corev1.PodRunning, running(t0)))
	if err := hs.client.CoreV1().Pods("sg").Delete(context.Background(), testID, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	wantError(t, hs.do("GET", "/v1/steps/"+testID, ""), 404, ReasonNotFound)
}

func TestDelete(t *testing.T) {
	sec := func(name string) *corev1.Secret {
		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "sg"}}
	}
	hs := newHarness(t, pod(corev1.PodSucceeded, terminated(0, "Completed", t0, t0)), sec(testID+"-env"), sec(testID+"-pull"), sec("keep"))
	hs.s.steps[testID] = &stepRecord{at: t0, stopped: true}
	for i := 0; i < 2; i++ {
		if rec := hs.do("DELETE", "/v1/steps/"+testID, ""); rec.Code != 204 {
			t.Errorf("delete %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	if len(hs.pods()) != 0 || strings.Join(hs.secretNames(), ",") != "keep" || !hs.s.steps[testID].deleted {
		t.Errorf("left pods %v, secrets %v, record %+v", hs.pods(), hs.secretNames(), hs.s.steps[testID])
	}
	wantError(t, hs.do("DELETE", "/v1/steps/keep", ""), 404, ReasonNotFound)
}

// fakeLogs serves canned logs and records the options asked for.
type fakeLogs struct {
	mu   sync.Mutex
	opts []*corev1.PodLogOptions
	body func() io.ReadCloser
}

func (f *fakeLogs) open(ctx context.Context, ns, name string, opts *corev1.PodLogOptions) (io.ReadCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opts = append(f.opts, opts)
	return f.body(), nil
}

func (f *fakeLogs) calls() []*corev1.PodLogOptions {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.opts
}

const logLines = "2026-10-14T10:00:01.5Z one\n2026-10-14T10:00:02.25Z two\n2026-10-14T10:00:02.5Z three\n2026-10-14T10:00:03Z four"

func TestLogs(t *testing.T) {
	hs := newHarness(t, pod(corev1.PodRunning, running(t0)))
	f := &fakeLogs{body: func() io.ReadCloser { return io.NopCloser(strings.NewReader(logLines)) }}
	hs.s.Logs = f.open

	rec := hs.do("GET", "/v1/steps/"+testID+"/logs?follow=1", "")
	if rec.Code != 200 || rec.Body.String() != logLines || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("logs %d %q", rec.Code, rec.Body)
	}
	o := f.calls()[0]
	if o.Container != "step" || !o.Follow || !o.Timestamps || o.SinceTime != nil {
		t.Errorf("log options %+v", o)
	}

	// The API server truncates sinceTime to seconds: earlier lines are
	// dropped, lines at exactly sinceTime kept.
	rec = hs.do("GET", "/v1/steps/"+testID+"/logs?follow=1&sinceTime=2026-10-14T10:00:02.25Z", "")
	if want := "2026-10-14T10:00:02.25Z two\n2026-10-14T10:00:02.5Z three\n2026-10-14T10:00:03Z four"; rec.Body.String() != want {
		t.Errorf("logs since %q", rec.Body)
	}
	if o := f.calls()[1]; o.SinceTime == nil || !o.SinceTime.Equal(&metav1.Time{Time: time.Date(2026, 10, 14, 10, 0, 2, 250e6, time.UTC)}) {
		t.Errorf("since option %+v", o.SinceTime)
	}

	wantError(t, hs.do("GET", "/v1/steps/"+testID+"/logs?sinceTime=yesterday", ""), 400, ReasonInvalidRequest)
	wantError(t, hs.do("GET", "/v1/steps/sg-runner-0-s-zzzzzzzz/logs?follow=1", ""), 404, ReasonNotFound)
}

func TestLogsWaitForTheContainer(t *testing.T) {
	hs := newHarness(t, pod(corev1.PodPending, waiting("ContainerCreating", "")))
	f := &fakeLogs{body: func() io.ReadCloser { return io.NopCloser(strings.NewReader(logLines)) }}
	hs.s.Logs = f.open
	done := make(chan *httptest.ResponseRecorder)
	go func() { done <- hs.do("GET", "/v1/steps/"+testID+"/logs?follow=1", "") }()

	time.Sleep(30 * time.Millisecond)
	if len(f.calls()) != 0 {
		t.Fatal("logs opened before the container started")
	}
	if _, err := hs.client.CoreV1().Pods("sg").UpdateStatus(context.Background(),
		pod(corev1.PodRunning, running(t0)), metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	select {
	case rec := <-done:
		if rec.Body.String() != logLines {
			t.Errorf("logs %q", rec.Body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("logs never came")
	}
}

func TestLogsOfAFailedStepAreEmpty(t *testing.T) {
	hs := newHarness(t, pod(corev1.PodPending, waiting("ImagePullBackOff", "")))
	f := &fakeLogs{body: func() io.ReadCloser { return io.NopCloser(strings.NewReader(logLines)) }}
	hs.s.Logs = f.open
	rec := hs.do("GET", "/v1/steps/"+testID+"/logs?follow=1", "")
	if rec.Code != 200 || rec.Body.Len() != 0 || len(f.calls()) != 0 {
		t.Errorf("logs of a failed step: %d %q, %d opens", rec.Code, rec.Body, len(f.calls()))
	}

	// Deleted while waiting: the stream ends.
	hs = newHarness(t, pod(corev1.PodPending, nil))
	hs.s.Logs = f.open
	done := make(chan *httptest.ResponseRecorder)
	go func() { done <- hs.do("GET", "/v1/steps/"+testID+"/logs?follow=1", "") }()
	time.Sleep(20 * time.Millisecond)
	_ = hs.client.CoreV1().Pods("sg").Delete(context.Background(), testID, metav1.DeleteOptions{})
	select {
	case rec := <-done:
		if rec.Code != 200 || rec.Body.Len() != 0 {
			t.Errorf("logs of a deleted step: %d %q", rec.Code, rec.Body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stream didn't end")
	}
}

func TestLogsCountOpenStreams(t *testing.T) {
	hs := newHarness(t, pod(corev1.PodRunning, running(t0)))
	pr, pw := io.Pipe()
	hs.s.Logs = (&fakeLogs{body: func() io.ReadCloser { return pr }}).open
	done := make(chan struct{})
	go func() { hs.do("GET", "/v1/steps/"+testID+"/logs?follow=1", ""); close(done) }()
	_, _ = pw.Write([]byte("2026-10-14T10:00:01Z hi\n"))
	if !hs.s.streaming(testID) {
		t.Error("an open stream isn't counted")
	}
	_ = pw.Close()
	<-done
	if hs.s.streaming(testID) {
		t.Error("a closed stream is still counted")
	}
}

// TestOverTheSocket runs the API on a unix socket like the controllers use it.
func TestOverTheSocket(t *testing.T) {
	// macOS keeps unix socket paths under 104 bytes: a short temp dir.
	dir, err := os.MkdirTemp("", "steps")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "sub", "steps.sock")
	if err := os.MkdirAll(filepath.Dir(sock), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sock, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(sock)
	if err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o666 {
		t.Errorf("socket %v %v", fi.Mode(), err)
	}
	srv := &http.Server{Handler: newHarness(t).s.Handler()}
	go func() { _ = srv.Serve(l) }()
	defer srv.Close()

	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	resp, err := c.Get("http://steps/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || strings.TrimSpace(string(b)) != `{"api":"v1"}` {
		t.Errorf("healthz over the socket %d %s", resp.StatusCode, b)
	}
}

// waitFor polls cond for up to 5s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting: %s", what)
		}
	}
}

// podDeletes counts the delete calls on pods.
func podDeletes(hs *harness) int {
	n := 0
	for _, a := range hs.client.Actions() {
		if a.GetVerb() == "delete" && a.GetResource().Resource == "pods" {
			n++
		}
	}
	return n
}

func stepSecrets(id string) []runtime.Object {
	return []runtime.Object{
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: id + "-env", Namespace: "sg"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: id + "-pull", Namespace: "sg"}},
	}
}

func (hs *harness) deleted(id string) bool {
	hs.s.mu.Lock()
	defer hs.s.mu.Unlock()
	rec := hs.s.steps[id]
	return rec != nil && rec.deleted
}

func TestServedTerminalStateDeletesTheStep(t *testing.T) {
	for name, p := range map[string]*corev1.Pod{
		"exited":         pod(corev1.PodFailed, terminated(11, "Error", t0, t0.Add(time.Minute))),
		"failed to pull": pod(corev1.PodPending, waiting("ImagePullBackOff", "Back-off pulling image")),
	} {
		hs := newHarness(t, append(stepSecrets(testID), p)...)
		first := hs.do("GET", "/v1/steps/"+testID, "")
		if first.Code != 200 {
			t.Fatalf("%s: get %d %s", name, first.Code, first.Body)
		}
		waitFor(t, name+": pod and Secrets deleted", func() bool { return hs.deleted(testID) })
		if len(hs.pods()) != 0 || len(hs.secretNames()) != 0 {
			t.Errorf("%s: left pods %v, secrets %v", name, hs.pods(), hs.secretNames())
		}
		for _, a := range hs.client.Actions() {
			if d, ok := a.(k8stesting.DeleteActionImpl); ok && a.GetResource().Resource == "pods" &&
				(d.DeleteOptions.PropagationPolicy == nil || *d.DeleteOptions.PropagationPolicy != metav1.DeletePropagationBackground) {
				t.Errorf("%s: pod delete options %+v", name, d.DeleteOptions)
			}
		}
		// Later GETs keep the state, and delete nothing again.
		for i := 0; i < 3; i++ {
			if rec := hs.do("GET", "/v1/steps/"+testID, ""); rec.Code != 200 || rec.Body.String() != first.Body.String() {
				t.Errorf("%s: get after deletion %d %s, want %s", name, rec.Code, rec.Body, first.Body)
			}
		}
		if err := hs.s.Sweep(context.Background()); err != nil {
			t.Fatal(err)
		}
		if n := podDeletes(hs); n != 1 {
			t.Errorf("%s: %d pod deletes", name, n)
		}
	}
}

func TestNonTerminalGetsDeleteNothing(t *testing.T) {
	hs := newHarness(t, append(stepSecrets(testID), pod(corev1.PodRunning, running(t0)))...)
	for i := 0; i < 3; i++ {
		hs.do("GET", "/v1/steps/"+testID, "")
	}
	time.Sleep(20 * time.Millisecond)
	if n := podDeletes(hs); n != 0 || len(hs.secretNames()) != 2 || len(hs.s.steps) != 0 {
		t.Errorf("%d pod deletes, secrets %v, records %v", n, hs.secretNames(), hs.s.steps)
	}
}

func TestOpenLogStreamDefersDeletion(t *testing.T) {
	hs := newHarness(t, append(stepSecrets(testID), pod(corev1.PodSucceeded, terminated(0, "Completed", t0, t0)))...)
	pr, pw := io.Pipe()
	hs.s.Logs = (&fakeLogs{body: func() io.ReadCloser { return pr }}).open
	done := make(chan struct{})
	go func() { hs.do("GET", "/v1/steps/"+testID+"/logs?follow=1", ""); close(done) }()
	_, _ = pw.Write([]byte("2026-10-14T10:00:01Z last line\n"))

	if rec := hs.do("GET", "/v1/steps/"+testID, ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"exited"`) {
		t.Fatalf("get %d %s", rec.Code, rec.Body)
	}
	time.Sleep(30 * time.Millisecond)
	if n := podDeletes(hs); n != 0 || len(hs.pods()) != 1 {
		t.Fatalf("deleted under an open log stream: %d deletes", n)
	}
	_ = pw.Close()
	<-done
	waitFor(t, "deletion after the stream closed", func() bool { return hs.deleted(testID) })
	if len(hs.pods()) != 0 || len(hs.secretNames()) != 0 || podDeletes(hs) != 1 {
		t.Errorf("pods %v, secrets %v, %d pod deletes", hs.pods(), hs.secretNames(), podDeletes(hs))
	}
}

func TestClosedStreamOfAnUnservedStepDeletesNothing(t *testing.T) {
	hs := newHarness(t, pod(corev1.PodSucceeded, terminated(0, "Completed", t0, t0)))
	hs.s.Logs = (&fakeLogs{body: func() io.ReadCloser { return io.NopCloser(strings.NewReader(logLines)) }}).open
	hs.do("GET", "/v1/steps/"+testID+"/logs?follow=1", "")
	time.Sleep(20 * time.Millisecond)
	if n := podDeletes(hs); n != 0 {
		t.Errorf("%d pod deletes before a client got the final state", n)
	}
}

func TestFailedDeletionIsRetried(t *testing.T) {
	hs := newHarness(t, stepPod(testID, "sg-runner-0", t0, corev1.PodSucceeded, terminated(0, "Completed", t0, t0)))
	var mu sync.Mutex
	failing := true
	hs.client.PrependReactor("delete", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		mu.Lock()
		defer mu.Unlock()
		if failing {
			return true, nil, errors.New("connection refused")
		}
		return false, nil, nil
	})
	hs.do("GET", "/v1/steps/"+testID, "")
	waitFor(t, "the first attempt", func() bool {
		hs.s.mu.Lock()
		defer hs.s.mu.Unlock()
		return podDeletes(hs) == 1 && !hs.s.steps[testID].deleting
	})
	mu.Lock()
	failing = false
	mu.Unlock()
	if err := hs.s.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(hs.pods()) != 0 || !hs.deleted(testID) {
		t.Errorf("the sweep didn't retry: pods %v", hs.pods())
	}
}

const testGrace = 100 * time.Millisecond

func TestServedStepWaitsForTheGrace(t *testing.T) {
	hs := newHarness(t, append(stepSecrets(testID), pod(corev1.PodFailed, terminated(12, "Error", t0, t0)))...)
	hs.s.Config.FinishedGrace = testGrace
	hs.s.Logs = (&fakeLogs{body: func() io.ReadCloser { return io.NopCloser(strings.NewReader(logLines)) }}).open
	served := time.Now()
	hs.do("GET", "/v1/steps/"+testID, "")
	hs.do("GET", "/v1/steps/"+testID, "")
	// A stream opened (and closed) in the grace still gets the logs, and
	// doesn't cut the grace short.
	if rec := hs.do("GET", "/v1/steps/"+testID+"/logs?follow=1", ""); rec.Body.String() != logLines {
		t.Errorf("logs in the grace %q", rec.Body)
	}
	if n := podDeletes(hs); n != 0 && time.Since(served) < testGrace {
		t.Fatalf("%d pod deletes before the grace passed", n)
	}
	waitFor(t, "deletion after the grace", func() bool { return hs.deleted(testID) })
	if elapsed := time.Since(served); elapsed < testGrace {
		t.Errorf("deleted after %s, before the grace of %s", elapsed, testGrace)
	}
	if len(hs.pods()) != 0 || len(hs.secretNames()) != 0 || podDeletes(hs) != 1 {
		t.Errorf("pods %v, secrets %v, %d pod deletes", hs.pods(), hs.secretNames(), podDeletes(hs))
	}
}

func TestStreamOpenedInTheGraceDefersTheDelete(t *testing.T) {
	hs := newHarness(t, pod(corev1.PodFailed, terminated(12, "Error", t0, t0)))
	hs.s.Config.FinishedGrace = testGrace
	pr, pw := io.Pipe()
	hs.s.Logs = (&fakeLogs{body: func() io.ReadCloser { return pr }}).open
	hs.do("GET", "/v1/steps/"+testID, "")
	done := make(chan struct{})
	go func() { hs.do("GET", "/v1/steps/"+testID+"/logs?follow=1", ""); close(done) }()
	_, _ = pw.Write([]byte("2026-10-14T10:00:01Z hi\n"))

	time.Sleep(2 * testGrace)
	if n := podDeletes(hs); n != 0 {
		t.Fatalf("%d pod deletes under an open stream", n)
	}
	_ = pw.Close()
	<-done
	// Past the grace: the closing stream deletes right away.
	waitFor(t, "deletion when the stream closed", func() bool { return hs.deleted(testID) })
	if podDeletes(hs) != 1 {
		t.Errorf("%d pod deletes", podDeletes(hs))
	}
}

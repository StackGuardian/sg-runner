package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"

	"github.com/StackGuardian/sg-runner/k8s/scaler/internal/decide"
	"github.com/StackGuardian/sg-runner/k8s/scaler/internal/kube"
	"github.com/StackGuardian/sg-runner/k8s/scaler/internal/metrics"
	"github.com/StackGuardian/sg-runner/k8s/scaler/internal/sg"
)

const ns = "sg"

var t0 = time.Unix(1_700_000_000, 0)

type fakeSG struct {
	group    *sg.RunnerGroup
	err      error
	statuses []string
}

func (f *fakeSG) RunnerGroup(context.Context) (*sg.RunnerGroup, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.group, nil
}

func (f *fakeSG) SetRunnerStatus(_ context.Context, id, status string) error {
	f.statuses = append(f.statuses, id+"="+status)
	return nil
}

func inst(n int, status string, connected bool, busy int) sg.Instance {
	i := sg.Instance{
		RunnerID: fmt.Sprintf("r-%d", n), Status: status, AgentConnected: connected, RunningTasksCount: busy,
		RegisteredResources: []sg.Resource{{Name: "CPU", IntegerValue: 2048}, {Name: "MEMORY", IntegerValue: 4096}},
		RemainingResources:  []sg.Resource{{Name: "CPU", IntegerValue: 2048}, {Name: "MEMORY", IntegerValue: 4096}},
	}
	if busy > 0 {
		i.RemainingResources = []sg.Resource{{Name: "CPU", IntegerValue: 0}, {Name: "MEMORY", IntegerValue: 0}}
	}
	i.InstanceDetails = append(i.InstanceDetails, struct {
		ComputerName string `json:"ComputerName"`
	}{fmt.Sprintf("sg-runner-%d.sg-runner.sg.svc.cluster.local", n)})
	return i
}

func statefulSet(replicas int32) *appsv1.StatefulSet {
	return &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: "sg-runner", Namespace: ns},
		Spec:       appsv1.StatefulSetSpec{Replicas: ptr.To(replicas)},
	}
}

func claim(name string, ann map[string]string) *corev1.PersistentVolumeClaim {
	return &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Annotations: ann}}
}

type env struct {
	t      *testing.T
	ctrl   *Controller
	sg     *fakeSG
	client *fake.Clientset
	events *record.FakeRecorder
	now    time.Time
	logs   *bytes.Buffer
}

func newEnv(t *testing.T, s SG, objs ...runtime.Object) *env {
	t.Helper()
	e := &env{t: t, client: fake.NewClientset(objs...), events: record.NewFakeRecorder(100), now: t0, logs: &bytes.Buffer{}}
	if f, ok := s.(*fakeSG); ok {
		e.sg = f
	}
	e.ctrl = e.newController(s)
	return e
}

func (e *env) newController(s SG) *Controller {
	return &Controller{
		Config: decide.Config{Min: 1, Max: 10, IdleAfter: time.Minute, StuckAfter: 3 * time.Minute,
			SettleTimeout: 5 * time.Minute, ParkTTL: 12 * time.Hour},
		Interval: 15 * time.Second,
		SG:       s,
		Kube:     kube.New(e.client, ns, "sg-runner", "img:1", "creds"),
		Events:   e.events,
		Metrics:  metrics.New(),
		Log:      slog.New(slog.NewTextHandler(e.logs, nil)),
		Now:      func() time.Time { return e.now },
	}
}

func (e *env) once() error {
	e.t.Helper()
	return e.ctrl.Once(context.Background())
}

func (e *env) sts() *appsv1.StatefulSet {
	s, err := e.client.AppsV1().StatefulSets(ns).Get(context.Background(), "sg-runner", metav1.GetOptions{})
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

func (e *env) claim(name string) (*corev1.PersistentVolumeClaim, error) {
	return e.client.CoreV1().PersistentVolumeClaims(ns).Get(context.Background(), name, metav1.GetOptions{})
}

func (e *env) drainEvents() []string {
	var out []string
	for {
		select {
		case ev := <-e.events.Events:
			out = append(out, ev)
		default:
			return out
		}
	}
}

func hasEvent(events []string, prefix string) bool {
	for _, ev := range events {
		if strings.HasPrefix(ev, prefix) {
			return true
		}
	}
	return false
}

func TestScaleOut(t *testing.T) {
	f := &fakeSG{group: &sg.RunnerGroup{QueuedWorkflowsCount: 1, ContainerInstances: []sg.Instance{
		inst(0, "ACTIVE", true, 1),
		{RunnerID: "vm", Status: "ACTIVE", AgentConnected: true}, // VM runner of the same group: ignored
	}}}
	e := newEnv(t, f, statefulSet(1), claim("state-sg-runner-0", nil))
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	if r := kube.Replicas(e.sts()); r != 2 {
		t.Fatalf("replicas = %d, want 2", r)
	}
	if ev := e.drainEvents(); !hasEvent(ev, "Normal ScaledOut replicas 1 -> 2") || !strings.Contains(strings.Join(ev, "|"), "registering new runner 1") {
		t.Errorf("events %v", ev)
	}
	if v := testutil.ToFloat64(e.ctrl.Metrics.ScaleEvents.WithLabelValues("out")); v != 1 {
		t.Errorf("scale_events_total{out} = %v", v)
	}
	if v := testutil.ToFloat64(e.ctrl.Metrics.Queued); v != 1 {
		t.Errorf("queued = %v", v)
	}
}

// Timers live on the StatefulSet: a new scaler (restart, new leader) keeps
// counting where the old one stopped.
func TestTimersSurviveRestart(t *testing.T) {
	f := &fakeSG{group: &sg.RunnerGroup{ContainerInstances: []sg.Instance{inst(0, "ACTIVE", true, 0), inst(1, "ACTIVE", true, 0)}}}
	e := newEnv(t, f, statefulSet(2), claim("state-sg-runner-0", nil), claim("state-sg-runner-1", nil))
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	if got := e.sts().Annotations[decide.AnnotationIdleSince]; got != fmt.Sprintf(`{"1":%d}`, t0.Unix()) {
		t.Fatalf("idle-since annotation = %q", got)
	}
	// Restarted scaler, 60s later.
	e.ctrl = e.newController(f)
	e.now = t0.Add(time.Minute)
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	s := e.sts()
	if kube.Replicas(s) != 1 {
		t.Fatalf("replicas = %d, want 1 (parked with the persisted timer)", kube.Replicas(s))
	}
	if _, ok := s.Annotations[decide.AnnotationIdleSince]; ok {
		t.Errorf("idle-since should be cleared after parking: %v", s.Annotations)
	}
	// The parked runner's PVC gets stamped.
	p, _ := e.claim("state-sg-runner-1")
	if p.Annotations[kube.AnnotationParkedAt] != fmt.Sprint(e.now.Unix()) {
		t.Errorf("parked-at = %v", p.Annotations)
	}
	if ev := e.drainEvents(); !hasEvent(ev, "Normal ScaledIn") || !hasEvent(ev, "Normal Parked") {
		t.Errorf("events %v", ev)
	}
}

// A runner parked without its preStop drain is drained and marked; on
// wake the scaler reactivates it and clears the mark. Unmarked drains stick.
func TestDrainParkedAndReactivate(t *testing.T) {
	f := &fakeSG{group: &sg.RunnerGroup{ContainerInstances: []sg.Instance{
		inst(0, "ACTIVE", true, 1), inst(1, "ACTIVE", false, 0), inst(2, "DRAINING", false, 0),
	}}}
	e := newEnv(t, f, statefulSet(1), claim("state-sg-runner-0", nil), claim("state-sg-runner-1", nil), claim("state-sg-runner-2", nil))
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.statuses, ",") != "r-1=DRAINING" {
		t.Fatalf("status calls = %v", f.statuses)
	}
	p, _ := e.claim("state-sg-runner-1")
	if p.Annotations[kube.AnnotationDrainedByScaler] != fmt.Sprint(t0.Unix()) {
		t.Fatalf("drain mark = %v", p.Annotations)
	}
	if ev := e.drainEvents(); !hasEvent(ev, "Normal DrainedParkedRunner") {
		t.Errorf("events %v", ev)
	}

	// Woken (someone scales to 3), both connected again, DRAINING.
	f.statuses = nil
	if err := e.ctrl.Kube.Scale(context.Background(), 3); err != nil {
		t.Fatal(err)
	}
	f.group.ContainerInstances = []sg.Instance{inst(0, "ACTIVE", true, 1), inst(1, "DRAINING", true, 0), inst(2, "DRAINING", true, 0)}
	e.now = t0.Add(time.Minute)
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.statuses, ",") != "r-1=ACTIVE" {
		t.Fatalf("status calls = %v (runner 2 was drained by someone else)", f.statuses)
	}
	p, _ = e.claim("state-sg-runner-1")
	if _, ok := p.Annotations[kube.AnnotationDrainedByScaler]; ok {
		t.Errorf("drain mark not cleared: %v", p.Annotations)
	}
	if ev := e.drainEvents(); !hasEvent(ev, "Normal Reactivated") {
		t.Errorf("events %v", ev)
	}
	if v := testutil.ToFloat64(e.ctrl.Metrics.StatusChanges.WithLabelValues("Reactivated", "ok")); v != 1 {
		t.Errorf("status changes metric = %v", v)
	}
}

func TestReap(t *testing.T) {
	f := &fakeSG{group: &sg.RunnerGroup{ContainerInstances: []sg.Instance{inst(0, "ACTIVE", true, 1), inst(1, "DRAINING", false, 0)}}}
	parkedAt := map[string]string{kube.AnnotationParkedAt: fmt.Sprint(t0.Unix())}
	e := newEnv(t, f, statefulSet(1), claim("state-sg-runner-0", nil),
		claim("state-sg-runner-1", parkedAt), claim("docker-sg-runner-1", nil))
	ctx := context.Background()
	jobs := e.client.BatchV1().Jobs(ns)

	// Within the TTL: nothing.
	e.now = t0.Add(11 * time.Hour)
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	if l, _ := jobs.List(ctx, metav1.ListOptions{}); len(l.Items) != 0 {
		t.Fatal("job started before the TTL")
	}

	// Past it: a reap Job, which blocks waking that ordinal.
	e.now = t0.Add(12 * time.Hour)
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	j, err := jobs.Get(ctx, "sg-runner-reap-1", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if j.Spec.Template.Spec.Volumes[0].PersistentVolumeClaim.ClaimName != "state-sg-runner-1" {
		t.Error("job mounts the wrong PVC")
	}
	f.group.QueuedWorkflowsCount = 1
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	if kube.Replicas(e.sts()) != 1 {
		t.Fatal("woke a runner being deregistered")
	}
	f.group.QueuedWorkflowsCount = 0

	// Failed: deleted for a retry, warned.
	j.Status.Failed = 1
	if _, err := jobs.UpdateStatus(ctx, j, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.drainEvents()
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	if _, err := jobs.Get(ctx, "sg-runner-reap-1", metav1.GetOptions{}); err == nil {
		t.Fatal("failed job not deleted")
	}
	if ev := e.drainEvents(); !hasEvent(ev, "Warning ReapFailed") {
		t.Errorf("events %v", ev)
	}

	// Retried, succeeds: PVCs and Job deleted.
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	j, _ = jobs.Get(ctx, "sg-runner-reap-1", metav1.GetOptions{})
	j.Status.Succeeded = 1
	if _, err := jobs.UpdateStatus(ctx, j, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"state-sg-runner-1", "docker-sg-runner-1"} {
		if _, err := e.claim(name); err == nil {
			t.Errorf("%s not deleted", name)
		}
	}
	if _, err := jobs.Get(ctx, "sg-runner-reap-1", metav1.GetOptions{}); err == nil {
		t.Error("job not deleted")
	}
	if _, err := e.claim("state-sg-runner-0"); err != nil {
		t.Error("awake runner's PVC deleted")
	}
	if ev := e.drainEvents(); !hasEvent(ev, "Normal Reaped") {
		t.Errorf("events %v", ev)
	}
	m := e.ctrl.Metrics.Reaps
	if testutil.ToFloat64(m.WithLabelValues("started")) != 2 || testutil.ToFloat64(m.WithLabelValues("failed")) != 1 ||
		testutil.ToFloat64(m.WithLabelValues("succeeded")) != 1 {
		t.Error("reap metrics")
	}
}

func TestBackoffAndFailureEvents(t *testing.T) {
	f := &fakeSG{err: errors.New("SG API GET /: HTTP 503")}
	e := newEnv(t, f, statefulSet(2))
	var delays []time.Duration
	for i := 0; i < 7; i++ {
		if err := e.once(); err == nil {
			t.Fatal("want an error")
		}
		delays = append(delays, e.ctrl.Delay())
	}
	want := []time.Duration{30, 60, 120, 240, 300, 300, 300}
	for i := range want {
		if delays[i] != want[i]*time.Second {
			t.Fatalf("delays = %v", delays)
		}
	}
	if kube.Replicas(e.sts()) != 2 {
		t.Error("scaled while SG was unreachable")
	}
	ev := e.drainEvents()
	if len(ev) != 1 || !hasEvent(ev, "Warning SGUnreachable") {
		t.Errorf("want one rate-limited SGUnreachable warning, got %v", ev)
	}
	if testutil.ToFloat64(e.ctrl.Metrics.SGErrors) != 7 || testutil.ToFloat64(e.ctrl.Metrics.ConsecutiveFailures) != 7 {
		t.Error("error metrics")
	}
	// Recovered.
	f.err = nil
	f.group = &sg.RunnerGroup{ContainerInstances: []sg.Instance{inst(0, "ACTIVE", true, 1), inst(1, "ACTIVE", true, 1)}}
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	if e.ctrl.Delay() != 15*time.Second || testutil.ToFloat64(e.ctrl.Metrics.ConsecutiveFailures) != 0 {
		t.Error("back-off not reset")
	}
}

func TestKubeErrorSkipsDecisions(t *testing.T) {
	f := &fakeSG{group: &sg.RunnerGroup{QueuedWorkflowsCount: 1, ContainerInstances: []sg.Instance{inst(0, "ACTIVE", true, 1)}}}
	e := newEnv(t, f) // no StatefulSet
	if err := e.once(); err == nil {
		t.Fatal("want an error")
	}
	if testutil.ToFloat64(e.ctrl.Metrics.KubeErrors) != 1 {
		t.Error("kube error not counted")
	}
}

// Identical warnings go out once per WarnEvery while the condition lasts,
// and again as soon as it comes back after clearing.
func TestWarningRateLimit(t *testing.T) {
	stuck := &sg.RunnerGroup{QueuedWorkflowsCount: 1, ContainerInstances: []sg.Instance{inst(0, "ACTIVE", true, 0)}}
	f := &fakeSG{group: stuck}
	e := newEnv(t, f, statefulSet(1), claim("state-sg-runner-0", nil))
	count := func() int {
		n := 0
		for _, ev := range e.drainEvents() {
			if strings.HasPrefix(ev, "Warning StuckQueue") {
				n++
			}
		}
		return n
	}
	for at := time.Duration(0); at <= 12*time.Minute; at += 15 * time.Second {
		e.now = t0.Add(at)
		if err := e.once(); err != nil {
			t.Fatal(err)
		}
	}
	// Stuck from 3m: warned at 3m and 13m would be next; 3m..12m is one.
	if n := count(); n != 1 {
		t.Fatalf("StuckQueue warnings = %d, want 1", n)
	}
	if testutil.ToFloat64(e.ctrl.Metrics.Stuck) != 1 {
		t.Error("stuck metric")
	}
	f.group = &sg.RunnerGroup{ContainerInstances: stuck.ContainerInstances}
	e.now = e.now.Add(15 * time.Second)
	e.once()
	f.group = stuck
	for at := time.Duration(0); at <= 3*time.Minute; at += 15 * time.Second {
		e.now = e.now.Add(15 * time.Second)
		e.once()
	}
	if n := count(); n != 1 {
		t.Fatalf("StuckQueue warnings after the condition came back = %d, want 1", n)
	}
}

// End to end with the real SG client: the runner group's token must not
// reach logs, events or errors.
func TestNoSecretsInLogs(t *testing.T) {
	const secret = "sgrt_TOPSECRET_runner_token"
	body := `{"msg": {"RunnerToken": "` + secret + `", "QueuedWorkflowsCount": 1, "ContainerInstances": [
	  {"runnerId": "r-0", "status": "ACTIVE", "agentConnected": true, "runningTasksCount": 1,
	   "registeredResources": [{"name": "CPU", "integerValue": 2048}, {"name": "MEMORY", "integerValue": 4096}],
	   "remainingResources": [{"name": "CPU", "integerValue": 0}, {"name": "MEMORY", "integerValue": 0}],
	   "instanceDetails": [{"ComputerName": "sg-runner-0.sg-runner.sg.svc"}]}]}}`
	fail := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			w.WriteHeader(500)
		}
		io.WriteString(w, body)
	}))
	defer srv.Close()
	client := sg.New(sg.Credentials{Token: "node-tok", Organization: "o", RunnerGroup: "g", BaseAPI: srv.URL}, nil)
	e := newEnv(t, client, statefulSet(1), claim("state-sg-runner-0", nil))
	e.ctrl.FailureEvents = 1
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	fail = true
	err := e.once()
	if err == nil {
		t.Fatal("want an error")
	}
	all := e.logs.String() + strings.Join(e.drainEvents(), "\n") + err.Error()
	if strings.Contains(all, secret) || strings.Contains(all, "node-tok") {
		t.Errorf("secret leaked:\n%s", all)
	}
	if !strings.Contains(all, "HTTP 500") {
		t.Errorf("failure not reported:\n%s", all)
	}
}

func TestDelayCap(t *testing.T) {
	c := &Controller{Interval: 10 * time.Minute, MaxBackoff: 5 * time.Minute}
	c.failures = 3
	if c.Delay() != 10*time.Minute {
		t.Errorf("an interval above the cap is kept: %v", c.Delay())
	}
}

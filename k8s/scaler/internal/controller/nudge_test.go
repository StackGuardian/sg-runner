package controller

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"

	"github.com/StackGuardian/sg-runner/k8s/scaler/internal/decide"
	"github.com/StackGuardian/sg-runner/k8s/scaler/internal/sg"
)

var runnerLabels = map[string]string{"app.kubernetes.io/component": "runner"}

func runnerPod(n string, node string) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "sg-runner-" + n, Namespace: ns, UID: types.UID("uid-" + n), Labels: runnerLabels},
		Spec: corev1.PodSpec{
			NodeName: node,
			Affinity: &corev1.Affinity{PodAntiAffinity: &corev1.PodAntiAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{{
					TopologyKey: "kubernetes.io/hostname", LabelSelector: &metav1.LabelSelector{MatchLabels: runnerLabels}}}}},
			Containers: []corev1.Container{{Name: "dockerd", Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{
				corev1.ResourceCPU: resource.MustParse("6500m"), corev1.ResourceMemory: resource.MustParse("11Gi")}}}},
			Volumes: []corev1.Volume{{Name: "state"}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	if node == "" {
		p.Status = corev1.PodStatus{Phase: corev1.PodPending, Conditions: []corev1.PodCondition{{
			Type: corev1.PodScheduled, Status: corev1.ConditionFalse, Reason: corev1.PodReasonUnschedulable}}}
	}
	return p
}

func refusedEvent(pod string) *corev1.Event {
	return &corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Name: pod + ".1", Namespace: ns},
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: pod, Namespace: ns},
		Reason:         "NotTriggerScaleUp", Source: corev1.EventSource{Component: "cluster-autoscaler"},
	}
}

// nudgeEnv: runner 0 runs and is busy, runner 1 (awake, new) can't be
// scheduled.
func nudgeEnv(t *testing.T, objs ...runtime.Object) *env {
	sts := statefulSet(2)
	sts.Spec.Selector = &metav1.LabelSelector{MatchLabels: runnerLabels}
	objs = append(objs, sts, runnerPod("0", "node-a"), runnerPod("1", ""),
		claim("state-sg-runner-0", nil), claim("state-sg-runner-1", nil))
	e := newEnv(t, &fakeSG{group: &sg.RunnerGroup{ContainerInstances: []sg.Instance{inst(0, decide.StatusActive, true, 1)}}}, objs...)
	e.ctrl.Nudge = true
	return e
}

func (e *env) job(name string) (*batchv1.Job, error) {
	return e.client.BatchV1().Jobs(ns).Get(context.Background(), name, metav1.GetOptions{})
}

func TestNudgeStartsPlaceholderWhenAutoscalerRefuses(t *testing.T) {
	e := nudgeEnv(t, refusedEvent("sg-runner-1"))
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	j, err := e.job("sg-runner-nudge-1")
	if err != nil {
		t.Fatalf("no placeholder job: %v\n%s", err, e.logs)
	}
	ps := j.Spec.Template.Spec
	req := ps.Containers[0].Resources.Requests
	if req.Cpu().String() != "6500m" || req.Memory().String() != "11Gi" {
		t.Errorf("placeholder requests %v, want the runner's", req)
	}
	if len(ps.Volumes) != 0 {
		t.Errorf("placeholder has volumes %v", ps.Volumes)
	}
	if ps.Affinity == nil || ps.Affinity.PodAntiAffinity == nil {
		t.Errorf("placeholder lost the runner's anti-affinity")
	}
	if j.Labels["app.kubernetes.io/component"] == "runner" {
		t.Errorf("placeholder carries runner labels: %v", j.Labels)
	}
	if !hasEvent(e.drainEvents(), "Normal NudgingAutoscaler runner 1") {
		t.Error("no NudgingAutoscaler event")
	}
	if _, err := e.job("sg-runner-nudge-0"); err == nil {
		t.Error("placeholder for the scheduled runner 0")
	}
}

func TestNudgeWaitsForTheAutoscalersVerdict(t *testing.T) {
	// No NotTriggerScaleUp: the autoscaler may still add a node itself.
	e := nudgeEnv(t)
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.job("sg-runner-nudge-1"); err == nil {
		t.Error("placeholder started without the autoscaler refusing")
	}
}

// autoscalerSays records the cluster autoscaler's answer on the runner's
// current placeholder pod.
func (e *env) autoscalerSays(n, reason string) {
	e.t.Helper()
	ev := &corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Name: "ph-" + n + "-" + reason + e.now.String(), Namespace: ns},
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "sg-runner-nudge-" + n + "-xyz", Namespace: ns},
		Reason:         reason, Message: "max node group size reached", LastTimestamp: metav1.NewTime(e.now),
	}
	if _, err := e.client.CoreV1().Events(ns).Create(context.Background(), ev, metav1.CreateOptions{}); err != nil {
		e.t.Fatal(err)
	}
}

func TestNudgeReleasesThePlaceholderOnceTheAutoscalerAccepts(t *testing.T) {
	e := nudgeEnv(t, refusedEvent("sg-runner-1"))
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	e.autoscalerSays("1", "TriggeredScaleUp")
	e.drainEvents()
	e.now = e.now.Add(e.ctrl.Interval)
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.job("sg-runner-nudge-1"); err == nil {
		t.Fatal("placeholder kept after the autoscaler accepted")
	}
	if !hasEvent(e.drainEvents(), "Normal NodeRequested runner 1") {
		t.Error("no NodeRequested event")
	}
	if v := testutil.ToFloat64(e.ctrl.Metrics.Nudges.WithLabelValues("node_requested")); v != 1 {
		t.Errorf("node_requested = %v, want 1", v)
	}
	// The node is booting and the runner still Pending: no new placeholder
	// within the cooldown.
	e.now = e.now.Add(time.Minute)
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.job("sg-runner-nudge-1"); err == nil {
		t.Error("new placeholder within the cooldown")
	}
	// Past it, still unschedulable: ask again, and that's the attempt
	// after which it's reported.
	e.now = e.now.Add(e.ctrl.NudgeCooldown)
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.job("sg-runner-nudge-1"); err != nil {
		t.Fatalf("no placeholder after the cooldown: %v", err)
	}
	if hasEvent(e.drainEvents(), "Warning ScaleUpBlocked") {
		t.Error("blocked after only one earlier attempt")
	}
	_ = e.client.BatchV1().Jobs(ns).Delete(context.Background(), "sg-runner-nudge-1", metav1.DeleteOptions{})
	e.now = e.now.Add(e.ctrl.NudgeCooldown)
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	if !hasEvent(e.drainEvents(), "Warning ScaleUpBlocked runner 1 can't get a node: still unschedulable after 2") {
		t.Error("no ScaleUpBlocked after repeated attempts")
	}
}

func TestNudgeHandsOverARunningPlaceholder(t *testing.T) {
	// The placeholder found room without a scale-up (a node freed up).
	e := nudgeEnv(t, refusedEvent("sg-runner-1"))
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	j, _ := e.job("sg-runner-nudge-1")
	j.Status.Ready = ptr.To[int32](1)
	if _, err := e.client.BatchV1().Jobs(ns).UpdateStatus(context.Background(), j, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(e.ctrl.Interval)
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.job("sg-runner-nudge-1"); err == nil {
		t.Error("running placeholder kept")
	}
}

func TestNudgeReportsAPlaceholderTheAutoscalerRefuses(t *testing.T) {
	e := nudgeEnv(t, refusedEvent("sg-runner-1"))
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	e.autoscalerSays("1", "NotTriggerScaleUp")
	e.drainEvents()
	e.now = e.now.Add(e.ctrl.Interval)
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.job("sg-runner-nudge-1"); err == nil {
		t.Error("refused placeholder kept")
	}
	if !hasEvent(e.drainEvents(), "Warning ScaleUpBlocked runner 1 can't get a node: the cluster autoscaler won't add a node even without volumes (max node group size reached)") {
		t.Error("no ScaleUpBlocked warning with the autoscaler's reason")
	}
}

func TestNudgeDeletesPlaceholderOnceTheRunnerIsPlaced(t *testing.T) {
	e := nudgeEnv(t, refusedEvent("sg-runner-1"))
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.client.CoreV1().Pods(ns).Update(context.Background(), runnerPod("1", "node-b"), metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(e.ctrl.Interval)
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.job("sg-runner-nudge-1"); err == nil {
		t.Error("placeholder kept after the runner was placed")
	}
}

func TestNudgeReportsAPlaceholderPastItsDeadline(t *testing.T) {
	e := nudgeEnv(t, refusedEvent("sg-runner-1"))
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	j, _ := e.job("sg-runner-nudge-1")
	j.Status.Failed = 1
	if _, err := e.client.BatchV1().Jobs(ns).UpdateStatus(context.Background(), j, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	e.drainEvents()
	e.now = e.now.Add(e.ctrl.Interval)
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.job("sg-runner-nudge-1"); err == nil {
		t.Error("failed placeholder kept")
	}
	if !hasEvent(e.drainEvents(), "Warning ScaleUpBlocked runner 1") {
		t.Error("no ScaleUpBlocked warning")
	}
}

func TestNudgeOff(t *testing.T) {
	e := nudgeEnv(t, refusedEvent("sg-runner-1"))
	e.ctrl.Nudge = false
	if err := e.once(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.job("sg-runner-nudge-1"); err == nil {
		t.Error("placeholder with nudging off")
	}
}

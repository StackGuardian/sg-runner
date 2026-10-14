package steps

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var t0 = time.Date(2026, 10, 14, 10, 0, 0, 0, time.UTC)

// pod is a step pod created at t0 in a phase, with the step container's state
// (nil for none).
func pod(phase corev1.PodPhase, cs *corev1.ContainerState, edit ...func(*corev1.Pod)) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: testID, Namespace: "sg", CreationTimestamp: metav1.NewTime(t0)},
		Spec:       corev1.PodSpec{NodeName: "node-a"},
		Status:     corev1.PodStatus{Phase: phase},
	}
	if cs != nil {
		p.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: ContainerName, State: *cs}}
	}
	for _, e := range edit {
		e(p)
	}
	return p
}

func waiting(reason, message string) *corev1.ContainerState {
	return &corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: reason, Message: message}}
}

func running(at time.Time) *corev1.ContainerState {
	return &corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: metav1.NewTime(at)}}
}

func terminated(code int32, reason string, from, to time.Time) *corev1.ContainerState {
	return &corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{
		ExitCode: code, Reason: reason, StartedAt: metav1.NewTime(from), FinishedAt: metav1.NewTime(to)}}
}

func unscheduled(p *corev1.Pod) {
	p.Spec.NodeName = ""
	p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodScheduled, Status: corev1.ConditionFalse,
		Reason: corev1.PodReasonUnschedulable, Message: "0/3 nodes are available", LastTransitionTime: metav1.NewTime(t0)}}
}

func deleting(p *corev1.Pod) { p.DeletionTimestamp = ptrTime(t0.Add(time.Hour)) }

func podFailed(reason string) func(*corev1.Pod) {
	return func(p *corev1.Pod) {
		p.Status.Reason, p.Status.Message = reason, reason+" message"
		p.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionFalse,
			LastTransitionTime: metav1.NewTime(t0.Add(7 * time.Minute))}}
	}
}

func ptrTime(t time.Time) *metav1.Time { m := metav1.NewTime(t); return &m }

func TestStepState(t *testing.T) {
	cfg := testConfig()
	started, ended := t0.Add(time.Minute), t0.Add(6*time.Minute)
	type want struct {
		state, reason string
		code          *int32
		start, finish *time.Time
	}
	code := func(c int32) *int32 { return &c }
	at := func(t time.Time) *time.Time { return &t }
	cases := map[string]struct {
		pod     *corev1.Pod
		after   time.Duration
		stopped bool
		want    want
	}{
		"just created":       {pod(corev1.PodPending, nil), time.Second, false, want{state: StatePending}},
		"creating":           {pod(corev1.PodPending, waiting("ContainerCreating", "")), time.Minute, false, want{state: StatePending}},
		"unscheduled":        {pod(corev1.PodPending, nil, unscheduled), 4 * time.Minute, false, want{state: StatePending}},
		"unschedulable":      {pod(corev1.PodPending, nil, unscheduled), 6 * time.Minute, false, want{state: StateFailed, reason: FailedUnschedulable, finish: at(t0.Add(5 * time.Minute))}},
		"pull backoff":       {pod(corev1.PodPending, waiting("ImagePullBackOff", "Back-off pulling image")), time.Minute, false, want{state: StateFailed, reason: FailedImagePullBackOff}},
		"pull not found":     {pod(corev1.PodPending, waiting("ErrImagePull", `rpc error: ... "x:1": not found`)), time.Minute, false, want{state: StateFailed, reason: FailedErrImagePull}},
		"pull unauthorized":  {pod(corev1.PodPending, waiting("ErrImagePull", "failed to authorize: 401 Unauthorized")), time.Minute, false, want{state: StateFailed, reason: FailedErrImagePull}},
		"pull denied":        {pod(corev1.PodPending, waiting("ErrImagePull", "pull access denied, repository does not exist")), time.Minute, false, want{state: StateFailed, reason: FailedErrImagePull}},
		"pull timeout":       {pod(corev1.PodPending, waiting("ErrImagePull", "dial tcp: i/o timeout")), time.Minute, false, want{state: StatePending}},
		"invalid image":      {pod(corev1.PodPending, waiting("InvalidImageName", "")), time.Minute, false, want{state: StateFailed, reason: FailedInvalidImageName}},
		"never pull":         {pod(corev1.PodPending, waiting("ErrImageNeverPull", "")), time.Minute, false, want{state: StateFailed, reason: FailedErrImageNeverPull}},
		"config error":       {pod(corev1.PodPending, waiting("CreateContainerConfigError", "secret not found")), 29 * time.Minute, false, want{state: StatePending}},
		"config error late":  {pod(corev1.PodPending, waiting("CreateContainerConfigError", "secret not found")), 31 * time.Minute, false, want{state: StateFailed, reason: FailedStartTimeout, finish: at(t0.Add(30 * time.Minute))}},
		"start timeout":      {pod(corev1.PodPending, waiting("ContainerCreating", "")), 31 * time.Minute, false, want{state: StateFailed, reason: FailedStartTimeout, finish: at(t0.Add(30 * time.Minute))}},
		"running":            {pod(corev1.PodRunning, running(started)), time.Hour, false, want{state: StateRunning, start: &started}},
		"exited 0":           {pod(corev1.PodSucceeded, terminated(0, "Completed", started, ended)), time.Hour, false, want{StateExited, "Completed", code(0), &started, &ended}},
		"exited 11":          {pod(corev1.PodFailed, terminated(11, "Error", started, ended)), time.Hour, false, want{StateExited, "Error", code(11), &started, &ended}},
		"oom killed":         {pod(corev1.PodFailed, terminated(137, "OOMKilled", started, ended)), time.Hour, false, want{StateExited, "OOMKilled", code(137), &started, &ended}},
		"exited, deleted":    {pod(corev1.PodFailed, terminated(3, "Error", started, ended), deleting), time.Hour, false, want{StateExited, "Error", code(3), &started, &ended}},
		"evicted":            {pod(corev1.PodFailed, terminated(137, "Error", started, ended), podFailed("Evicted")), time.Hour, false, want{state: StateFailed, reason: FailedEvicted, finish: &ended}},
		"evicted, no status": {pod(corev1.PodFailed, nil, podFailed("Evicted")), time.Hour, false, want{state: StateFailed, reason: FailedEvicted, finish: at(t0.Add(7 * time.Minute))}},
		"deadline":           {pod(corev1.PodFailed, terminated(137, "Error", started, ended), podFailed("DeadlineExceeded")), time.Hour, false, want{state: StateFailed, reason: FailedDeadlineExceeded, finish: &ended}},
		"rejected by node":   {pod(corev1.PodFailed, waiting("ContainerCreating", ""), podFailed("OutOfmemory")), time.Hour, false, want{state: StateFailed, reason: FailedUnschedulable, finish: at(t0.Add(7 * time.Minute))}},
		"shut down":          {pod(corev1.PodFailed, running(started), podFailed("NodeShutdown")), time.Hour, false, want{state: StateFailed, reason: FailedEvicted, finish: at(t0.Add(7 * time.Minute))}},
		"deleted running":    {pod(corev1.PodRunning, running(started), deleting), time.Hour, false, want{state: StateFailed, reason: FailedPodDeleted}},
		"deleted pending":    {pod(corev1.PodPending, nil, deleting), time.Minute, false, want{state: StateFailed, reason: FailedPodDeleted}},
		"stopping running":   {pod(corev1.PodRunning, running(started), deleting), time.Hour, true, want{state: StateRunning, start: &started}},
		"stopped exited":     {pod(corev1.PodFailed, terminated(143, "Error", started, ended), deleting), time.Hour, true, want{StateExited, "Error", code(143), &started, &ended}},
	}
	for name, c := range cases {
		got := cfg.StepState(c.pod, t0.Add(c.after), c.stopped)
		w := c.want
		if got.ID != testID || got.State != w.state || got.Reason != w.reason || !eqCode(got.ExitCode, w.code) ||
			!eqTime(got.StartedAt, w.start) || !eqTime(got.FinishedAt, w.finish) {
			t.Errorf("%s: got %+v (code %v, started %v, finished %v), want %+v", name, got,
				deref(got.ExitCode), got.StartedAt, got.FinishedAt, w)
		}
		if got.Terminal() != (w.state == StateExited || w.state == StateFailed) {
			t.Errorf("%s: Terminal = %v", name, got.Terminal())
		}
	}
}

func TestStepStateMessages(t *testing.T) {
	cfg := testConfig()
	st := cfg.StepState(pod(corev1.PodPending, waiting("ContainerCreating", "pulling")), t0.Add(time.Minute), false)
	if st.Message != "ContainerCreating: pulling" {
		t.Errorf("pending message %q", st.Message)
	}
	st = cfg.StepState(pod(corev1.PodPending, waiting("CreateContainerConfigError", "secret x not found")), t0.Add(time.Hour), false)
	if st.Message != "not started after 30m0s (CreateContainerConfigError: secret x not found)" {
		t.Errorf("start timeout message %q", st.Message)
	}
	st = cfg.StepState(pod(corev1.PodPending, nil, unscheduled), t0.Add(time.Hour), false)
	if st.Message != "0/3 nodes are available" {
		t.Errorf("unschedulable message %q", st.Message)
	}
}

func TestStoppedState(t *testing.T) {
	st := stoppedState(testID, nil)
	if st.State != StateExited || *st.ExitCode != 137 || st.Reason != ReasonStopped || st.ID != testID {
		t.Errorf("stopped without a last state: %+v", st)
	}
	pending := State{ID: testID, State: StatePending}
	if st := stoppedState(testID, &pending); st.State != StateExited || *st.ExitCode != 137 {
		t.Errorf("stopped while pending: %+v", st)
	}
	c := int32(143)
	exited := State{ID: testID, State: StateExited, ExitCode: &c, Reason: "Error"}
	if st := stoppedState(testID, &exited); *st.ExitCode != 143 || st.Reason != "Error" {
		t.Errorf("stopped after exiting: %+v", st)
	}
}

func eqCode(a, b *int32) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }

func eqTime(a, b *time.Time) bool { return a == nil && b == nil || a != nil && b != nil && a.Equal(*b) }

func deref(c *int32) any {
	if c == nil {
		return nil
	}
	return *c
}

package kube

import (
	"context"
	"testing"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func TestPodRequestsSumsContainersAndTakesTheLargerInit(t *testing.T) {
	q := resource.MustParse
	p := &corev1.Pod{Spec: corev1.PodSpec{
		InitContainers: []corev1.Container{{Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{
			corev1.ResourceCPU: q("8"), corev1.ResourceMemory: q("1Gi")}}}},
		Containers: []corev1.Container{
			{Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: q("6500m"), corev1.ResourceMemory: q("11Gi")}}},
			{Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceMemory: q("32Mi")}}},
			{},
		},
	}}
	got := PodRequests(p)
	if got.Cpu().String() != "8" || got.Memory().String() != "11296Mi" {
		t.Errorf("PodRequests = cpu %s memory %s, want 8 and 11296Mi", got.Cpu(), got.Memory())
	}
}

func TestUnschedulable(t *testing.T) {
	cond := func(reason string) []corev1.PodCondition {
		return []corev1.PodCondition{{Type: corev1.PodScheduled, Status: corev1.ConditionFalse, Reason: reason}}
	}
	cases := map[string]struct {
		pod  corev1.Pod
		want bool
	}{
		"unschedulable": {corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodPending, Conditions: cond(corev1.PodReasonUnschedulable)}}, true},
		"not tried yet": {corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodPending}}, false},
		"other reason":  {corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodPending, Conditions: cond("SchedulingGated")}}, false},
		"bound":         {corev1.Pod{Spec: corev1.PodSpec{NodeName: "n"}, Status: corev1.PodStatus{Phase: corev1.PodPending, Conditions: cond(corev1.PodReasonUnschedulable)}}, false},
		"running":       {corev1.Pod{Status: corev1.PodStatus{Phase: corev1.PodRunning}}, false},
	}
	for name, c := range cases {
		if got := Unschedulable(&c.pod); got != c.want {
			t.Errorf("%s: Unschedulable = %v, want %v", name, got, c.want)
		}
	}
}

func TestNudgeJobs(t *testing.T) {
	job := func(name string, st batchv1.JobStatus) *batchv1.Job {
		return &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: map[string]string{"app": "sg-runner-nudge"}}, Status: st}
	}
	k := newKube(
		job("sg-runner-nudge-1", batchv1.JobStatus{}),
		job("sg-runner-nudge-2", batchv1.JobStatus{Ready: ptr.To[int32](1)}),
		job("sg-runner-nudge-3", batchv1.JobStatus{Failed: 1}),
	)
	got, err := k.NudgeJobs(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]NudgeState{1: NudgeWaiting, 2: NudgeRunning, 3: NudgeFailed}
	for n, s := range want {
		if got[n].State != s {
			t.Errorf("ordinal %d: %v, want %v", n, got[n].State, s)
		}
	}
	if len(got) != len(want) {
		t.Errorf("NudgeJobs = %v", got)
	}
}

func TestNudgeJobIsAPlainPlaceholder(t *testing.T) {
	k := newKube()
	k.ReapPod.ImagePullSecrets = []string{"regcred"}
	runner := &corev1.Pod{Spec: corev1.PodSpec{
		NodeSelector: map[string]string{"pool": "runners"},
		Tolerations:  []corev1.Toleration{{Key: "dedicated", Operator: corev1.TolerationOpExists}},
		Containers: []corev1.Container{{Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{
			corev1.ResourceCPU: resource.MustParse("2")}}}},
		Volumes: []corev1.Volume{{Name: "state"}},
	}}
	j := k.NudgeJob(4, runner)
	ps := j.Spec.Template.Spec
	if j.Name != "sg-runner-nudge-4" || j.Labels["app"] != "sg-runner-nudge" {
		t.Errorf("name/labels %s %v", j.Name, j.Labels)
	}
	if ps.Containers[0].Image != DefaultNudgeImage || len(ps.Volumes) != 0 || *ps.AutomountServiceAccountToken {
		t.Errorf("not a plain placeholder: %+v", ps)
	}
	if ps.NodeSelector["pool"] != "runners" || len(ps.Tolerations) != 1 || ps.ImagePullSecrets[0].Name != "regcred" {
		t.Errorf("scheduling not copied: %+v", ps)
	}
	if *j.Spec.ActiveDeadlineSeconds != NudgeDeadline || *j.Spec.BackoffLimit != 0 {
		t.Errorf("deadline/backoff %+v", j.Spec)
	}
}

func TestNudgeOutcomeReadsOnlyTheCurrentPlaceholder(t *testing.T) {
	created := time.Unix(1_700_000_000, 0)
	ev := func(name, pod, reason string, at time.Time) *corev1.Event {
		return &corev1.Event{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: pod}, Reason: reason, Message: reason + " msg",
			LastTimestamp: metav1.NewTime(at)}
	}
	k := newKube(
		// An earlier placeholder for runner 2, and another runner's.
		ev("e1", "sg-runner-nudge-2-old", EventScaleUpTriggered, created.Add(-5*time.Minute)),
		ev("e2", "sg-runner-nudge-3-abc", EventScaleUpTriggered, created.Add(time.Minute)),
		ev("e3", "sg-runner-2", EventScaleUpRefused, created.Add(time.Minute)),
	)
	ctx := context.Background()
	if r, _, err := k.NudgeOutcome(ctx, 2, created); err != nil || r != "" {
		t.Fatalf("outcome before any answer = %q, %v; want none", r, err)
	}

	_, _ = k.Client.CoreV1().Events(ns).Create(ctx, ev("e4", "sg-runner-nudge-2-new", EventScaleUpRefused, created.Add(time.Second)), metav1.CreateOptions{})
	if r, msg, _ := k.NudgeOutcome(ctx, 2, created); r != EventScaleUpRefused || msg != "NotTriggerScaleUp msg" {
		t.Errorf("outcome = %q %q, want the refusal", r, msg)
	}
	// Triggered wins over an earlier refusal of the same placeholder.
	_, _ = k.Client.CoreV1().Events(ns).Create(ctx, ev("e5", "sg-runner-nudge-2-new", EventScaleUpTriggered, created.Add(2*time.Second)), metav1.CreateOptions{})
	if r, _, _ := k.NudgeOutcome(ctx, 2, created); r != EventScaleUpTriggered {
		t.Errorf("outcome = %q, want %q", r, EventScaleUpTriggered)
	}
}

package steps

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// stepPod is a labeled step pod of a runner, created at created.
func stepPod(name, runner string, created time.Time, phase corev1.PodPhase, cs *corev1.ContainerState) *corev1.Pod {
	p := pod(phase, cs)
	p.Name, p.CreationTimestamp = name, metav1.NewTime(created)
	p.Labels = map[string]string{LabelComponent: ComponentStep, LabelRunner: runner}
	return p
}

func stepSecret(name, runner string, created time.Time) *corev1.Secret {
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "sg", CreationTimestamp: metav1.NewTime(created),
		Labels: map[string]string{LabelComponent: ComponentStep, LabelRunner: runner}}}
}

func short(names []string) string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, strings.TrimPrefix(n, "sg-runner-0-s-"))
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

func (hs *harness) podNames() []string {
	var out []string
	for _, p := range hs.pods() {
		out = append(out, p.Name)
	}
	return out
}

func (hs *harness) outcomes() map[string]string {
	out := map[string]string{}
	for _, p := range hs.pods() {
		if o, ok := p.Labels[LabelOutcome]; ok {
			out[strings.TrimPrefix(p.Name, "sg-runner-0-s-")] = o
		}
	}
	return out
}

func TestSweep(t *testing.T) {
	now := t0.Add(3 * time.Hour)
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	id := func(s string) string { return "sg-runner-0-s-" + s }
	var objs []runtime.Object
	add := func(p *corev1.Pod, secrets bool) {
		objs = append(objs, p)
		if secrets {
			objs = append(objs, stepSecret(p.Name+"-env", "sg-runner-0", p.CreationTimestamp.Time),
				stepSecret(p.Name+"-pull", "sg-runner-0", p.CreationTimestamp.Time))
		}
	}
	// Ended over FINISHED_TTL (1h) ago: goes, with its Secrets.
	add(stepPod(id("old00000"), "sg-runner-0", ago(2*time.Hour), corev1.PodFailed, terminated(3, "Error", ago(2*time.Hour), ago(61*time.Minute))), true)
	// Ended within the TTL, or read by a stream: stays, finished.
	add(stepPod(id("recent00"), "sg-runner-0", ago(2*time.Hour), corev1.PodSucceeded, terminated(0, "Completed", ago(2*time.Hour), ago(59*time.Minute))), true)
	add(stepPod(id("streamed"), "sg-runner-0", ago(2*time.Hour), corev1.PodSucceeded, terminated(0, "Completed", ago(2*time.Hour), ago(2*time.Hour))), true)
	// Running: untouched.
	add(stepPod(id("running0"), "sg-runner-0", ago(time.Hour), corev1.PodRunning, running(ago(time.Hour))), true)
	// Failed in the broker's eyes: its deadline, or (no time to tell) when
	// the broker first saw it, counts as its end.
	unsched := stepPod(id("unsched0"), "sg-runner-0", ago(2*time.Hour), corev1.PodPending, nil)
	unscheduled(unsched)
	unsched.CreationTimestamp = metav1.NewTime(ago(2 * time.Hour))
	add(unsched, false)
	add(stepPod(id("pullfail"), "sg-runner-0", ago(2*time.Hour), corev1.PodPending, waiting("ImagePullBackOff", "")), true)
	// Not ours to touch.
	add(stepPod("sg-runner-1-s-other000", "sg-runner-1", ago(2*time.Hour), corev1.PodSucceeded, terminated(0, "Completed", ago(2*time.Hour), ago(2*time.Hour))), false)
	add(stepPod("sg-runner-0-s-bad", "sg-runner-0", ago(2*time.Hour), corev1.PodSucceeded, terminated(0, "Completed", ago(2*time.Hour), ago(2*time.Hour))), false)
	// Secrets of a stopped step whose pod is gone go; Secrets of a pod that
	// vanished without the broker wait for the runner pod.
	objs = append(objs, stepSecret(id("gone0000")+"-env", "sg-runner-0", ago(time.Hour)),
		stepSecret(id("vanished")+"-env", "sg-runner-0", ago(time.Hour)))

	hs := newHarness(t, objs...)
	hs.now = now
	hs.s.steps[id("gone0000")] = &stepRecord{at: ago(61 * time.Minute), stopped: true}
	hs.s.steps[id("gone0001")] = &stepRecord{at: ago(59 * time.Minute), stopped: true}
	exited := State{ID: id("forgot00"), State: StateExited}
	hs.s.steps[id("forgot00")] = &stepRecord{at: ago(3 * time.Hour), final: &exited, deleted: true,
		deletedAt: ago(61 * time.Minute), secretsDeleted: true}
	hs.s.openStream(id("streamed"))

	if err := hs.s.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A Secret list or get would return their data, the node token's too.
	for _, a := range hs.client.Actions() {
		if a.GetResource().Resource == "secrets" && a.GetVerb() != "delete" {
			t.Errorf("the GC did %s on secrets", a.GetVerb())
		}
	}
	if got := short(hs.podNames()); got != "bad pullfail recent00 running0 sg-runner-1-s-other000 streamed" {
		t.Errorf("pods left: %s", got)
	}
	if got := short(hs.secretNames()); got != "running0-env running0-pull vanished-env" {
		t.Errorf("secrets left: %s", got)
	}
	want := map[string]string{"pullfail": OutcomeFailed, "recent00": OutcomeSucceeded, "streamed": OutcomeSucceeded}
	if got := hs.outcomes(); len(got) != len(want) || got["pullfail"] != want["pullfail"] ||
		got["recent00"] != want["recent00"] || got["streamed"] != want["streamed"] {
		t.Errorf("outcomes %v", got)
	}
	var records []string
	for k := range hs.s.steps {
		records = append(records, k)
	}
	if got := short(records); got != "gone0001 old00000 pullfail recent00 streamed unsched0" {
		t.Errorf("records left: %s", got)
	}
	// Deleted after FINISHED_TTL, the step still tells how it ended.
	rec := hs.do("GET", "/v1/steps/"+id("old00000"), "")
	if !strings.Contains(rec.Body.String(), `"state":"exited","exitCode":3`) {
		t.Errorf("after the TTL: %d %s", rec.Code, rec.Body)
	}

	// An hour on, the stream closed: the pull failure first seen an hour ago
	// and the streamed step go; nothing is finished twice.
	hs.client.ClearActions()
	hs.s.closeStream(id("streamed"))
	hs.now = now.Add(61 * time.Minute)
	if err := hs.s.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := short(hs.podNames()); got != "bad running0 sg-runner-1-s-other000" {
		t.Errorf("pods left an hour on: %s", got)
	}
	for _, a := range hs.client.Actions() {
		if a.GetVerb() == "patch" {
			t.Errorf("patched again: %v", a)
		}
	}
}

func TestRunGCStopsWithItsContext(t *testing.T) {
	hs := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { hs.s.RunGC(ctx, time.Hour); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunGC didn't stop")
	}
}

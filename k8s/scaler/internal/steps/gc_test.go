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

func TestSweep(t *testing.T) {
	now := t0.Add(2 * time.Hour)
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	id := func(s string) string { return "sg-runner-0-s-" + s }
	objs := []runtime.Object{
		// Finished long enough ago: goes, with its Secrets.
		stepPod(id("old00000"), "sg-runner-0", ago(time.Hour), corev1.PodSucceeded, terminated(0, "Completed", ago(time.Hour), ago(11*time.Minute))),
		stepSecret(id("old00000")+"-env", "sg-runner-0", ago(time.Hour)),
		stepSecret(id("old00000")+"-pull", "sg-runner-0", ago(time.Hour)),
		// Finished recently, running, or read by a stream: stays.
		stepPod(id("recent00"), "sg-runner-0", ago(time.Hour), corev1.PodFailed, terminated(1, "Error", ago(time.Hour), ago(9*time.Minute))),
		stepSecret(id("recent00")+"-env", "sg-runner-0", ago(time.Hour)),
		stepPod(id("running0"), "sg-runner-0", ago(time.Hour), corev1.PodRunning, running(ago(time.Hour))),
		stepPod(id("streamed"), "sg-runner-0", ago(time.Hour), corev1.PodSucceeded, terminated(0, "Completed", ago(time.Hour), ago(time.Hour))),
		// Failed in the broker's eyes: counted from its deadline.
		stepPod(id("unsched0"), "sg-runner-0", ago(20*time.Minute), corev1.PodPending, nil),
		stepPod(id("pullold0"), "sg-runner-0", ago(45*time.Minute), corev1.PodPending, waiting("ImagePullBackOff", "")),
		stepPod(id("pullnew0"), "sg-runner-0", ago(35*time.Minute), corev1.PodPending, waiting("ImagePullBackOff", "")),
		stepPod(id("claimed0"), "sg-runner-0", ago(time.Hour), corev1.PodSucceeded, terminated(0, "Completed", ago(time.Hour), ago(time.Hour))),
		// Not ours to touch.
		stepPod("sg-runner-1-s-other000", "sg-runner-1", ago(time.Hour), corev1.PodSucceeded, terminated(0, "Completed", ago(time.Hour), ago(time.Hour))),
		stepPod("sg-runner-0-s-bad", "sg-runner-0", ago(time.Hour), corev1.PodSucceeded, terminated(0, "Completed", ago(time.Hour), ago(time.Hour))),
		// Secrets of a stopped step whose pod is gone go; Secrets of a pod
		// that vanished without a stop wait for the runner pod.
		stepSecret(id("gone0000")+"-env", "sg-runner-0", ago(time.Hour)),
		stepSecret(id("gone0000")+"-pull", "sg-runner-0", ago(time.Hour)),
		stepSecret(id("vanished")+"-env", "sg-runner-0", ago(time.Hour)),
	}
	unsched := objs[7].(*corev1.Pod)
	unscheduled(unsched)
	unsched.CreationTimestamp = metav1.NewTime(ago(20 * time.Minute))

	hs := newHarness(t, objs...)
	hs.now = now
	hs.s.steps[id("gone0000")] = &stepRecord{at: ago(61 * time.Minute), stopped: true}
	hs.s.steps[id("gone0001")] = &stepRecord{at: ago(59 * time.Minute), stopped: true}
	hs.s.steps[id("running0")] = &stepRecord{at: ago(2 * time.Hour), stopped: true}
	// A client got its final state and its deletion runs: not the GC's.
	exited := State{ID: id("claimed0"), State: StateExited}
	hs.s.steps[id("claimed0")] = &stepRecord{at: ago(time.Hour), final: &exited, deleting: true}
	// Deleted over an hour ago: forgotten.
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
	var pods []string
	for _, p := range hs.pods() {
		pods = append(pods, strings.TrimPrefix(p.Name, "sg-runner-0-s-"))
	}
	sort.Strings(pods)
	if got := strings.Join(pods, " "); got != "bad claimed0 pullnew0 recent00 running0 sg-runner-1-s-other000 streamed" {
		t.Errorf("pods left: %s", got)
	}
	secrets := hs.secretNames()
	sort.Strings(secrets)
	if got := strings.Join(secrets, " "); got != id("recent00")+"-env "+id("vanished")+"-env" {
		t.Errorf("secrets left: %s", got)
	}
	var records []string
	for k := range hs.s.steps {
		records = append(records, strings.TrimPrefix(k, "sg-runner-0-s-"))
	}
	sort.Strings(records)
	if got := strings.Join(records, " "); got != "claimed0 gone0001 old00000 pullold0 running0 unsched0" {
		t.Errorf("records left: %s", got)
	}
	if !hs.s.steps[id("gone0001")].secretsDeleted || hs.s.steps[id("running0")].secretsDeleted {
		t.Errorf("secretsDeleted: gone0001 %v, running0 %v", hs.s.steps[id("gone0001")].secretsDeleted,
			hs.s.steps[id("running0")].secretsDeleted)
	}
	// Deleted unread after FINISHED_TTL, the step still tells how it ended.
	rec := hs.do("GET", "/v1/steps/"+id("old00000"), "")
	if !strings.Contains(rec.Body.String(), `"state":"exited","exitCode":0`) {
		t.Errorf("after the fallback deletion: %d %s", rec.Code, rec.Body)
	}

	// Deleted once: the next sweep leaves Secrets alone.
	hs.client.ClearActions()
	if err := hs.s.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, a := range hs.client.Actions() {
		if a.GetResource().Resource == "secrets" {
			t.Errorf("second sweep: %s on secrets", a.GetVerb())
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

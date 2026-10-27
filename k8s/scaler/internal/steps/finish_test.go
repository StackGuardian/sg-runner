package steps

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

// waitFor polls cond for up to 5s.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting: %s", what)
		}
	}
}

// count counts the client's calls of a verb on a resource.
func count(hs *harness, verb, resource string) int {
	n := 0
	for _, a := range hs.client.Actions() {
		if a.GetVerb() == verb && a.GetResource().Resource == resource {
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

func (hs *harness) finished(id string) bool {
	hs.s.mu.Lock()
	defer hs.s.mu.Unlock()
	rec := hs.s.steps[id]
	return rec != nil && rec.finished
}

func TestOutcome(t *testing.T) {
	code := func(c int32) *int32 { return &c }
	for _, c := range []struct {
		st      State
		stopped bool
		want    string
	}{
		{State{State: StateExited, ExitCode: code(0)}, false, OutcomeSucceeded},
		{State{State: StateExited, ExitCode: code(11)}, false, OutcomeApprovalRequired},
		{State{State: StateExited, ExitCode: code(12)}, false, OutcomeCompletedEarly},
		{State{State: StateExited, ExitCode: code(1)}, false, OutcomeFailed},
		{State{State: StateExited, ExitCode: code(137)}, false, OutcomeFailed},
		{State{State: StateFailed, Reason: FailedImagePullBackOff}, false, OutcomeFailed},
		{State{State: StateExited, ExitCode: code(0)}, true, OutcomeStopped},
		{State{State: StateExited, ExitCode: code(143)}, true, OutcomeStopped},
	} {
		if got := Outcome(c.st, c.stopped); got != c.want {
			t.Errorf("%+v stopped=%v: %s, want %s", c.st, c.stopped, got, c.want)
		}
	}
}

// TestTerminalGetFinishesTheStep: the first GET that sees a step ended labels
// its pod with the outcome and deletes its Secrets; the pod stays.
func TestTerminalGetFinishesTheStep(t *testing.T) {
	for name, c := range map[string]struct {
		pod     *corev1.Pod
		code    string
		outcome string
	}{
		"approval":     {pod(corev1.PodSucceeded, wrappedExit0("sg-exit-code=11"), wrapped), `"exitCode":11`, OutcomeApprovalRequired},
		"early finish": {pod(corev1.PodSucceeded, wrappedExit0("sg-exit-code=12"), wrapped), `"exitCode":12`, OutcomeCompletedEarly},
		"success":      {pod(corev1.PodSucceeded, wrappedExit0(""), wrapped), `"exitCode":0`, OutcomeSucceeded},
		"error":        {pod(corev1.PodFailed, terminated(3, "Error", t0, t0)), `"exitCode":3`, OutcomeFailed},
		// The outcome follows the exit code, wrapped or not.
		"unwrapped 11": {pod(corev1.PodFailed, terminated(11, "Error", t0, t0)), `"exitCode":11`, OutcomeApprovalRequired},
		"unwrapped 12": {pod(corev1.PodFailed, terminated(12, "Error", t0, t0)), `"exitCode":12`, OutcomeCompletedEarly},
		"pull failed":  {pod(corev1.PodPending, waiting("ImagePullBackOff", "")), `"state":"failed"`, OutcomeFailed},
	} {
		hs := newHarness(t, append(stepSecrets(testID), c.pod)...)
		first := hs.do("GET", "/v1/steps/"+testID, "")
		if first.Code != 200 || !strings.Contains(first.Body.String(), c.code) {
			t.Fatalf("%s: get %d %s", name, first.Code, first.Body)
		}
		waitFor(t, name+": finished", func() bool { return hs.finished(testID) })
		if got := hs.outcomes()["7f3k9q2x"]; got != c.outcome {
			t.Errorf("%s: outcome %q, want %q", name, got, c.outcome)
		}
		if len(hs.secretNames()) != 0 || len(hs.pods()) != 1 {
			t.Errorf("%s: secrets %v, pods %v", name, hs.secretNames(), hs.podNames())
		}
		// Later GETs answer the same from memory; nothing is done twice.
		for i := 0; i < 3; i++ {
			if rec := hs.do("GET", "/v1/steps/"+testID, ""); rec.Body.String() != first.Body.String() {
				t.Errorf("%s: later get %s, want %s", name, rec.Body, first.Body)
			}
		}
		if err := hs.s.Sweep(context.Background()); err != nil {
			t.Fatal(err)
		}
		if count(hs, "patch", "pods") != 1 || count(hs, "delete", "pods") != 0 || count(hs, "get", "pods") != 1 {
			t.Errorf("%s: %d patches, %d pod deletes, %d gets", name, count(hs, "patch", "pods"),
				count(hs, "delete", "pods"), count(hs, "get", "pods"))
		}
	}
}

func TestNonTerminalGetsChangeNothing(t *testing.T) {
	hs := newHarness(t, append(stepSecrets(testID), pod(corev1.PodRunning, running(t0)))...)
	for i := 0; i < 3; i++ {
		hs.do("GET", "/v1/steps/"+testID, "")
	}
	time.Sleep(20 * time.Millisecond)
	if count(hs, "patch", "pods") != 0 || count(hs, "delete", "secrets") != 0 || len(hs.s.steps) != 0 {
		t.Errorf("actions %v, records %v", hs.client.Actions(), hs.s.steps)
	}
}

func TestLabeledPodIsNotPatchedAgain(t *testing.T) {
	p := pod(corev1.PodFailed, terminated(3, "Error", t0, t0))
	p.Labels = map[string]string{LabelOutcome: OutcomeFailed}
	hs := newHarness(t, append(stepSecrets(testID), p)...)
	hs.do("GET", "/v1/steps/"+testID, "")
	waitFor(t, "finished", func() bool { return hs.finished(testID) })
	if count(hs, "patch", "pods") != 0 || len(hs.secretNames()) != 0 {
		t.Errorf("%d patches, secrets %v", count(hs, "patch", "pods"), hs.secretNames())
	}
}

func TestFailedFinishIsRetried(t *testing.T) {
	hs := newHarness(t, append(stepSecrets(testID),
		stepPod(testID, "sg-runner-0", t0, corev1.PodSucceeded, terminated(0, "Completed", t0, t0)))...)
	var mu sync.Mutex
	failing := true
	hs.client.PrependReactor("delete", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
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
		return count(hs, "delete", "secrets") == 1 && !hs.s.steps[testID].finishing
	})
	if hs.finished(testID) {
		t.Fatal("finished despite the failure")
	}
	mu.Lock()
	failing = false
	mu.Unlock()
	if err := hs.s.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !hs.finished(testID) || len(hs.secretNames()) != 0 || len(hs.pods()) != 1 {
		t.Errorf("the sweep didn't retry: secrets %v", hs.secretNames())
	}
}

// TestStoppedStepOutcome: a stopped pod (being deleted) gets the stopped
// outcome and loses its Secrets.
func TestStoppedStepOutcome(t *testing.T) {
	hs := newHarness(t, append(stepSecrets(testID), pod(corev1.PodRunning, running(t0)))...)
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
	waitFor(t, "finished", func() bool { return hs.finished(testID) })
	if got := hs.outcomes()["7f3k9q2x"]; got != OutcomeStopped || len(hs.secretNames()) != 0 {
		t.Errorf("outcome %q, secrets %v", got, hs.secretNames())
	}
	if rec := hs.do("GET", "/v1/steps/"+testID, ""); !strings.Contains(rec.Body.String(), `"exitCode":143`) {
		t.Errorf("get %s", rec.Body)
	}
}

// fakeImages answers lookups from a map and records them.
type fakeImages struct {
	mu      sync.Mutex
	configs map[string]ImageConfig
	auths   []*RegistryAuth
}

func (f *fakeImages) Lookup(_ context.Context, image string, auth *RegistryAuth) (ImageConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auths = append(f.auths, auth)
	c, ok := f.configs[image]
	if !ok {
		return ImageConfig{}, errors.New("MANIFEST_UNKNOWN: manifest unknown")
	}
	return c, nil
}

func TestCreateWraps(t *testing.T) {
	images := &fakeImages{configs: map[string]ImageConfig{
		"registry.example.com/team/image:1.2": {Entrypoint: []string{"/entry"}, Cmd: []string{"default"}},
		"empty:1":                             {},
	}}
	created := func(t *testing.T, cfg func(*Config), edit func(*Request)) *corev1.Pod {
		t.Helper()
		hs := newHarness(t)
		if cfg != nil {
			cfg(&hs.s.Config)
		}
		hs.s.Images = images
		if rec := hs.do("POST", "/v1/steps", requestJSON(t, edit)); rec.Code != 201 {
			t.Fatalf("create %d %s", rec.Code, rec.Body)
		}
		return &hs.pods()[0]
	}

	p := created(t, nil, func(r *Request) {
		r.RegistryAuth = &RegistryAuth{Registry: "registry.example.com", Username: "u", Password: "p"}
	})
	c := p.Spec.Containers[0]
	if p.Annotations[AnnotationWrapped] != "true" || len(p.Spec.InitContainers) != 1 ||
		strings.Join(c.Command, " ") != WrapperPath+" -- /entry sh -c echo $$(HOME) $$HOME" || c.Args != nil {
		t.Errorf("wrapped pod: annotations %v, command %q, args %q", p.Annotations, c.Command, c.Args)
	}
	if a := images.auths[0]; a == nil || a.Username != "u" {
		t.Errorf("lookup auth %+v", a)
	}

	for name, c := range map[string]struct {
		cfg    func(*Config)
		edit   func(*Request)
		reason string
	}{
		"lookup fails":    {nil, func(r *Request) { r.Image = "unknown:1" }, "image config lookup: MANIFEST_UNKNOWN"},
		"nothing to run":  {nil, func(r *Request) { r.Image, r.Args = "empty:1", nil }, "the image has no entrypoint or cmd"},
		"no broker image": {func(c *Config) { c.BrokerImage = "" }, nil, "BROKER_IMAGE is not set"},
	} {
		p := created(t, c.cfg, c.edit)
		ct := p.Spec.Containers[0]
		if p.Annotations[AnnotationWrapped] != "false" || !strings.HasPrefix(p.Annotations[AnnotationNotWrappedReason], c.reason) ||
			p.Spec.InitContainers != nil || ct.Command != nil {
			t.Errorf("%s: annotations %v, command %q", name, p.Annotations, ct.Command)
		}
	}
}

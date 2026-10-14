package teardown

import (
	"bytes"
	"context"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/StackGuardian/sg-runner/k8s/scaler/internal/kube"
)

const ns = "sg"

func pod(name, component string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns,
		Labels: map[string]string{"app.kubernetes.io/component": component}}}
}

func pvc(name string) *corev1.PersistentVolumeClaim {
	return &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}
}

// cluster stands in for the controllers and the kubelet: it removes pods
// once their workload is scaled to 0 and finishes reap Jobs, failing those
// of the ordinals in fail.
type cluster struct {
	t    *testing.T
	k    *kube.Kube
	fail map[string]bool
	logs *bytes.Buffer
}

func newCluster(t *testing.T, fail []string, objs ...runtime.Object) *cluster {
	c := &cluster{t: t, k: kube.New(fake.NewClientset(objs...), ns, "sg-runner", "runner:1", "creds", "cfg"),
		fail: map[string]bool{}, logs: &bytes.Buffer{}}
	for _, name := range fail {
		c.fail[name] = true
	}
	return c
}

func (c *cluster) step(ctx context.Context) {
	cs := c.k.Client
	if d, err := cs.AppsV1().Deployments(ns).Get(ctx, "sg-runner-scaler", metav1.GetOptions{}); err == nil && *d.Spec.Replicas == 0 {
		c.deletePods(ctx, "scaler")
	}
	if s, err := c.k.GetStatefulSet(ctx); err == nil && *s.Spec.Replicas == 0 {
		c.deletePods(ctx, "runner")
	}
	jobs, _ := cs.BatchV1().Jobs(ns).List(ctx, metav1.ListOptions{})
	for _, j := range jobs.Items {
		if j.Status.Succeeded+j.Status.Failed > 0 {
			continue
		}
		if c.fail[j.Name] {
			j.Status.Failed = 1
		} else {
			j.Status.Succeeded = 1
		}
		if _, err := cs.BatchV1().Jobs(ns).UpdateStatus(ctx, &j, metav1.UpdateOptions{}); err != nil {
			c.t.Error(err)
		}
	}
}

func (c *cluster) deletePods(ctx context.Context, component string) {
	pods, _ := c.k.Client.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/component=" + component})
	for _, p := range pods.Items {
		_ = c.k.Client.CoreV1().Pods(ns).Delete(ctx, p.Name, metav1.DeleteOptions{})
	}
}

func (c *cluster) run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		for ctx.Err() == nil {
			c.step(ctx)
			time.Sleep(time.Millisecond)
		}
	}()
	td := &Teardown{
		Kube:             c.k,
		ScalerDeployment: "sg-runner-scaler",
		ScalerSelector:   "app.kubernetes.io/component=scaler",
		RunnerSelector:   "app.kubernetes.io/component=runner",
		Poll:             time.Millisecond,
		Log:              slog.New(slog.NewJSONHandler(c.logs, nil)),
	}
	return td.Run(ctx)
}

func (c *cluster) claims() []string {
	list, err := c.k.Client.CoreV1().PersistentVolumeClaims(ns).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		c.t.Fatal(err)
	}
	var names []string
	for _, p := range list.Items {
		names = append(names, p.Name)
	}
	slices.Sort(names)
	return names
}

func workloads() []runtime.Object {
	return []runtime.Object{
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "sg-runner-scaler", Namespace: ns},
			Spec: appsv1.DeploymentSpec{Replicas: ptr.To[int32](1)}},
		&appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: "sg-runner", Namespace: ns},
			Spec: appsv1.StatefulSetSpec{Replicas: ptr.To[int32](2)}},
		pod("sg-runner-scaler-abc", "scaler"),
		pod("sg-runner-0", "runner"),
		pod("sg-runner-1", "runner"),
	}
}

func TestTeardownDeregistersEveryRunnerAndDeletesPVCs(t *testing.T) {
	objs := append(workloads(),
		// Awake runners 0 and 1, parked runner 3, an orphaned Docker cache 5,
		// and a PVC of another release that must stay.
		pvc("state-sg-runner-0"), pvc("docker-sg-runner-0"),
		pvc("state-sg-runner-1"), pvc("docker-sg-runner-1"),
		pvc("state-sg-runner-3"), pvc("docker-sg-runner-3"),
		pvc("docker-sg-runner-5"),
		pvc("state-other-0"),
		// A failed reap the scaler left behind: must not count as this run's.
		&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "sg-runner-reap-3", Namespace: ns,
			Labels: map[string]string{"app": "sg-runner-reaper"}}, Status: batchv1.JobStatus{Failed: 1}},
	)
	c := newCluster(t, nil, objs...)
	if err := c.run(); err != nil {
		t.Fatalf("Run: %v\n%s", err, c.logs)
	}
	if got, want := c.claims(), []string{"state-other-0"}; !slices.Equal(got, want) {
		t.Errorf("PVCs left = %v, want %v", got, want)
	}
	jobs, _ := c.k.Client.BatchV1().Jobs(ns).List(context.Background(), metav1.ListOptions{})
	if len(jobs.Items) != 0 {
		t.Errorf("%d reap Jobs left, want 0", len(jobs.Items))
	}
	if !strings.Contains(c.logs.String(), `"teardown complete"`) {
		t.Errorf("no completion log:\n%s", c.logs)
	}
}

func TestTeardownKeepsPVCsOfRunnersItCouldNotDeregister(t *testing.T) {
	objs := append(workloads(),
		pvc("state-sg-runner-0"), pvc("docker-sg-runner-0"),
		pvc("state-sg-runner-1"), pvc("docker-sg-runner-1"),
	)
	c := newCluster(t, []string{"sg-runner-reap-1"}, objs...)
	err := c.run()
	if err == nil || !strings.Contains(err.Error(), "could not deregister runners [1]") {
		t.Fatalf("Run error = %v, want one naming runner 1", err)
	}
	if got, want := c.claims(), []string{"docker-sg-runner-1", "state-sg-runner-1"}; !slices.Equal(got, want) {
		t.Errorf("PVCs left = %v, want %v", got, want)
	}
	// The failed Job stays for its logs.
	if _, err := c.k.Client.BatchV1().Jobs(ns).Get(context.Background(), "sg-runner-reap-1", metav1.GetOptions{}); err != nil {
		t.Errorf("failed reap Job deleted: %v", err)
	}
}

func TestTeardownWithoutScalerOrRunners(t *testing.T) {
	// Scaler disabled and the StatefulSet already gone: nothing to do, no error.
	c := newCluster(t, nil, pvc("docker-sg-runner-2"))
	ctx := context.Background()
	td := &Teardown{Kube: c.k, RunnerSelector: "app.kubernetes.io/component=runner", Poll: time.Millisecond,
		Log: slog.New(slog.NewJSONHandler(c.logs, nil))}
	if err := td.Run(ctx); err != nil {
		t.Fatalf("Run: %v\n%s", err, c.logs)
	}
	if got := c.claims(); len(got) != 0 {
		t.Errorf("PVCs left = %v, want none", got)
	}
}

func TestTeardownStopsOnCancel(t *testing.T) {
	// A runner that never stops (a workflow still running) blocks until the
	// context ends: the Job's deadline, not a hang.
	c := newCluster(t, nil, pod("sg-runner-0", "runner"))
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	td := &Teardown{Kube: c.k, RunnerSelector: "app.kubernetes.io/component=runner", Poll: time.Millisecond,
		Log: slog.New(slog.NewJSONHandler(c.logs, nil))}
	if err := td.Run(ctx); err == nil {
		t.Fatal("Run returned nil with a runner pod that never stops")
	}
}

package kube

import (
	"context"
	"reflect"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"

	"github.com/StackGuardian/sg-runner/k8s/scaler/internal/decide"
)

const ns = "sg"

func pvc(name string, ann map[string]string) *corev1.PersistentVolumeClaim {
	return &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Annotations: ann}}
}

func newKube(objs ...runtime.Object) *Kube {
	return New(fake.NewClientset(objs...), ns, "sg-runner", "img:1", "creds")
}

func TestClaims(t *testing.T) {
	k := newKube(
		pvc("state-sg-runner-0", nil),
		pvc("state-sg-runner-1", map[string]string{AnnotationParkedAt: "1700000000", AnnotationDrainedByScaler: "1700000001"}),
		pvc("state-sg-runner-2", map[string]string{AnnotationParkedAt: "garbage"}),
		pvc("docker-sg-runner-1", nil),
		pvc("state-sg-runner-other-3", nil),
		pvc("state-sg-runner-x", nil),
	)
	got, err := k.Claims(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]decide.Claim{
		0: {Name: "state-sg-runner-0"},
		1: {Name: "state-sg-runner-1", Stamped: true, ParkedAt: time.Unix(1700000000, 0), DrainedByScaler: true},
		2: {Name: "state-sg-runner-2", Stamped: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Claims =\n%+v\nwant\n%+v", got, want)
	}
}

func TestAnnotateClaim(t *testing.T) {
	k := newKube(pvc("state-sg-runner-1", map[string]string{"keep": "me", AnnotationParkedAt: "1"}))
	ctx := context.Background()
	v := "42"
	if err := k.AnnotateClaim(ctx, "state-sg-runner-1", map[string]*string{AnnotationDrainedByScaler: &v, AnnotationParkedAt: nil}); err != nil {
		t.Fatal(err)
	}
	p, _ := k.Client.CoreV1().PersistentVolumeClaims(ns).Get(ctx, "state-sg-runner-1", metav1.GetOptions{})
	if want := map[string]string{"keep": "me", AnnotationDrainedByScaler: "42"}; !reflect.DeepEqual(p.Annotations, want) {
		t.Errorf("annotations = %v, want %v", p.Annotations, want)
	}
}

func TestScaleAndAnnotateStatefulSet(t *testing.T) {
	k := newKube(&appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: "sg-runner", Namespace: ns, Annotations: map[string]string{"helm": "x"}},
		Spec:       appsv1.StatefulSetSpec{Replicas: ptr.To[int32](1)},
	})
	ctx := context.Background()
	if err := k.Scale(ctx, 3); err != nil {
		t.Fatal(err)
	}
	v := `{"2":1}`
	if err := k.AnnotateStatefulSet(ctx, map[string]*string{decide.AnnotationIdleSince: &v, decide.AnnotationStuckSince: nil}); err != nil {
		t.Fatal(err)
	}
	s, err := k.GetStatefulSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if Replicas(s) != 3 || s.Annotations["helm"] != "x" || s.Annotations[decide.AnnotationIdleSince] != v {
		t.Errorf("statefulset = replicas %d annotations %v", Replicas(s), s.Annotations)
	}
	if Replicas(&appsv1.StatefulSet{}) != 1 {
		t.Error("unset replicas should default to 1")
	}
}

func TestReapJobSpec(t *testing.T) {
	k := New(nil, ns, "sg-runner", "img:1", "creds")
	j := k.ReapJob(4)
	if j.Name != "sg-runner-reap-4" || j.Labels["app"] != "sg-runner-reaper" {
		t.Errorf("metadata %+v", j.ObjectMeta)
	}
	if *j.Spec.BackoffLimit != 0 || *j.Spec.TTLSecondsAfterFinished != ReapJobTTL {
		t.Error("backoffLimit/ttl")
	}
	ps := j.Spec.Template.Spec
	if ps.RestartPolicy != corev1.RestartPolicyNever || *ps.AutomountServiceAccountToken {
		t.Error("restart policy / token automount")
	}
	c := ps.Containers[0]
	if c.Image != "img:1" || !reflect.DeepEqual(c.Args, []string{"reap"}) || c.ImagePullPolicy != corev1.PullIfNotPresent {
		t.Errorf("container %+v", c)
	}
	wantMounts := []corev1.VolumeMount{
		{Name: "state", MountPath: "/etc/ecs", SubPath: "ecs-config"},
		{Name: "state", MountPath: "/var/lib/ecs/data", SubPath: "ecs-data"},
		{Name: "state", MountPath: "/var/lib/amazon/ssm", SubPath: "ssm"},
		{Name: "sg-credentials", MountPath: "/etc/sg-runner/credentials", ReadOnly: true},
	}
	if !reflect.DeepEqual(c.VolumeMounts, wantMounts) {
		t.Errorf("mounts %+v", c.VolumeMounts)
	}
	if ps.Volumes[0].PersistentVolumeClaim.ClaimName != "state-sg-runner-4" ||
		ps.Volumes[1].Secret.SecretName != "creds" || *ps.Volumes[1].Secret.DefaultMode != 0o400 {
		t.Errorf("volumes %+v", ps.Volumes)
	}
}

func TestReapJobLifecycle(t *testing.T) {
	k := newKube(
		&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "sg-runner-reap-5", Namespace: ns, Labels: map[string]string{"app": "sg-runner-reaper"}},
			Status: batchv1.JobStatus{Succeeded: 1}},
		&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "sg-runner-reap-6", Namespace: ns, Labels: map[string]string{"app": "sg-runner-reaper"}},
			Status: batchv1.JobStatus{Failed: 1}},
		&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: ns, Labels: map[string]string{"app": "sg-runner-reaper"}}},
		&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Name: "sg-runner-reap-9", Namespace: ns}},
	)
	ctx := context.Background()
	if err := k.CreateReapJob(ctx, 3); err != nil {
		t.Fatal(err)
	}
	if err := k.CreateReapJob(ctx, 3); err != nil {
		t.Fatalf("existing job should be fine: %v", err)
	}
	got, err := k.ReapJobs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[int]decide.JobState{3: decide.JobRunning, 5: decide.JobSucceeded, 6: decide.JobFailed}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ReapJobs = %v, want %v", got, want)
	}
	if err := k.DeleteReapJob(ctx, 5); err != nil {
		t.Fatal(err)
	}
	if err := k.DeleteReapJob(ctx, 5); err != nil {
		t.Fatalf("missing job should be fine: %v", err)
	}
	if err := k.DeleteClaim(ctx, "nope"); err != nil {
		t.Fatalf("missing pvc should be fine: %v", err)
	}
}

func TestReapJobPodOptions(t *testing.T) {
	k := New(nil, ns, "sg-runner", "img:1", "creds")
	k.ReapPod = ReapPodOptions{
		Labels:           map[string]string{"np": "egress", "app": "hijack"},
		ImagePullSecrets: []string{"regcred"},
		NodeSelector:     map[string]string{"kubernetes.io/os": "linux"},
		Tolerations:      []corev1.Toleration{{Key: "dedicated", Operator: corev1.TolerationOpExists}},
	}
	j := k.ReapJob(1)
	ps := j.Spec.Template.Spec
	for _, l := range []map[string]string{j.Labels, j.Spec.Template.Labels} {
		if l["np"] != "egress" || l["app"] != "sg-runner-reaper" {
			t.Errorf("labels %v", l)
		}
	}
	if len(ps.ImagePullSecrets) != 1 || ps.ImagePullSecrets[0].Name != "regcred" ||
		ps.NodeSelector["kubernetes.io/os"] != "linux" || len(ps.Tolerations) != 1 {
		t.Errorf("pod spec %+v", ps)
	}
	if len(k.ReapPod.Labels) != 2 || k.ReapPod.Labels["app"] != "hijack" {
		t.Error("ReapJob modified the options")
	}
}

// The Job as the API server stores it, with the chart's labels.
func TestCreateReapJobWithChartOptions(t *testing.T) {
	k := newKube()
	k.ReapPod = ReapPodOptions{
		Labels: map[string]string{"app.kubernetes.io/name": "sg-runner", "app.kubernetes.io/instance": "x",
			"app.kubernetes.io/component": "reaper"},
		ImagePullSecrets: []string{"regcred"},
		NodeSelector:     map[string]string{"kubernetes.io/arch": "arm64"},
		Tolerations:      []corev1.Toleration{{Key: "dedicated", Operator: corev1.TolerationOpEqual, Value: "runners", Effect: corev1.TaintEffectNoSchedule}},
	}
	ctx := context.Background()
	if err := k.CreateReapJob(ctx, 2); err != nil {
		t.Fatal(err)
	}
	j, err := k.Client.BatchV1().Jobs(ns).Get(ctx, "sg-runner-reap-2", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"app": "sg-runner-reaper", "app.kubernetes.io/name": "sg-runner",
		"app.kubernetes.io/instance": "x", "app.kubernetes.io/component": "reaper"}
	if !reflect.DeepEqual(j.Labels, want) || !reflect.DeepEqual(j.Spec.Template.Labels, want) {
		t.Errorf("labels job=%v pod=%v", j.Labels, j.Spec.Template.Labels)
	}
	ps := j.Spec.Template.Spec
	if !reflect.DeepEqual(ps.ImagePullSecrets, []corev1.LocalObjectReference{{Name: "regcred"}}) ||
		ps.NodeSelector["kubernetes.io/arch"] != "arm64" || !reflect.DeepEqual(ps.Tolerations, k.ReapPod.Tolerations) {
		t.Errorf("pod spec %+v", ps)
	}
	// Still found by the scaler's label selector.
	if jobs, err := k.ReapJobs(ctx); err != nil || jobs[2] != decide.JobRunning {
		t.Errorf("ReapJobs = %v, %v", jobs, err)
	}
}

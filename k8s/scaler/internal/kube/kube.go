// Package kube is the scaler's Kubernetes side: the runner StatefulSet, its
// state PVCs and the reap Jobs.
package kube

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"

	"github.com/StackGuardian/sg-runner/k8s/scaler/internal/decide"
)

// Annotations on a runner's state PVC.
const (
	// AnnotationParkedAt is when the runner was first seen parked (epoch).
	AnnotationParkedAt = "sg-runner.stackguardian.io/parked-at"
	// AnnotationDrainedByScaler marks a drain the scaler did (epoch), so it
	// undoes only its own drains on wake.
	AnnotationDrainedByScaler = "sg-runner.stackguardian.io/drained-by-scaler"
)

// ReapJobTTL deletes finished reap Jobs the scaler didn't get to.
const ReapJobTTL int32 = 24 * 3600

// ReapPodOptions are extra settings for reap Jobs, so a chart's
// NetworkPolicy, pull secrets and scheduling cover them.
type ReapPodOptions struct {
	// Labels go on the Job and its pod, next to app: <sts>-reaper (which wins).
	Labels           map[string]string
	ImagePullSecrets []string
	NodeSelector     map[string]string
	Tolerations      []corev1.Toleration
}

// Kube talks to the API server for one runner StatefulSet.
type Kube struct {
	Client      kubernetes.Interface
	Namespace   string
	StatefulSet string
	// Image is the runner image reap Jobs run.
	Image string
	// CredentialsSecret holds the runner group's node token (key
	// SG_NODE_TOKEN).
	CredentialsSecret string
	// ConfigMap holds the runner group (SG_ORGANIZATION, SG_RUNNER_GROUP,
	// SG_BASE_API).
	ConfigMap string
	// ReapPod customizes reap Jobs (and placeholder Jobs' pull secrets).
	ReapPod ReapPodOptions
	// NudgeImage is the placeholder Jobs' image (DefaultNudgeImage when empty).
	NudgeImage string

	claimRE  *regexp.Regexp
	dockerRE *regexp.Regexp
	jobRE    *regexp.Regexp
}

// New returns the adapter for one StatefulSet.
func New(c kubernetes.Interface, namespace, statefulSet, image, secret, configMap string) *Kube {
	q := regexp.QuoteMeta(statefulSet)
	return &Kube{
		Client: c, Namespace: namespace, StatefulSet: statefulSet, Image: image,
		CredentialsSecret: secret, ConfigMap: configMap,
		claimRE:  regexp.MustCompile(`^state-` + q + `-(\d+)$`),
		dockerRE: regexp.MustCompile(`^docker-` + q + `-(\d+)$`),
		jobRE:    regexp.MustCompile(`^` + q + `-reap-(\d+)$`),
	}
}

// ClaimName is the state PVC of an ordinal.
func (k *Kube) ClaimName(n int) string { return fmt.Sprintf("state-%s-%d", k.StatefulSet, n) }

// DockerClaimName is the Docker cache PVC of an ordinal.
func (k *Kube) DockerClaimName(n int) string { return fmt.Sprintf("docker-%s-%d", k.StatefulSet, n) }

// JobName is the reap Job of an ordinal.
func (k *Kube) JobName(n int) string { return fmt.Sprintf("%s-reap-%d", k.StatefulSet, n) }

// GetStatefulSet reads the runner StatefulSet.
func (k *Kube) GetStatefulSet(ctx context.Context) (*appsv1.StatefulSet, error) {
	return k.Client.AppsV1().StatefulSets(k.Namespace).Get(ctx, k.StatefulSet, metav1.GetOptions{})
}

// Replicas is a StatefulSet's spec.replicas (1 when unset, as the API defaults).
func Replicas(s *appsv1.StatefulSet) int {
	if s.Spec.Replicas == nil {
		return 1
	}
	return int(*s.Spec.Replicas)
}

// Scale sets replicas through the scale subresource.
func (k *Kube) Scale(ctx context.Context, replicas int) error {
	body := fmt.Sprintf(`{"spec":{"replicas":%d}}`, replicas)
	_, err := k.Client.AppsV1().StatefulSets(k.Namespace).Patch(ctx, k.StatefulSet,
		types.MergePatchType, []byte(body), metav1.PatchOptions{}, "scale")
	return err
}

func annotationsPatch(a map[string]*string) ([]byte, error) {
	return json.Marshal(map[string]any{"metadata": map[string]any{"annotations": a}})
}

// AnnotateStatefulSet merges annotations into the StatefulSet's metadata;
// nil values remove them.
func (k *Kube) AnnotateStatefulSet(ctx context.Context, a map[string]*string) error {
	body, err := annotationsPatch(a)
	if err != nil {
		return err
	}
	_, err = k.Client.AppsV1().StatefulSets(k.Namespace).Patch(ctx, k.StatefulSet,
		types.MergePatchType, body, metav1.PatchOptions{})
	return err
}

// AnnotateClaim merges annotations into a PVC; nil values remove them.
func (k *Kube) AnnotateClaim(ctx context.Context, name string, a map[string]*string) error {
	body, err := annotationsPatch(a)
	if err != nil {
		return err
	}
	_, err = k.Client.CoreV1().PersistentVolumeClaims(k.Namespace).Patch(ctx, name,
		types.MergePatchType, body, metav1.PatchOptions{})
	return err
}

// Claims lists the state PVCs by ordinal.
func (k *Kube) Claims(ctx context.Context) (map[int]decide.Claim, error) {
	list, err := k.Client.CoreV1().PersistentVolumeClaims(k.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	out := map[int]decide.Claim{}
	for _, p := range list.Items {
		m := k.claimRE.FindStringSubmatch(p.Name)
		if m == nil || p.DeletionTimestamp != nil {
			continue
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		c := decide.Claim{Name: p.Name}
		if v, ok := p.Annotations[AnnotationParkedAt]; ok {
			c.Stamped = true
			if at, err := strconv.ParseInt(v, 10, 64); err == nil && at > 0 {
				c.ParkedAt = time.Unix(at, 0)
			}
		}
		_, c.DrainedByScaler = p.Annotations[AnnotationDrainedByScaler]
		out[n] = c
	}
	return out, nil
}

// DockerClaims lists the ordinals that have a Docker cache PVC.
func (k *Kube) DockerClaims(ctx context.Context) ([]int, error) {
	list, err := k.Client.CoreV1().PersistentVolumeClaims(k.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var out []int
	for _, p := range list.Items {
		m := k.dockerRE.FindStringSubmatch(p.Name)
		if m == nil || p.DeletionTimestamp != nil {
			continue
		}
		if n, err := strconv.Atoi(m[1]); err == nil {
			out = append(out, n)
		}
	}
	return out, nil
}

// ScaleDeployment sets a Deployment's replicas through the scale subresource.
func (k *Kube) ScaleDeployment(ctx context.Context, name string, replicas int) error {
	body := fmt.Sprintf(`{"spec":{"replicas":%d}}`, replicas)
	_, err := k.Client.AppsV1().Deployments(k.Namespace).Patch(ctx, name,
		types.MergePatchType, []byte(body), metav1.PatchOptions{}, "scale")
	return err
}

// CountPods counts the pods matching a label selector.
func (k *Kube) CountPods(ctx context.Context, selector string) (int, error) {
	list, err := k.Client.CoreV1().Pods(k.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return 0, err
	}
	return len(list.Items), nil
}

// ReapJobExists tells whether the reap Job of an ordinal still exists.
func (k *Kube) ReapJobExists(ctx context.Context, n int) (bool, error) {
	_, err := k.Client.BatchV1().Jobs(k.Namespace).Get(ctx, k.JobName(n), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	return err == nil, err
}

// DeleteClaim deletes a PVC; a missing one is fine.
func (k *Kube) DeleteClaim(ctx context.Context, name string) error {
	err := k.Client.CoreV1().PersistentVolumeClaims(k.Namespace).Delete(ctx, name, metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

// ReapJobs lists the reap Jobs by ordinal.
func (k *Kube) ReapJobs(ctx context.Context) (map[int]decide.JobState, error) {
	list, err := k.Client.BatchV1().Jobs(k.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app=" + k.StatefulSet + "-reaper",
	})
	if err != nil {
		return nil, err
	}
	out := map[int]decide.JobState{}
	for _, j := range list.Items {
		m := k.jobRE.FindStringSubmatch(j.Name)
		if m == nil {
			continue
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		switch {
		case j.Status.Succeeded > 0:
			out[n] = decide.JobSucceeded
		case j.Status.Failed > 0:
			out[n] = decide.JobFailed
		default:
			out[n] = decide.JobRunning
		}
	}
	return out, nil
}

// ReapJob is the Job deregistering a parked runner from its state PVC
// (`runner.sh reap`).
func (k *Kube) ReapJob(n int) *batchv1.Job {
	labels := map[string]string{}
	for key, v := range k.ReapPod.Labels {
		labels[key] = v
	}
	labels["app"] = k.StatefulSet + "-reaper"
	var pullSecrets []corev1.LocalObjectReference
	for _, name := range k.ReapPod.ImagePullSecrets {
		pullSecrets = append(pullSecrets, corev1.LocalObjectReference{Name: name})
	}
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: k.JobName(n), Namespace: k.Namespace, Labels: labels},
		Spec: batchv1.JobSpec{
			BackoffLimit:            ptr.To[int32](0),
			TTLSecondsAfterFinished: ptr.To(ReapJobTTL),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					RestartPolicy:                corev1.RestartPolicyNever,
					AutomountServiceAccountToken: ptr.To(false),
					ImagePullSecrets:             pullSecrets,
					NodeSelector:                 k.ReapPod.NodeSelector,
					Tolerations:                  k.ReapPod.Tolerations,
					Containers: []corev1.Container{{
						Name: "reap", Image: k.Image, ImagePullPolicy: corev1.PullIfNotPresent,
						Args: []string{"reap"},
						VolumeMounts: []corev1.VolumeMount{
							{Name: "state", MountPath: "/etc/ecs", SubPath: "ecs-config"},
							{Name: "state", MountPath: "/var/lib/ecs/data", SubPath: "ecs-data"},
							{Name: "state", MountPath: "/var/lib/amazon/ssm", SubPath: "ssm"},
							{Name: "sg-credentials", MountPath: "/etc/sg-runner/credentials", ReadOnly: true},
						},
					}},
					Volumes: []corev1.Volume{
						{Name: "state", VolumeSource: corev1.VolumeSource{
							PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: k.ClaimName(n)}}},
						// The node token and the runner group as files in one
						// directory, as runner.sh reads them.
						{Name: "sg-credentials", VolumeSource: corev1.VolumeSource{
							Projected: &corev1.ProjectedVolumeSource{
								DefaultMode: ptr.To[int32](0o400),
								Sources: []corev1.VolumeProjection{
									{Secret: &corev1.SecretProjection{
										LocalObjectReference: corev1.LocalObjectReference{Name: k.CredentialsSecret},
										Items:                []corev1.KeyToPath{{Key: "SG_NODE_TOKEN", Path: "SG_NODE_TOKEN"}},
									}},
									{ConfigMap: &corev1.ConfigMapProjection{
										LocalObjectReference: corev1.LocalObjectReference{Name: k.ConfigMap},
									}},
								},
							}}},
					},
				},
			},
		},
	}
}

// CreateReapJob starts the reap Job of an ordinal; an existing one is fine.
func (k *Kube) CreateReapJob(ctx context.Context, n int) error {
	_, err := k.Client.BatchV1().Jobs(k.Namespace).Create(ctx, k.ReapJob(n), metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

// DeleteReapJob deletes the reap Job of an ordinal and its pod.
func (k *Kube) DeleteReapJob(ctx context.Context, n int) error {
	err := k.Client.BatchV1().Jobs(k.Namespace).Delete(ctx, k.JobName(n), metav1.DeleteOptions{
		PropagationPolicy: ptr.To(metav1.DeletePropagationBackground),
	})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

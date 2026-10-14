package kube

// Nudging the cluster autoscaler. Some autoscalers (GKE's, at least) never
// add a node for a pod with a persistent disk: the template node they
// simulate lacks the disk driver's zone label, so a runner with its PVCs
// stays Pending ("NotTriggerScaleUp ... didn't match Pod's node
// affinity/selector") while the same pod without volumes would scale up. A
// nudge is a placeholder Job with the runner pod's requests and scheduling
// rules but no volumes: the autoscaler adds a node for it, and once it runs,
// deleting it leaves that node to the runner.

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/utils/ptr"
)

// DefaultNudgeImage is the placeholder's image: it only has to sleep.
const DefaultNudgeImage = "registry.k8s.io/pause:3.10"

// NudgeDeadline bounds a placeholder that never gets a node (e.g. the node
// pool's maximum is reached).
const NudgeDeadline int64 = 15 * 60

// NudgeState is a placeholder Job's progress.
type NudgeState int

// Placeholder progress.
const (
	// NudgeWaiting: created, its pod not running yet (a node is coming).
	NudgeWaiting NudgeState = iota
	// NudgeRunning: its pod runs, so the node is there.
	NudgeRunning
	// NudgeFailed: past its deadline without a node.
	NudgeFailed
)

func (k *Kube) nudgeApp() string { return k.StatefulSet + "-nudge" }

// NudgeJobName is the placeholder Job of an ordinal.
func (k *Kube) NudgeJobName(n int) string { return fmt.Sprintf("%s-nudge-%d", k.StatefulSet, n) }

// RunnerPods lists the runner StatefulSet's pods by ordinal.
func (k *Kube) RunnerPods(ctx context.Context, selector string) (map[int]*corev1.Pod, error) {
	list, err := k.Client.CoreV1().Pods(k.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(`^` + regexp.QuoteMeta(k.StatefulSet) + `-(\d+)$`)
	out := map[int]*corev1.Pod{}
	for i := range list.Items {
		p := &list.Items[i]
		m := re.FindStringSubmatch(p.Name)
		if m == nil {
			continue
		}
		if n, err := strconv.Atoi(m[1]); err == nil {
			out[n] = p
		}
	}
	return out, nil
}

// Unschedulable reports a pod the scheduler can't place on any node.
func Unschedulable(p *corev1.Pod) bool {
	if p.Spec.NodeName != "" || p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodPending {
		return false
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodScheduled && c.Status == corev1.ConditionFalse && c.Reason == corev1.PodReasonUnschedulable {
			return true
		}
	}
	return false
}

// Cluster autoscaler event reasons on a pending pod.
const (
	// EventScaleUpRefused: no node group can host the pod.
	EventScaleUpRefused = "NotTriggerScaleUp"
	// EventScaleUpTriggered: a node group is being resized for it.
	EventScaleUpTriggered = "TriggeredScaleUp"
)

// podEvents lists a reason's events on pods; the field selector is checked
// again here (fake clients ignore it).
func (k *Kube) podEvents(ctx context.Context, reason string, match func(corev1.ObjectReference) bool) ([]corev1.Event, error) {
	sel := fields.Set{"involvedObject.kind": "Pod", "reason": reason}.AsSelector().String()
	list, err := k.Client.CoreV1().Events(k.Namespace).List(ctx, metav1.ListOptions{FieldSelector: sel})
	if err != nil {
		return nil, err
	}
	var out []corev1.Event
	for _, e := range list.Items {
		if e.InvolvedObject.Kind == "Pod" && e.Reason == reason && match(e.InvolvedObject) {
			out = append(out, e)
		}
	}
	return out, nil
}

// ScaleUpRefused reports whether the cluster autoscaler said it won't add a
// node for this pod (event NotTriggerScaleUp).
func (k *Kube) ScaleUpRefused(ctx context.Context, p *corev1.Pod) (bool, error) {
	ev, err := k.podEvents(ctx, EventScaleUpRefused, func(o corev1.ObjectReference) bool {
		return o.Name == p.Name && (o.UID == "" || o.UID == p.UID)
	})
	return len(ev) > 0, err
}

// NudgeOutcome is what the cluster autoscaler said about an ordinal's
// current placeholder pod (events since the Job's creation; earlier ones
// belong to earlier placeholders): the event reason (EventScaleUpTriggered or
// EventScaleUpRefused) and its message, or empty while it hasn't decided.
func (k *Kube) NudgeOutcome(ctx context.Context, n int, since time.Time) (reason, message string, err error) {
	prefix := k.NudgeJobName(n) + "-"
	since = since.Truncate(time.Second)
	isPlaceholder := func(o corev1.ObjectReference) bool { return strings.HasPrefix(o.Name, prefix) }
	// A triggered scale-up wins: the node is coming even if the autoscaler
	// also refused once (e.g. while another scale-up was in flight).
	for _, r := range []string{EventScaleUpTriggered, EventScaleUpRefused} {
		ev, err := k.podEvents(ctx, r, isPlaceholder)
		if err != nil {
			return "", "", err
		}
		for _, e := range ev {
			if !eventTime(e).Before(since) {
				return r, e.Message, nil
			}
		}
	}
	return "", "", nil
}

// eventTime is when an event last happened.
func eventTime(e corev1.Event) time.Time {
	switch {
	case !e.LastTimestamp.IsZero():
		return e.LastTimestamp.Time
	case !e.EventTime.IsZero():
		return e.EventTime.Time
	default:
		return e.FirstTimestamp.Time
	}
}

// Nudge is a placeholder Job: its progress and when it was created.
type Nudge struct {
	State   NudgeState
	Created time.Time
}

// NudgeJobs lists the placeholder Jobs by ordinal.
func (k *Kube) NudgeJobs(ctx context.Context) (map[int]Nudge, error) {
	list, err := k.Client.BatchV1().Jobs(k.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "app=" + k.nudgeApp()})
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(`^` + regexp.QuoteMeta(k.StatefulSet) + `-nudge-(\d+)$`)
	out := map[int]Nudge{}
	for _, j := range list.Items {
		m := re.FindStringSubmatch(j.Name)
		if m == nil || j.DeletionTimestamp != nil {
			continue
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		nj := Nudge{State: NudgeWaiting, Created: j.CreationTimestamp.Time}
		switch {
		case j.Status.Failed > 0:
			nj.State = NudgeFailed
		case j.Status.Ready != nil && *j.Status.Ready > 0:
			nj.State = NudgeRunning
		}
		out[n] = nj
	}
	return out, nil
}

// PodRequests is what the scheduler reserves for a pod: the containers'
// requests summed, or an init container's if larger.
func PodRequests(p *corev1.Pod) corev1.ResourceList {
	out := corev1.ResourceList{}
	for _, c := range p.Spec.Containers {
		for name, q := range c.Resources.Requests {
			sum := out[name]
			sum.Add(q)
			out[name] = sum
		}
	}
	for _, c := range p.Spec.InitContainers {
		for name, q := range c.Resources.Requests {
			if cur, ok := out[name]; !ok || q.Cmp(cur) > 0 {
				out[name] = q.DeepCopy()
			}
		}
	}
	return out
}

// NudgeJob is the placeholder for a runner pod: its requests, node
// selection, tolerations and affinity (so it asks for the same kind of node),
// no volumes.
func (k *Kube) NudgeJob(n int, runner *corev1.Pod) *batchv1.Job {
	labels := map[string]string{"app": k.nudgeApp()}
	var pullSecrets []corev1.LocalObjectReference
	for _, name := range k.ReapPod.ImagePullSecrets {
		pullSecrets = append(pullSecrets, corev1.LocalObjectReference{Name: name})
	}
	image := k.NudgeImage
	if image == "" {
		image = DefaultNudgeImage
	}
	requests := PodRequests(runner)
	// Nothing to reserve otherwise, and the pause container needs no more.
	if len(requests) == 0 {
		requests = corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1m")}
	}
	return &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: k.NudgeJobName(n), Namespace: k.Namespace, Labels: labels},
		Spec: batchv1.JobSpec{
			BackoffLimit:            ptr.To[int32](0),
			ActiveDeadlineSeconds:   ptr.To(NudgeDeadline),
			TTLSecondsAfterFinished: ptr.To[int32](600),
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					RestartPolicy:                 corev1.RestartPolicyNever,
					AutomountServiceAccountToken:  ptr.To(false),
					TerminationGracePeriodSeconds: ptr.To[int64](0),
					ImagePullSecrets:              pullSecrets,
					NodeSelector:                  runner.Spec.NodeSelector,
					Tolerations:                   runner.Spec.Tolerations,
					Affinity:                      runner.Spec.Affinity,
					PriorityClassName:             runner.Spec.PriorityClassName,
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot:   ptr.To(true),
						RunAsUser:      ptr.To[int64](65535),
						SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
					},
					Containers: []corev1.Container{{
						Name: "placeholder", Image: image, ImagePullPolicy: corev1.PullIfNotPresent,
						Resources: corev1.ResourceRequirements{Requests: requests},
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: ptr.To(false),
							ReadOnlyRootFilesystem:   ptr.To(true),
							Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						},
					}},
				},
			},
		},
	}
}

// CreateNudgeJob starts the placeholder for a runner pod; an existing one is
// fine.
func (k *Kube) CreateNudgeJob(ctx context.Context, n int, runner *corev1.Pod) error {
	_, err := k.Client.BatchV1().Jobs(k.Namespace).Create(ctx, k.NudgeJob(n, runner), metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

// DeleteNudgeJob deletes a placeholder Job and its pod; a missing one is fine.
func (k *Kube) DeleteNudgeJob(ctx context.Context, n int) error {
	err := k.Client.BatchV1().Jobs(k.Namespace).Delete(ctx, k.NudgeJobName(n), metav1.DeleteOptions{
		PropagationPolicy: ptr.To(metav1.DeletePropagationBackground),
	})
	if apierrors.IsNotFound(err) {
		return nil
	}
	return err
}

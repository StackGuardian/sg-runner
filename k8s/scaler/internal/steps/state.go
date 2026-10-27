package steps

import (
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// Step states.
const (
	StatePending = "pending"
	StateRunning = "running"
	StateExited  = "exited"
	StateFailed  = "failed"
)

// Reasons of failed steps (and of stopped ones whose pod is gone).
const (
	FailedUnschedulable     = "Unschedulable"
	FailedImagePullBackOff  = "ImagePullBackOff"
	FailedErrImagePull      = "ErrImagePull"
	FailedInvalidImageName  = "InvalidImageName"
	FailedErrImageNeverPull = "ErrImageNeverPull"
	FailedStartTimeout      = "StartTimeout"
	FailedEvicted           = "Evicted"
	FailedDeadlineExceeded  = "DeadlineExceeded"
	FailedPodDeleted        = "PodDeleted"
	// ReasonStopped is the reason of a stopped step the broker never saw exit.
	ReasonStopped = "Stopped"
)

// StoppedExitCode is a stopped step's exit code when the broker never saw
// its own (Docker's for a killed container).
const StoppedExitCode int32 = 137

// State is GET /v1/steps/{id}.
type State struct {
	ID         string     `json:"id"`
	State      string     `json:"state"`
	ExitCode   *int32     `json:"exitCode"`
	Reason     string     `json:"reason"`
	Message    string     `json:"message"`
	StartedAt  *time.Time `json:"startedAt"`
	FinishedAt *time.Time `json:"finishedAt"`
}

// Terminal reports a state that won't change.
func (s State) Terminal() bool { return s.State == StateExited || s.State == StateFailed }

// stoppedState is a stopped step's state after its pod is gone.
func stoppedState(id string, last *State) State {
	if last != nil && last.State == StateExited {
		return *last
	}
	code := StoppedExitCode
	return State{ID: id, State: StateExited, ExitCode: &code, Reason: ReasonStopped, Message: "stopped"}
}

// ErrImagePull messages that won't get better with retries; any other pull
// error stays pending until the kubelet backs off.
var permanentPullErrors = []string{"not found", "manifest unknown", "unauthorized", "authentication required", "denied", "forbidden"}

// StepState is what a step pod says about the step at now. stopped tells
// whether the broker was asked to stop it.
func (c *Config) StepState(p *corev1.Pod, now time.Time, stopped bool) State {
	s := State{ID: p.Name}
	var cs *corev1.ContainerStatus
	for i := range p.Status.ContainerStatuses {
		if p.Status.ContainerStatuses[i].Name == ContainerName {
			cs = &p.Status.ContainerStatuses[i]
		}
	}
	failed := func(reason, message string) State {
		s.State, s.Reason, s.Message = StateFailed, reason, message
		return s
	}

	// The kubelet killed the pod: whatever the container says, the step was
	// cut short.
	if p.Status.Phase == corev1.PodFailed {
		switch p.Status.Reason {
		case FailedEvicted, FailedDeadlineExceeded:
			s.FinishedAt = podFinishedAt(p, cs)
			return failed(p.Status.Reason, p.Status.Message)
		}
	}

	if cs != nil {
		if t := cs.State.Terminated; t != nil {
			code, message := t.ExitCode, t.Message
			if c, ok := wrappedExit(p, t); ok {
				code, message = c, ""
			}
			s.State, s.ExitCode, s.Reason, s.Message = StateExited, &code, t.Reason, message
			s.StartedAt, s.FinishedAt = timePtr(t.StartedAt.Time), timePtr(t.FinishedAt.Time)
			return s
		}
	}

	if p.DeletionTimestamp != nil && !stopped {
		return failed(FailedPodDeleted, "the step's pod was deleted")
	}

	switch p.Status.Phase {
	case corev1.PodFailed, corev1.PodSucceeded:
		// Rejected or shut down by the node without a container status to
		// tell: a container that never ran couldn't be placed there.
		s.FinishedAt = podFinishedAt(p, cs)
		msg := strings.TrimSpace(p.Status.Reason + ": " + p.Status.Message)
		if cs == nil || cs.State.Running == nil && cs.LastTerminationState.Terminated == nil {
			return failed(FailedUnschedulable, msg)
		}
		return failed(FailedEvicted, msg)
	}

	if cs != nil && cs.State.Running != nil {
		s.State = StateRunning
		s.StartedAt = timePtr(cs.State.Running.StartedAt.Time)
		return s
	}

	created := p.CreationTimestamp.Time
	if p.Spec.NodeName == "" {
		for _, cond := range p.Status.Conditions {
			if cond.Type == corev1.PodScheduled && cond.Status == corev1.ConditionFalse &&
				cond.Reason == corev1.PodReasonUnschedulable && now.Sub(created) > c.SchedulingTimeout {
				s.FinishedAt = timePtr(created.Add(c.SchedulingTimeout))
				return failed(FailedUnschedulable, cond.Message)
			}
		}
	}

	var waiting string
	if cs != nil && cs.State.Waiting != nil {
		w := cs.State.Waiting
		waiting = strings.TrimSpace(w.Reason + ": " + w.Message)
		switch w.Reason {
		case FailedImagePullBackOff, FailedInvalidImageName, FailedErrImageNeverPull:
			return failed(w.Reason, w.Message)
		case FailedErrImagePull:
			msg := strings.ToLower(w.Message)
			for _, e := range permanentPullErrors {
				if strings.Contains(msg, e) {
					return failed(w.Reason, w.Message)
				}
			}
		}
	}

	if now.Sub(created) > c.StartTimeout {
		s.FinishedAt = timePtr(created.Add(c.StartTimeout))
		msg := fmt.Sprintf("not started after %s", c.StartTimeout)
		if waiting != "" {
			msg += " (" + waiting + ")"
		}
		return failed(FailedStartTimeout, msg)
	}
	s.State, s.Message = StatePending, waiting
	return s
}

// wrappedExits are the termination messages of the wrapper's mapped exits.
var wrappedExits = map[string]int32{"sg-exit-code=11": 11, "sg-exit-code=12": 12}

// wrappedExit is the step's own exit code when the wrapper mapped it to 0:
// only a wrapped pod's exit 0 with the wrapper's exact message counts.
func wrappedExit(p *corev1.Pod, t *corev1.ContainerStateTerminated) (int32, bool) {
	if p.Annotations[AnnotationWrapped] != "true" || t.ExitCode != 0 {
		return 0, false
	}
	code, ok := wrappedExits[t.Message]
	return code, ok
}

// podFinishedAt is when a pod the kubelet failed stopped: its container's
// end, else its conditions' last change.
func podFinishedAt(p *corev1.Pod, cs *corev1.ContainerStatus) *time.Time {
	if cs != nil && cs.State.Terminated != nil && !cs.State.Terminated.FinishedAt.IsZero() {
		return timePtr(cs.State.Terminated.FinishedAt.Time)
	}
	var last time.Time
	for _, cond := range p.Status.Conditions {
		if cond.LastTransitionTime.After(last) {
			last = cond.LastTransitionTime.Time
		}
	}
	return timePtr(last)
}

// timePtr is t in UTC, nil when zero.
func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	t = t.UTC()
	return &t
}

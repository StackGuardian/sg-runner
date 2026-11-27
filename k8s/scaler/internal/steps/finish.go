package steps

import (
	"context"
	"encoding/json"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Outcome is the outcome label of a terminal state.
func Outcome(st State, stopped bool) string {
	switch {
	case stopped:
		return OutcomeStopped
	case st.State != StateExited || st.ExitCode == nil:
		return OutcomeFailed
	}
	switch *st.ExitCode {
	case 0:
		return OutcomeSucceeded
	case 11:
		return OutcomeApprovalRequired
	case 12:
		return OutcomeCompletedEarly
	}
	return OutcomeFailed
}

// wrap is how a step runs: under the wrapper when the broker's image is known
// and the step image's entrypoint and cmd (or the request's args) are.
func (s *Server) wrap(ctx context.Context, r *Request) Wrap {
	switch {
	case s.Config.BrokerImage == "":
		return Wrap{Reason: "BROKER_IMAGE is not set"}
	case s.Images == nil:
		return Wrap{Reason: "no image config lookup"}
	}
	cfg, err := s.Images.Lookup(ctx, r.Image, r.RegistryAuth)
	if err != nil {
		return Wrap{Reason: lookupError(err)}
	}
	cmd := wrapCommand(cfg, r.Args)
	if cmd == nil {
		return Wrap{Reason: "the image has no entrypoint or cmd, and the step no args"}
	}
	return Wrap{Command: cmd}
}

// terminalLocked records a terminal state the broker saw (the first one
// stays) and claims finishing the step: true makes the caller its only
// finisher. s.mu is held.
func (s *Server) terminalLocked(id string, st State) bool {
	rec := s.recordLocked(id)
	if rec.final == nil {
		rec.final, rec.terminalAt = &st, s.now()
	}
	if rec.finishing || rec.finished {
		return false
	}
	rec.finishing = true
	return true
}

func (s *Server) finishAsync(id string, p *corev1.Pod) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s.finish(ctx, id, p)
}

// finish labels a claimed terminal step's pod with its outcome (once: a
// labeled pod keeps its label) and deletes its Secrets, which hold
// credentials a finished pod doesn't need. p is nil when the pod is gone. A
// failure leaves it to the next GET or sweep.
func (s *Server) finish(ctx context.Context, id string, p *corev1.Pod) {
	s.mu.Lock()
	rec := s.steps[id]
	outcome := Outcome(*rec.final, rec.stopped)
	s.mu.Unlock()

	err := func() error {
		// A pod being deleted takes metadata changes too (a stopped one).
		if p != nil && p.Labels[LabelOutcome] == "" {
			patch, _ := json.Marshal(map[string]any{"metadata": map[string]any{"labels": map[string]string{LabelOutcome: outcome}}})
			_, err := s.Client.CoreV1().Pods(s.Config.Namespace).Patch(ctx, id, types.MergePatchType, patch, metav1.PatchOptions{})
			if err := ignoreNotFound(err); err != nil {
				return kubeError("label Pod "+id, err)
			}
		}
		return s.deleteSecrets(ctx, id)
	}()

	s.mu.Lock()
	rec.finishing = false
	if err == nil {
		rec.finished, rec.secretsDeleted = true, true
	}
	s.mu.Unlock()
	if err != nil {
		s.Log.Warn("finishing a step", "id", id, "err", err)
		return
	}
	s.Log.Info("step finished", "id", id, "outcome", outcome)
}

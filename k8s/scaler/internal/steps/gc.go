package steps

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// selector matches this runner's step pods.
func (c *Config) selector() string {
	return labels.Set{LabelComponent: ComponentStep, LabelRunner: c.RunnerPodName}.String()
}

// Sweep finishes terminal steps no GET saw end (outcome label, Secrets),
// deletes finished step pods FINISHED_TTL after they ended, deletes the
// Secrets of steps whose pod went without the broker, and forgets steps gone
// for an hour. It never lists Secrets (a list returns their data, the node
// token's too): step Secrets go by name with their step, or with the runner
// pod that owns them.
func (s *Server) Sweep(ctx context.Context) error {
	now := s.now()
	pods, err := s.Client.CoreV1().Pods(s.Config.Namespace).List(ctx, metav1.ListOptions{LabelSelector: s.Config.selector()})
	if err != nil {
		return kubeError("list step pods", err)
	}

	live := map[string]bool{}
	for i := range pods.Items {
		p := &pods.Items[i]
		if !s.idRE.MatchString(p.Name) {
			continue
		}
		live[p.Name] = true
		if p.DeletionTimestamp != nil {
			continue
		}
		s.mu.Lock()
		rec := s.steps[p.Name]
		var st State
		if rec != nil && rec.final != nil {
			st = *rec.final
		} else {
			stopped := rec != nil && rec.stopped
			st = s.Config.StepState(p, now, stopped)
			if stopped {
				rec.see(st)
			}
		}
		if !st.Terminal() {
			s.mu.Unlock()
			continue
		}
		finish := s.terminalLocked(p.Name, st)
		ended := s.steps[p.Name].terminalAt
		s.mu.Unlock()
		if finish {
			s.finish(ctx, p.Name, p)
		}

		if st.FinishedAt != nil {
			ended = *st.FinishedAt
		}
		if s.streaming(p.Name) || now.Sub(ended) <= s.Config.FinishedTTL {
			continue
		}
		if err := s.deleteStep(ctx, p.Name); err != nil {
			s.Log.Warn("gc: deleting a finished step", "id", p.Name, "err", err)
			continue
		}
		s.mu.Lock()
		rec = s.steps[p.Name]
		rec.deleted, rec.deletedAt, rec.secretsDeleted = true, now, true
		s.mu.Unlock()
		s.Log.Info("gc: deleted a finished step", "id", p.Name, "state", st.State, "reason", st.Reason)
	}

	// A stop, or someone else, deleted the pod only.
	var gone []string
	s.mu.Lock()
	for id, rec := range s.steps {
		if !live[id] && !rec.secretsDeleted && !rec.finishing {
			gone = append(gone, id)
		}
	}
	s.mu.Unlock()
	for _, id := range gone {
		if err := s.deleteSecrets(ctx, id); err != nil {
			s.Log.Warn("gc: deleting the Secrets of a step without a pod", "id", id, "err", err)
			continue
		}
		s.mu.Lock()
		if rec := s.steps[id]; rec != nil {
			rec.secretsDeleted = true
		}
		s.mu.Unlock()
	}

	s.mu.Lock()
	for id, rec := range s.steps {
		since := rec.at
		if rec.deleted {
			since = rec.deletedAt
		}
		if !live[id] && !rec.finishing && now.Sub(since) > recordTTL {
			delete(s.steps, id)
		}
	}
	s.mu.Unlock()
	return nil
}

// RunGC sweeps every interval until ctx ends.
func (s *Server) RunGC(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := s.Sweep(ctx); err != nil && ctx.Err() == nil {
			s.Log.Warn("gc", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

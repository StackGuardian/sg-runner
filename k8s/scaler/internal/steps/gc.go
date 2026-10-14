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

// finishedAt is when a terminal step ended, for the GC: a failure without a
// time (an image the kubelet can't pull) counts from the start deadline.
func (c *Config) finishedAt(created time.Time, st State) time.Time {
	if st.FinishedAt != nil {
		return *st.FinishedAt
	}
	return created.Add(c.StartTimeout)
}

// Sweep deletes finished steps no client read within FINISHED_TTL (their
// controller is gone), retries deletions of steps a client read, deletes the
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
		stopped := rec != nil && rec.stopped
		served := rec != nil && rec.final != nil
		s.mu.Unlock()
		if served {
			if s.claimDeletion(p.Name) {
				s.deleteFinal(p.Name, "gc retry")
			}
			continue
		}
		st := s.Config.StepState(p, now, stopped)
		if !st.Terminal() || s.streaming(p.Name) ||
			now.Sub(s.Config.finishedAt(p.CreationTimestamp.Time, st)) <= s.Config.FinishedTTL {
			continue
		}
		s.mu.Lock()
		if rec := s.recordLocked(p.Name); rec.final == nil {
			rec.final = &st
		}
		s.mu.Unlock()
		if s.claimDeletion(p.Name) {
			s.deleteFinal(p.Name, "unread after FINISHED_TTL")
		}
	}

	// A stop, or someone else, deleted the pod only.
	var gone []string
	s.mu.Lock()
	for id, rec := range s.steps {
		if !live[id] && !rec.secretsDeleted && !rec.deleting {
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
		if !live[id] && !rec.deleting && now.Sub(since) > recordTTL {
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

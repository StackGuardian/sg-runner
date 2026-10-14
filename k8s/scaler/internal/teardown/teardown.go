// Package teardown removes every runner of a StatefulSet from StackGuardian
// before Helm deletes the release (the chart's pre-delete hook), so
// `helm uninstall` leaves no registered runners and no PVCs behind.
package teardown

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/StackGuardian/sg-runner/k8s/scaler/internal/decide"
	"github.com/StackGuardian/sg-runner/k8s/scaler/internal/kube"
)

// Teardown parks, deregisters and deletes every runner of one StatefulSet.
type Teardown struct {
	Kube *kube.Kube
	// ScalerDeployment is stopped first, so it can't wake, park or reap
	// runners meanwhile. Empty = no scaler.
	ScalerDeployment string
	// ScalerSelector and RunnerSelector select the scaler's and the runners'
	// pods, to wait for them to be gone.
	ScalerSelector string
	RunnerSelector string
	// Poll is how often to check progress (5s when zero).
	Poll time.Duration
	Log  *slog.Logger
}

// Run stops the scaler, parks every runner (each one's preStop drain waits
// for its running workflows), deregisters each runner from its state PVC
// with a reap Job, and deletes the PVCs of every runner it deregistered. A
// runner that fails to deregister keeps its PVCs, and Run returns an error,
// so Helm stops before anything is orphaned.
func (t *Teardown) Run(ctx context.Context) error {
	if t.Poll == 0 {
		t.Poll = 5 * time.Second
	}
	if t.ScalerDeployment != "" {
		t.Log.Info("stopping the scaler", "deployment", t.ScalerDeployment)
		if err := t.Kube.ScaleDeployment(ctx, t.ScalerDeployment, 0); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("stop the scaler: %w", err)
		}
		if err := t.waitNoPods(ctx, t.ScalerSelector, "scaler"); err != nil {
			return err
		}
	}

	t.Log.Info("parking every runner", "statefulset", t.Kube.StatefulSet)
	if err := t.Kube.Scale(ctx, 0); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("park the runners: %w", err)
	}
	if err := t.waitNoPods(ctx, t.RunnerSelector, "runner"); err != nil {
		return err
	}

	claims, err := t.Kube.Claims(ctx)
	if err != nil {
		return fmt.Errorf("list runner PVCs: %w", err)
	}
	ordinals := make([]int, 0, len(claims))
	for n := range claims {
		ordinals = append(ordinals, n)
	}
	slices.Sort(ordinals)
	t.Log.Info("deregistering runners", "ordinals", ordinals)

	// A leftover reap Job (a failed reap by the scaler) would read as this
	// run's result: start every reap afresh.
	for _, n := range ordinals {
		if err := t.deleteReapJob(ctx, n); err != nil {
			return err
		}
	}
	for _, n := range ordinals {
		if err := t.Kube.CreateReapJob(ctx, n); err != nil {
			return fmt.Errorf("start reap Job for runner %d: %w", n, err)
		}
	}
	states, err := t.waitReaps(ctx, ordinals)
	if err != nil {
		return err
	}

	var failed []int
	for _, n := range ordinals {
		if states[n] != decide.JobSucceeded {
			failed = append(failed, n)
			t.Log.Error("could not deregister runner; keeping its PVCs", "ordinal", n, "job", t.Kube.JobName(n))
			continue
		}
		for _, claim := range []string{t.Kube.ClaimName(n), t.Kube.DockerClaimName(n)} {
			if err := t.Kube.DeleteClaim(ctx, claim); err != nil {
				return fmt.Errorf("delete PVC %s: %w", claim, err)
			}
		}
		if err := t.Kube.DeleteReapJob(ctx, n); err != nil {
			return fmt.Errorf("delete reap Job %s: %w", t.Kube.JobName(n), err)
		}
		t.Log.Info("runner deregistered, PVCs deleted", "ordinal", n)
	}

	// Placeholders asking the cluster autoscaler for nodes (the scaler is
	// stopped, nothing needs them).
	nudges, err := t.Kube.NudgeJobs(ctx)
	if err != nil {
		return fmt.Errorf("list placeholder Jobs: %w", err)
	}
	for n := range nudges {
		if err := t.Kube.DeleteNudgeJob(ctx, n); err != nil {
			return fmt.Errorf("delete placeholder Job %s: %w", t.Kube.NudgeJobName(n), err)
		}
	}

	// Docker caches whose runner is gone already (reaped earlier, or its state
	// PVC deleted by hand).
	docker, err := t.Kube.DockerClaims(ctx)
	if err != nil {
		return fmt.Errorf("list Docker cache PVCs: %w", err)
	}
	for _, n := range docker {
		if _, ok := claims[n]; ok {
			continue
		}
		if err := t.Kube.DeleteClaim(ctx, t.Kube.DockerClaimName(n)); err != nil {
			return fmt.Errorf("delete PVC %s: %w", t.Kube.DockerClaimName(n), err)
		}
	}

	if len(failed) > 0 {
		return fmt.Errorf("could not deregister runners %v: see the logs of their %s-reap-<n> Jobs; "+
			"their PVCs are kept so nothing is orphaned", failed, t.Kube.StatefulSet)
	}
	t.Log.Info("teardown complete", "runners", len(ordinals))
	return nil
}

// waitNoPods waits until no pod matches selector. Runners can take as long as
// their running workflows (their preStop drain waits for them).
func (t *Teardown) waitNoPods(ctx context.Context, selector, what string) error {
	var last time.Time
	for {
		n, err := t.Kube.CountPods(ctx, selector)
		if err != nil {
			return fmt.Errorf("list %s pods: %w", what, err)
		}
		if n == 0 {
			return nil
		}
		if time.Since(last) >= time.Minute {
			t.Log.Info("waiting for pods to stop (runners wait for their running workflows)", "component", what, "pods", n)
			last = time.Now()
		}
		if err := t.sleep(ctx); err != nil {
			return err
		}
	}
}

// deleteReapJob deletes the reap Job of an ordinal and waits until it's gone.
func (t *Teardown) deleteReapJob(ctx context.Context, n int) error {
	if err := t.Kube.DeleteReapJob(ctx, n); err != nil {
		return fmt.Errorf("delete old reap Job %s: %w", t.Kube.JobName(n), err)
	}
	for {
		exists, err := t.Kube.ReapJobExists(ctx, n)
		if err != nil {
			return fmt.Errorf("check old reap Job %s: %w", t.Kube.JobName(n), err)
		}
		if !exists {
			return nil
		}
		if err := t.sleep(ctx); err != nil {
			return err
		}
	}
}

// waitReaps waits until every ordinal's reap Job has finished.
func (t *Teardown) waitReaps(ctx context.Context, ordinals []int) (map[int]decide.JobState, error) {
	for {
		jobs, err := t.Kube.ReapJobs(ctx)
		if err != nil {
			return nil, fmt.Errorf("list reap Jobs: %w", err)
		}
		done := true
		for _, n := range ordinals {
			if s, ok := jobs[n]; !ok || s == decide.JobRunning {
				done = false
				break
			}
		}
		if done {
			return jobs, nil
		}
		if err := t.sleep(ctx); err != nil {
			return nil, err
		}
	}
}

func (t *Teardown) sleep(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(t.Poll):
		return nil
	}
}

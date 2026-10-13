// Package controller runs the scaling loop: observe SG and the cluster,
// decide, act, report.
package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"regexp"
	"strconv"
	"sync/atomic"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"

	"github.com/StackGuardian/sg-runner/k8s/scaler/internal/decide"
	"github.com/StackGuardian/sg-runner/k8s/scaler/internal/kube"
	"github.com/StackGuardian/sg-runner/k8s/scaler/internal/metrics"
	"github.com/StackGuardian/sg-runner/k8s/scaler/internal/sg"
)

// SG is the part of the SG API the loop uses.
type SG interface {
	RunnerGroup(ctx context.Context) (*sg.RunnerGroup, error)
	SetRunnerStatus(ctx context.Context, runnerID, status string) error
}

// Defaults for the loop's back-off and event rate limits.
const (
	DefaultMaxBackoff    = 5 * time.Minute
	DefaultFailureEvents = 3
	DefaultWarnEvery     = 10 * time.Minute
)

// Controller is the scaling loop for one runner StatefulSet.
type Controller struct {
	Config   decide.Config
	Interval time.Duration
	SG       SG
	Kube     *kube.Kube
	Events   record.EventRecorder
	Metrics  *metrics.Metrics
	Log      *slog.Logger
	Now      func() time.Time

	// MaxBackoff caps the delay after failed loops.
	MaxBackoff time.Duration
	// FailureEvents is how many failed loops in a row raise a Warning.
	FailureEvents int
	// WarnEvery rate-limits repeats of the same Warning event.
	WarnEvery time.Duration

	state     *decide.State
	persisted map[string]*string
	failures  int
	warned    map[string]time.Time
	// conditions are the keys of the warnings decide raised last loop.
	conditions map[string]bool
	// lastLoop is the Unix nano time of the last loop attempt.
	lastLoop atomic.Int64
	ordinal  *regexp.Regexp
}

func (c *Controller) init() {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Log == nil {
		c.Log = slog.Default()
	}
	if c.MaxBackoff == 0 {
		c.MaxBackoff = DefaultMaxBackoff
	}
	if c.FailureEvents == 0 {
		c.FailureEvents = DefaultFailureEvents
	}
	if c.WarnEvery == 0 {
		c.WarnEvery = DefaultWarnEvery
	}
	if c.warned == nil {
		c.warned = map[string]time.Time{}
	}
	if c.ordinal == nil {
		c.ordinal = regexp.MustCompile(`^` + regexp.QuoteMeta(c.Kube.StatefulSet) + `-(\d+)\.`)
	}
}

// LastLoop is when the last loop started; zero before the first.
func (c *Controller) LastLoop() time.Time {
	ns := c.lastLoop.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// Run loops until ctx is done.
func (c *Controller) Run(ctx context.Context) error {
	c.init()
	c.Log.Info("scaling", "statefulset", c.Kube.StatefulSet, "namespace", c.Kube.Namespace,
		"min", c.Config.Min, "max", c.Config.Max, "headroom_pct", c.Config.HeadroomPct,
		"idle", c.Config.IdleAfter, "park_ttl", c.Config.ParkTTL, "stuck_after", c.Config.StuckAfter,
		"settle_timeout", c.Config.SettleTimeout, "interval", c.Interval)
	// Timers are re-read from the StatefulSet when (re)starting, e.g. after
	// taking over the lease.
	c.state = nil
	for {
		_ = c.Once(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(c.Delay()):
		}
	}
}

// Delay is the wait before the next loop: the interval, doubled for every
// failed loop in a row, up to MaxBackoff.
func (c *Controller) Delay() time.Duration {
	d := c.Interval
	for i := 0; i < c.failures && d < c.MaxBackoff; i++ {
		d *= 2
	}
	return min(d, max(c.MaxBackoff, c.Interval))
}

// loopError marks which API failed a loop.
type loopError struct {
	reason string
	err    error
}

func (e *loopError) Error() string { return e.err.Error() }
func (e *loopError) Unwrap() error { return e.err }

// Once runs one loop. On an SG or Kubernetes API error it makes no
// decision and returns the error; the next loop waits longer.
func (c *Controller) Once(ctx context.Context) error {
	c.init()
	start := c.Now()
	c.lastLoop.Store(start.UnixNano())
	defer func() { c.Metrics.LoopDuration.Observe(c.Now().Sub(start).Seconds()) }()

	sts, err := c.loop(ctx, start)
	if err == nil {
		if c.failures > 0 {
			c.Log.Info("recovered", "after_failures", c.failures)
		}
		c.failures = 0
		c.Metrics.ConsecutiveFailures.Set(0)
		delete(c.warned, "SGUnreachable")
		delete(c.warned, "KubernetesAPIError")
		return nil
	}
	c.failures++
	c.Metrics.ConsecutiveFailures.Set(float64(c.failures))
	reason := "KubernetesAPIError"
	var le *loopError
	if errors.As(err, &le) {
		reason = le.reason
	}
	c.Log.Error("loop failed, skipping decisions", "reason", reason, "err", err,
		"consecutive_failures", c.failures, "next_in", c.Delay())
	if c.failures >= c.FailureEvents && sts != nil {
		c.warn(sts, decide.Event{Type: decide.EventWarning, Reason: reason, Key: reason,
			Message: fmt.Sprintf("%d loops failed in a row, not scaling: %v", c.failures, err)})
	}
	return err
}

func (c *Controller) sgErr(err error) error {
	c.Metrics.SGErrors.Inc()
	return &loopError{reason: "SGUnreachable", err: err}
}

func (c *Controller) kubeErr(what string, err error) error {
	c.Metrics.KubeErrors.Inc()
	return &loopError{reason: "KubernetesAPIError", err: fmt.Errorf("%s: %w", what, err)}
}

// loop returns the StatefulSet when it got that far, for events.
func (c *Controller) loop(ctx context.Context, now time.Time) (*appsv1.StatefulSet, error) {
	sts, err := c.Kube.GetStatefulSet(ctx)
	if err != nil {
		return nil, c.kubeErr("get statefulset", err)
	}
	group, err := c.SG.RunnerGroup(ctx)
	if err != nil {
		return sts, c.sgErr(err)
	}
	claims, err := c.Kube.Claims(ctx)
	if err != nil {
		return sts, c.kubeErr("list pvcs", err)
	}
	jobs, err := c.Kube.ReapJobs(ctx)
	if err != nil {
		return sts, c.kubeErr("list reap jobs", err)
	}
	if c.state == nil {
		s := decide.DecodeState(sts.Annotations)
		c.state = &s
		c.persisted = decide.EncodeState(s)
	}

	obs := decide.Observation{
		Now: now, Replicas: kube.Replicas(sts), Queued: group.QueuedWorkflowsCount,
		Runners: c.runners(group), Claims: claims, ReapJobs: jobs,
	}
	if group.MaxNumberOfRunners != nil {
		obs.MaxRunners = *group.MaxNumberOfRunners
	}
	d := decide.Decide(c.Config, obs, *c.state)

	c.Log.Info("loop", "replicas", obs.Replicas, "max", d.Max, "queued", obs.Queued,
		"reserved_pct", d.ReservedPct, "free_pct", d.FreePct, "settling", d.Settling,
		"unconnected", len(d.Unconnected), "stuck", d.Stuck, "scale", d.Scale.String(), "why", d.Why)

	active := map[string]bool{}
	for _, e := range d.Events {
		active[e.Key] = true
		c.Log.Warn(e.Message, "reason", e.Reason)
		c.warn(sts, e)
	}
	// A condition that cleared and comes back is reported again right away.
	for k := range c.conditions {
		if !active[k] {
			delete(c.warned, k)
		}
	}
	c.conditions = active

	if d.Scale != decide.ScaleNone {
		if err := c.Kube.Scale(ctx, d.Replicas); err != nil {
			return sts, c.kubeErr("scale statefulset", err)
		}
		c.Metrics.ScaleEvents.WithLabelValues(d.Scale.String()).Inc()
		reason, msg := "ScaledOut", fmt.Sprintf("replicas %d -> %d: %s", obs.Replicas, d.Replicas, d.Why)
		if d.Scale == decide.ScaleIn {
			reason = "ScaledIn"
			msg = fmt.Sprintf("parking runner %d (replicas %d -> %d): %s", d.Replicas, obs.Replicas, d.Replicas, d.Why)
		} else if _, parked := claims[obs.Replicas]; parked {
			msg += fmt.Sprintf("; waking parked runner %d", obs.Replicas)
		} else {
			msg += fmt.Sprintf("; registering new runner %d", obs.Replicas)
		}
		c.Log.Info(msg, "reason", reason)
		c.Events.Event(sts, corev1.EventTypeNormal, reason, msg)
	}
	c.state = &d.State
	c.persistState(ctx)

	for _, sc := range d.StatusChanges {
		c.changeStatus(ctx, sts, sc, now)
	}
	for _, name := range d.ClearDrainMarks {
		if err := c.Kube.AnnotateClaim(ctx, name, map[string]*string{kube.AnnotationDrainedByScaler: nil}); err != nil {
			c.Metrics.KubeErrors.Inc()
			c.Log.Error("clear drain mark", "pvc", name, "err", err)
		}
	}
	c.reap(ctx, sts, d.Reap, now)

	parked := 0
	for n := range claims {
		if n >= d.Replicas {
			parked++
		}
	}
	m := c.Metrics
	m.Queued.Set(float64(obs.Queued))
	m.ReservedPct.Set(float64(d.ReservedPct))
	m.FreePct.Set(float64(d.FreePct))
	m.Replicas.Set(float64(d.Replicas))
	m.Awake.Set(float64(obs.Replicas))
	m.Parked.Set(float64(parked))
	m.Max.Set(float64(d.Max))
	m.Unconnected.Set(float64(len(d.Unconnected)))
	m.Settling.Set(float64(d.Settling))
	m.Stuck.Set(b2f(d.Stuck))
	return sts, nil
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// runners maps SG runners to StatefulSet ordinals through their host name
// (the pod's FQDN); others (VM runners of the same group) are left out.
func (c *Controller) runners(g *sg.RunnerGroup) []decide.Runner {
	var out []decide.Runner
	for _, i := range g.ContainerInstances {
		m := c.ordinal.FindStringSubmatch(i.ComputerName())
		if m == nil {
			continue
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		out = append(out, decide.Runner{
			Ordinal: n, ID: i.RunnerID, Status: i.Status, Connected: i.AgentConnected,
			Busy:    i.RunningTasksCount + i.PendingTasksCount,
			CPU:     sg.ResourceValue(i.RegisteredResources, "CPU"),
			CPUFree: sg.ResourceValue(i.RemainingResources, "CPU"),
			Mem:     sg.ResourceValue(i.RegisteredResources, "MEMORY"),
			MemFree: sg.ResourceValue(i.RemainingResources, "MEMORY"),
		})
	}
	return out
}

// persistState writes changed timers to the StatefulSet. A failure is
// retried next loop; the timers stay in memory meanwhile.
func (c *Controller) persistState(ctx context.Context) {
	want := decide.EncodeState(*c.state)
	if maps.EqualFunc(want, c.persisted, func(a, b *string) bool {
		return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
	}) {
		return
	}
	if err := c.Kube.AnnotateStatefulSet(ctx, want); err != nil {
		c.Metrics.KubeErrors.Inc()
		c.Log.Error("persist timers on the statefulset", "err", err)
		return
	}
	c.persisted = want
}

// changeStatus drains or reactivates a runner through SG. A drain is marked
// on the runner's PVC first, so a drain is never left without its mark
// (which would keep the runner DRAINING for good); a reactivation clears
// the mark after SG accepted it.
func (c *Controller) changeStatus(ctx context.Context, sts *appsv1.StatefulSet, sc decide.StatusChange, now time.Time) {
	log := c.Log.With("runner", sc.Ordinal, "status", sc.Status, "reason", sc.Reason)
	fail := func(what string, err error) {
		c.Metrics.StatusChanges.WithLabelValues(sc.Reason, "failed").Inc()
		log.Error(what, "err", err)
		c.warn(sts, decide.Event{Type: decide.EventWarning, Reason: "StatusChangeFailed",
			Key:     fmt.Sprintf("StatusChangeFailed/%d/%s", sc.Ordinal, sc.Status),
			Message: fmt.Sprintf("could not set runner %d %s (%s): %v", sc.Ordinal, sc.Status, sc.Reason, err)})
	}
	if sc.Status == decide.StatusDraining {
		v := strconv.FormatInt(now.Unix(), 10)
		if err := c.Kube.AnnotateClaim(ctx, sc.Claim, map[string]*string{kube.AnnotationDrainedByScaler: &v}); err != nil {
			c.Metrics.KubeErrors.Inc()
			fail("mark drain on pvc", err)
			return
		}
	}
	if err := c.SG.SetRunnerStatus(ctx, sc.RunnerID, sc.Status); err != nil {
		c.Metrics.SGErrors.Inc()
		fail("set runner status", err)
		return
	}
	if sc.Status == decide.StatusActive {
		if err := c.Kube.AnnotateClaim(ctx, sc.Claim, map[string]*string{kube.AnnotationDrainedByScaler: nil}); err != nil {
			// Retried next loop: an ACTIVE runner's mark is cleared as stale.
			c.Metrics.KubeErrors.Inc()
			log.Error("clear drain mark", "err", err)
		}
	}
	c.Metrics.StatusChanges.WithLabelValues(sc.Reason, "ok").Inc()
	var msg string
	switch sc.Reason {
	case "DrainedParkedRunner":
		msg = fmt.Sprintf("runner %d is parked but SG had it ACTIVE (its pod went away without draining): set DRAINING", sc.Ordinal)
	case "DrainedUnconnectedRunner":
		msg = fmt.Sprintf("runner %d is awake but not connected past the settle timeout: set DRAINING until it connects", sc.Ordinal)
	default:
		msg = fmt.Sprintf("runner %d awake and connected again: set ACTIVE (undoing the scaler's drain)", sc.Ordinal)
	}
	log.Info(msg)
	c.Events.Event(sts, corev1.EventTypeNormal, sc.Reason, msg)
}

func (c *Controller) reap(ctx context.Context, sts *appsv1.StatefulSet, actions []decide.ReapAction, now time.Time) {
	for _, a := range actions {
		log := c.Log.With("runner", a.Ordinal, "pvc", a.Claim)
		kerr := func(what string, err error) {
			c.Metrics.KubeErrors.Inc()
			log.Error(what, "err", err)
		}
		switch a.Kind {
		case decide.ReapStamp:
			v := strconv.FormatInt(now.Unix(), 10)
			if err := c.Kube.AnnotateClaim(ctx, a.Claim, map[string]*string{kube.AnnotationParkedAt: &v}); err != nil {
				kerr("stamp parked-at", err)
				continue
			}
			log.Info("runner parked")
			c.Events.Eventf(sts, corev1.EventTypeNormal, "Parked", "runner %d parked (pod gone, registration kept on %s)", a.Ordinal, a.Claim)
		case decide.ReapClearStamp:
			if err := c.Kube.AnnotateClaim(ctx, a.Claim, map[string]*string{kube.AnnotationParkedAt: nil}); err != nil {
				kerr("clear parked-at", err)
				continue
			}
			log.Info("runner awake")
			c.Events.Eventf(sts, corev1.EventTypeNormal, "Woke", "runner %d awake again", a.Ordinal)
		case decide.ReapStartJob:
			if err := c.Kube.CreateReapJob(ctx, a.Ordinal); err != nil {
				kerr("create reap job", err)
				continue
			}
			c.Metrics.Reaps.WithLabelValues("started").Inc()
			log.Info("deregistering parked runner", "parked_for", a.ParkedFor.Round(time.Second))
			c.Events.Eventf(sts, corev1.EventTypeNormal, "Reaping",
				"runner %d parked for %s: deregistering it (job/%s)", a.Ordinal, a.ParkedFor.Round(time.Second), c.Kube.JobName(a.Ordinal))
		case decide.ReapCleanup:
			if err := c.Kube.DeleteClaim(ctx, a.Claim); err != nil {
				kerr("delete state pvc", err)
				continue
			}
			if err := c.Kube.DeleteClaim(ctx, c.Kube.DockerClaimName(a.Ordinal)); err != nil {
				kerr("delete docker pvc", err)
				continue
			}
			if err := c.Kube.DeleteReapJob(ctx, a.Ordinal); err != nil {
				kerr("delete reap job", err)
			}
			c.Metrics.Reaps.WithLabelValues("succeeded").Inc()
			log.Info("runner deregistered, PVCs deleted")
			c.Events.Eventf(sts, corev1.EventTypeNormal, "Reaped", "runner %d deregistered from SG and its PVCs deleted", a.Ordinal)
		case decide.ReapRetry:
			if err := c.Kube.DeleteReapJob(ctx, a.Ordinal); err != nil {
				kerr("delete failed reap job", err)
				continue
			}
			c.Metrics.Reaps.WithLabelValues("failed").Inc()
			log.Warn("deregistration failed, retrying next loop")
			c.warn(sts, decide.Event{Type: decide.EventWarning, Reason: "ReapFailed",
				Key:     fmt.Sprintf("ReapFailed/%d", a.Ordinal),
				Message: fmt.Sprintf("deregistering parked runner %d failed; retrying (identity kept on %s)", a.Ordinal, a.Claim)})
		}
	}
}

// warn emits a Warning event unless the same one went out within WarnEvery.
func (c *Controller) warn(sts *appsv1.StatefulSet, e decide.Event) {
	now := c.Now()
	if last, ok := c.warned[e.Key]; ok && now.Sub(last) < c.WarnEvery {
		return
	}
	c.warned[e.Key] = now
	c.Events.Event(sts, e.Type, e.Reason, e.Message)
}

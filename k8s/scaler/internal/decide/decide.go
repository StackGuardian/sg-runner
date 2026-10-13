// Package decide holds the scaler's rules as a pure function: an observation
// of SG and the cluster, the timers kept between loops and the configuration
// go in; the replicas to set, runner status changes, reap steps, warnings and
// the updated timers come out. Nothing here does I/O.
package decide

import (
	"fmt"
	"math"
	"sort"
	"time"
)

// Runner statuses as SG reports them.
const (
	StatusActive   = "ACTIVE"
	StatusDraining = "DRAINING"
)

// Event types, as Kubernetes names them.
const (
	EventNormal  = "Normal"
	EventWarning = "Warning"
)

// Config holds the scaling rules' knobs.
type Config struct {
	Min           int
	Max           int
	HeadroomPct   int
	IdleAfter     time.Duration
	StuckAfter    time.Duration
	SettleTimeout time.Duration
	ParkTTL       time.Duration
}

// Runner is one SG container instance mapped to a StatefulSet ordinal.
type Runner struct {
	Ordinal   int
	ID        string
	Status    string
	Connected bool
	// Busy is running plus pending tasks.
	Busy    int
	CPU     float64
	CPUFree float64
	Mem     float64
	MemFree float64
}

// FullyIdle reports a runner with nothing running and nothing reserved.
func (r Runner) FullyIdle() bool {
	return r.Busy == 0 && r.CPUFree == r.CPU && r.MemFree == r.Mem
}

// Size is the runner's registered CPU units / MiB, for messages.
func (r Runner) Size() string {
	return fmt.Sprintf("%g/%g", r.CPU, r.Mem)
}

// JobState is the state of a runner's reap Job.
type JobState int

// Reap Job states.
const (
	JobNone JobState = iota
	JobRunning
	JobSucceeded
	JobFailed
)

// Claim is a runner's state PVC.
type Claim struct {
	Name string
	// ParkedAt is the parked-at stamp; zero when absent or unreadable.
	ParkedAt time.Time
	// Stamped reports a parked-at annotation present, readable or not.
	Stamped bool
	// DrainedByScaler reports that the scaler set this runner DRAINING.
	DrainedByScaler bool
}

// Observation is what one loop sees.
type Observation struct {
	Now      time.Time
	Replicas int
	Queued   int
	// MaxRunners is the runner group's MaxNumberOfRunners; 0 when unset.
	MaxRunners int
	// Runners are the SG runners that map to an ordinal of the StatefulSet.
	Runners []Runner
	// Claims are the state PVCs by ordinal.
	Claims map[int]Claim
	// ReapJobs are the reap Jobs by ordinal.
	ReapJobs map[int]JobState
}

// State is what the scaler remembers between loops.
type State struct {
	// IdleSince: highest awake ordinal -> when it was first seen idle.
	IdleSince map[int]time.Time
	// StuckSince: since when workflows were queued while an awake runner
	// sat fully idle; zero when not.
	StuckSince time.Time
	// UnconnectedSince: awake ordinal not connected to SG -> first seen so.
	UnconnectedSince map[int]time.Time
}

// Clone returns a deep copy.
func (s State) Clone() State {
	c := State{StuckSince: s.StuckSince, IdleSince: map[int]time.Time{}, UnconnectedSince: map[int]time.Time{}}
	for k, v := range s.IdleSince {
		c.IdleSince[k] = v
	}
	for k, v := range s.UnconnectedSince {
		c.UnconnectedSince[k] = v
	}
	return c
}

// Scale is a replicas change.
type Scale int

// Scale directions.
const (
	ScaleNone Scale = iota
	ScaleOut
	ScaleIn
)

func (s Scale) String() string {
	switch s {
	case ScaleOut:
		return "out"
	case ScaleIn:
		return "in"
	}
	return "none"
}

// StatusChange sets a runner's status through SG.
type StatusChange struct {
	Ordinal  int
	RunnerID string
	// Claim is the runner's state PVC, which records drains by the scaler.
	Claim  string
	Status string
	// Reason is DrainedParkedRunner, DrainedUnconnectedRunner or Reactivated.
	Reason string
}

// ReapKind is one step of reaping parked runners.
type ReapKind int

// Reap steps.
const (
	// ReapStamp stamps parked-at on a newly parked runner's PVC.
	ReapStamp ReapKind = iota
	// ReapClearStamp clears parked-at on a runner awake again.
	ReapClearStamp
	// ReapStartJob starts the Job deregistering a runner parked past the TTL.
	ReapStartJob
	// ReapCleanup deletes a deregistered runner's PVCs and its Job.
	ReapCleanup
	// ReapRetry deletes a failed Job so a later loop retries.
	ReapRetry
)

// ReapAction is one reap step for one ordinal.
type ReapAction struct {
	Kind      ReapKind
	Ordinal   int
	Claim     string
	ParkedFor time.Duration
}

// Event is something worth reporting as a Kubernetes Event. Key identifies
// repeats of the same condition so they can be rate-limited.
type Event struct {
	Type    string
	Reason  string
	Key     string
	Message string
}

// Decision is the outcome of one loop.
type Decision struct {
	State State

	Max         int
	ReservedPct int
	FreePct     int
	Awake       int
	Settling    int
	// Unconnected are the awake ordinals not connected to SG.
	Unconnected []int
	Stuck       bool

	// Replicas to set; equal to the observed replicas when Scale is ScaleNone.
	Replicas int
	Scale    Scale
	// Why explains the scale decision (or why a scale out waits).
	Why string

	StatusChanges []StatusChange
	// ClearDrainMarks are state PVCs whose drained-by-scaler mark is stale.
	ClearDrainMarks []string
	Reap            []ReapAction
	Events          []Event
}

// ReservedPct is the share (0-100, floored) of CPU or memory, whichever is
// higher, reserved on ACTIVE and connected runners with an ordinal below
// the given one. 100 when there are none.
func ReservedPct(runners []Runner, below int) int {
	var cpu, cpuFree, mem, memFree float64
	n := 0
	for _, r := range runners {
		if r.Ordinal < below && r.Status == StatusActive && r.Connected {
			n++
			cpu += r.CPU
			cpuFree += r.CPUFree
			mem += r.Mem
			memFree += r.MemFree
		}
	}
	if n == 0 {
		return 100
	}
	cpuPct := (cpu - cpuFree) * 100 / math.Max(cpu, 1)
	memPct := (mem - memFree) * 100 / math.Max(mem, 1)
	return int(math.Floor(math.Max(cpuPct, memPct)))
}

// Decide applies the scaling rules to one observation.
func Decide(cfg Config, obs Observation, prev State) Decision {
	now := obs.Now
	st := prev.Clone()
	d := Decision{State: st, Replicas: obs.Replicas}
	replicas := obs.Replicas

	d.Max = cfg.Max
	if obs.MaxRunners > 0 && obs.MaxRunners < d.Max {
		d.Max = obs.MaxRunners
	}

	// Undo the scaler's own drains once the runner is awake and connected
	// again; drains by anyone else (no mark) stick. Decide as if they were
	// ACTIVE already, or the runner reactivated this loop looks busy and
	// another one gets woken for nothing.
	var reactivate []StatusChange
	runners := make([]Runner, len(obs.Runners))
	copy(runners, obs.Runners)
	for i, r := range runners {
		claim, ok := obs.Claims[r.Ordinal]
		if !ok || !claim.DrainedByScaler || r.Ordinal >= replicas || !r.Connected || r.ID == "" {
			continue
		}
		switch r.Status {
		case StatusDraining:
			reactivate = append(reactivate, StatusChange{
				Ordinal: r.Ordinal, RunnerID: r.ID, Claim: claim.Name, Status: StatusActive,
				Reason: "Reactivated",
			})
			runners[i].Status = StatusActive
		case StatusActive:
			// Active again (by someone, or a drain that failed): the mark is stale.
			d.ClearDrainMarks = append(d.ClearDrainMarks, claim.Name)
		}
	}
	obs.Runners = runners

	d.ReservedPct = ReservedPct(obs.Runners, replicas)
	d.FreePct = 100 - d.ReservedPct
	d.Awake = replicas

	byOrdinal := map[int][]Runner{}
	for _, r := range obs.Runners {
		byOrdinal[r.Ordinal] = append(byOrdinal[r.Ordinal], r)
	}
	connected := func(n int) bool {
		for _, r := range byOrdinal[n] {
			if r.Connected {
				return true
			}
		}
		return false
	}

	// Settling: an awake runner not connected yet. Wait for it, or one queued
	// workflow wakes several runners; past the settle timeout, decide without
	// it, report it and drain it so SG places nothing there.
	unconnected := map[int]bool{}
	for n := 0; n < replicas; n++ {
		if !connected(n) {
			unconnected[n] = true
			d.Unconnected = append(d.Unconnected, n)
		}
	}
	for n := range st.UnconnectedSince {
		if !unconnected[n] {
			delete(st.UnconnectedSince, n)
		}
	}
	for _, n := range d.Unconnected {
		since, ok := st.UnconnectedSince[n]
		if !ok {
			since = now
			st.UnconnectedSince[n] = now
		}
		waited := now.Sub(since)
		if waited < cfg.SettleTimeout {
			d.Settling++
			continue
		}
		d.Events = append(d.Events, Event{
			Type: EventWarning, Reason: "RunnerNotConnected", Key: fmt.Sprintf("RunnerNotConnected/%d", n),
			Message: fmt.Sprintf("runner %d awake but not connected to SG for %s; scaling without it (check its pod)",
				n, waited.Round(time.Second)),
		})
		claim, hasClaim := obs.Claims[n]
		for _, r := range byOrdinal[n] {
			if r.Status == StatusActive && r.ID != "" && hasClaim {
				d.StatusChanges = append(d.StatusChanges, StatusChange{
					Ordinal: n, RunnerID: r.ID, Claim: claim.Name, Status: StatusDraining,
					Reason: "DrainedUnconnectedRunner",
				})
			}
		}
	}

	// Stuck queue: queued while a runner sits fully idle past SG's retry
	// delay means what's queued fits no runner of this size.
	var idle *Runner
	for i, r := range obs.Runners {
		if r.Ordinal < replicas && r.Status == StatusActive && r.Connected && r.FullyIdle() {
			idle = &obs.Runners[i]
			break
		}
	}
	if obs.Queued > 0 && idle != nil {
		if st.StuckSince.IsZero() {
			st.StuckSince = now
		}
		if waited := now.Sub(st.StuckSince); waited >= cfg.StuckAfter {
			d.Stuck = true
			d.Events = append(d.Events, Event{
				Type: EventWarning, Reason: "StuckQueue", Key: "StuckQueue",
				Message: fmt.Sprintf("%d workflow(s) queued for %s while runner %d (CPU units/MiB %s) sits idle: "+
					"they need more than one runner pod offers. Ignoring them; raise the runner's resources to run them.",
					obs.Queued, waited.Round(time.Second), idle.Ordinal, idle.Size()),
			})
		}
	} else {
		st.StuckSince = time.Time{}
	}

	// Scaling.
	queueWantsOut := obs.Queued > 0 && idle == nil
	headroomWantsOut := d.FreePct < cfg.HeadroomPct
	belowMin := replicas < cfg.Min
	switch {
	case d.Settling > 0:
		d.Why = fmt.Sprintf("waiting for %d runner(s) to connect", d.Settling)
	case replicas < d.Max && (queueWantsOut || headroomWantsOut || belowMin):
		switch {
		case queueWantsOut:
			d.Why = fmt.Sprintf("%d workflow(s) queued and no runner idle", obs.Queued)
		case headroomWantsOut:
			d.Why = fmt.Sprintf("%d%% free, below the %d%% headroom", d.FreePct, cfg.HeadroomPct)
		default:
			d.Why = fmt.Sprintf("below the minimum of %d", cfg.Min)
		}
		if obs.ReapJobs[replicas] != JobNone {
			d.Why = fmt.Sprintf("scale out waits: runner %d is being deregistered", replicas)
			break
		}
		d.Scale = ScaleOut
		d.Replicas = replicas + 1
		st.IdleSince = map[int]time.Time{}
		// The new runner starts idle: don't mistake it for a stuck queue.
		st.StuckSince = time.Time{}
	case replicas > cfg.Min && (obs.Queued == 0 || d.Stuck || replicas > d.Max):
		top := replicas - 1
		for n := range st.IdleSince {
			if n != top {
				delete(st.IdleSince, n)
			}
		}
		busy, seen := 0, len(byOrdinal[top]) > 0
		for _, r := range byOrdinal[top] {
			busy += r.Busy
		}
		if !seen || busy > 0 {
			delete(st.IdleSince, top)
			break
		}
		since, ok := st.IdleSince[top]
		if !ok {
			since = now
			st.IdleSince[top] = now
		}
		// Don't park into a scale out: the rest must keep the headroom.
		freeWithoutTop := 100 - ReservedPct(obs.Runners, top)
		if idleFor := now.Sub(since); idleFor >= cfg.IdleAfter && freeWithoutTop >= cfg.HeadroomPct {
			d.Scale = ScaleIn
			d.Replicas = top
			d.Why = fmt.Sprintf("runner %d idle for %s", top, idleFor.Round(time.Second))
			delete(st.IdleSince, top)
		}
	}

	// Parked runners SG still reports ACTIVE: the pod went away without its
	// preStop drain (node loss, force delete). Drain them so SG places
	// nothing there, and mark the drain as the scaler's own.
	for _, r := range obs.Runners {
		if r.Ordinal < replicas || r.Status != StatusActive || r.Connected || r.ID == "" {
			continue
		}
		claim, ok := obs.Claims[r.Ordinal]
		if !ok {
			continue
		}
		d.StatusChanges = append(d.StatusChanges, StatusChange{
			Ordinal: r.Ordinal, RunnerID: r.ID, Claim: claim.Name, Status: StatusDraining,
			Reason: "DrainedParkedRunner",
		})
	}

	// Not the runner parked this loop: its pod is on its way down.
	for _, sc := range reactivate {
		if sc.Ordinal < d.Replicas {
			d.StatusChanges = append(d.StatusChanges, sc)
		}
	}

	d.Reap = PlanReap(obs.Claims, obs.ReapJobs, d.Replicas, now, cfg.ParkTTL)
	d.State = st
	return d
}

// PlanReap stamps newly parked runners, clears stamps of runners awake
// again and deregisters runners parked longer than ttl.
func PlanReap(claims map[int]Claim, jobs map[int]JobState, replicas int, now time.Time, ttl time.Duration) []ReapAction {
	ordinals := make([]int, 0, len(claims))
	for n := range claims {
		ordinals = append(ordinals, n)
	}
	sort.Ints(ordinals)

	var out []ReapAction
	for _, n := range ordinals {
		c := claims[n]
		if n < replicas {
			if c.Stamped {
				out = append(out, ReapAction{Kind: ReapClearStamp, Ordinal: n, Claim: c.Name})
			}
			continue
		}
		if c.ParkedAt.IsZero() {
			out = append(out, ReapAction{Kind: ReapStamp, Ordinal: n, Claim: c.Name})
			continue
		}
		parkedFor := now.Sub(c.ParkedAt)
		if parkedFor < ttl {
			continue
		}
		a := ReapAction{Ordinal: n, Claim: c.Name, ParkedFor: parkedFor}
		switch jobs[n] {
		case JobNone:
			a.Kind = ReapStartJob
		case JobSucceeded:
			a.Kind = ReapCleanup
		case JobFailed:
			a.Kind = ReapRetry
		default:
			continue
		}
		out = append(out, a)
	}
	return out
}

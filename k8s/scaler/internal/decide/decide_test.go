package decide

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

var t0 = time.Unix(1_700_000_000, 0)

func cfg() Config {
	return Config{
		Min: 1, Max: 10, HeadroomPct: 0,
		IdleAfter: 60 * time.Second, StuckAfter: 180 * time.Second,
		SettleTimeout: 300 * time.Second, ParkTTL: 12 * time.Hour,
	}
}

// Runner sizes as SG registers them: CPU units and MiB.
const cpu, mem = 2048, 4096

func idle(n int) Runner {
	return Runner{Ordinal: n, ID: id(n), Status: StatusActive, Connected: true, CPU: cpu, CPUFree: cpu, Mem: mem, MemFree: mem}
}

// full is a runner one workflow fills completely.
func full(n int) Runner {
	r := idle(n)
	r.Busy, r.CPUFree, r.MemFree = 1, 0, 0
	return r
}

// half is a runner one workflow fills halfway.
func half(n int) Runner {
	r := idle(n)
	r.Busy, r.CPUFree, r.MemFree = 1, cpu/2, mem/2
	return r
}

func unconnected(n int, status string) Runner {
	r := idle(n)
	r.Connected, r.Status = false, status
	return r
}

func id(n int) string { return "runner-id-" + string(rune('a'+n)) }

func claims(ordinals ...int) map[int]Claim {
	m := map[int]Claim{}
	for _, n := range ordinals {
		m[n] = Claim{Name: claimName(n)}
	}
	return m
}

func claimName(n int) string { return "state-sg-runner-" + string(rune('0'+n)) }

func obs(at time.Duration, replicas, queued int, runners ...Runner) Observation {
	cl := map[int]Claim{}
	for n := 0; n < replicas; n++ {
		cl[n] = Claim{Name: claimName(n)}
	}
	return Observation{Now: t0.Add(at), Replicas: replicas, Queued: queued, Runners: runners, Claims: cl}
}

func hasEvent(d Decision, reason string) bool {
	for _, e := range d.Events {
		if e.Reason == reason {
			return true
		}
	}
	return false
}

func TestReservedPct(t *testing.T) {
	tests := []struct {
		name    string
		runners []Runner
		below   int
		want    int
	}{
		{"none awake", nil, 3, 100},
		{"only unconnected", []Runner{unconnected(0, StatusActive)}, 1, 100},
		{"only draining", []Runner{func() Runner { r := idle(0); r.Status = StatusDraining; return r }()}, 1, 100},
		{"idle", []Runner{idle(0)}, 1, 0},
		{"full", []Runner{full(0)}, 1, 100},
		{"half of two", []Runner{full(0), idle(1)}, 2, 50},
		{"ordinal at or above excluded", []Runner{idle(0), full(1)}, 1, 0},
		{"memory higher than cpu", []Runner{func() Runner { r := idle(0); r.MemFree = mem / 4; return r }()}, 1, 75},
		{"floored", []Runner{func() Runner { r := idle(0); r.CPUFree = cpu * 2 / 3; return r }()}, 1, 33},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ReservedPct(tt.runners, tt.below); got != tt.want {
				t.Errorf("ReservedPct = %d, want %d", got, tt.want)
			}
		})
	}
}

// Single loops, each rule on its own.
func TestDecideRules(t *testing.T) {
	tests := []struct {
		name      string
		cfg       func(*Config)
		obs       Observation
		state     State
		wantScale Scale
		wantRepl  int
		wantEvent string
	}{
		{name: "queued, runner busy: out", obs: obs(0, 1, 1, full(0)), wantScale: ScaleOut, wantRepl: 2},
		{name: "queued, runner fully idle: wait for SG's retry", obs: obs(0, 1, 1, idle(0)), wantRepl: 1},
		{name: "queued, half-busy runner counts as not idle: out", obs: obs(0, 1, 1, half(0)), wantScale: ScaleOut, wantRepl: 2},
		{name: "nothing queued, no headroom: nothing", obs: obs(0, 1, 0, full(0)), wantRepl: 1},
		{name: "headroom: free below it: out", cfg: func(c *Config) { c.HeadroomPct = 60 }, obs: obs(0, 1, 0, half(0)), wantScale: ScaleOut, wantRepl: 2},
		{name: "headroom: free at it: nothing", cfg: func(c *Config) { c.HeadroomPct = 50 }, obs: obs(0, 1, 0, half(0)), wantRepl: 1},
		{name: "at SCALER_MAX: no out", cfg: func(c *Config) { c.Max = 2 }, obs: obs(0, 2, 1, full(0), full(1)), wantRepl: 2},
		{name: "at MaxNumberOfRunners: no out", obs: func() Observation {
			o := obs(0, 2, 1, full(0), full(1))
			o.MaxRunners = 2
			return o
		}(), wantRepl: 2},
		{name: "MaxNumberOfRunners above SCALER_MAX: SCALER_MAX wins", cfg: func(c *Config) { c.Max = 2 }, obs: func() Observation {
			o := obs(0, 2, 1, full(0), full(1))
			o.MaxRunners = 5
			return o
		}(), wantRepl: 2},
		{name: "below SCALER_MIN: out", cfg: func(c *Config) { c.Min = 2 }, obs: obs(0, 1, 0, idle(0)), wantScale: ScaleOut, wantRepl: 2},
		{name: "zero replicas: up to the minimum", obs: obs(0, 0, 0), wantScale: ScaleOut, wantRepl: 1},
		{name: "reap Job on next ordinal: out waits", obs: func() Observation {
			o := obs(0, 1, 1, full(0))
			o.ReapJobs = map[int]JobState{1: JobRunning}
			return o
		}(), wantRepl: 1},
		{name: "reap Job on another ordinal: out", obs: func() Observation {
			o := obs(0, 1, 1, full(0))
			o.ReapJobs = map[int]JobState{2: JobRunning}
			return o
		}(), wantScale: ScaleOut, wantRepl: 2},
		{name: "at SCALER_MIN, idle long: no in", obs: obs(time.Hour, 1, 0, idle(0)), state: State{IdleSince: map[int]time.Time{0: t0}}, wantRepl: 1},
		{name: "top idle long enough: in", obs: obs(60*time.Second, 2, 0, idle(0), idle(1)), state: State{IdleSince: map[int]time.Time{1: t0}}, wantScale: ScaleIn, wantRepl: 1},
		{name: "top idle not long enough: nothing", obs: obs(59*time.Second, 2, 0, idle(0), idle(1)), state: State{IdleSince: map[int]time.Time{1: t0}}, wantRepl: 2},
		{name: "top busy: nothing", obs: obs(time.Hour, 2, 0, idle(0), full(1)), state: State{IdleSince: map[int]time.Time{1: t0}}, wantRepl: 2},
		{name: "top unknown to SG: not idle", obs: obs(time.Hour, 2, 0, idle(0)), state: State{IdleSince: map[int]time.Time{1: t0}}, wantRepl: 2},
		{name: "queued: no in", obs: obs(time.Hour, 2, 1, full(0), idle(1)), state: State{IdleSince: map[int]time.Time{1: t0}}, wantRepl: 2},
		{name: "headroom without top too low: no in", cfg: func(c *Config) { c.HeadroomPct = 20 },
			obs: obs(time.Hour, 2, 0, full(0), idle(1)), state: State{IdleSince: map[int]time.Time{1: t0}}, wantRepl: 2},
		{name: "above max (MaxNumberOfRunners lowered), queued: idle top still parks", obs: func() Observation {
			o := obs(time.Hour, 3, 1, full(0), full(1), idle(2))
			o.MaxRunners = 2
			return o
		}(), state: State{IdleSince: map[int]time.Time{2: t0}}, wantScale: ScaleIn, wantRepl: 2},
		{name: "settling: no decision", obs: obs(0, 2, 1, full(0)), wantRepl: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cfg()
			if tt.cfg != nil {
				tt.cfg(&c)
			}
			d := Decide(c, tt.obs, tt.state)
			if d.Scale != tt.wantScale || d.Replicas != tt.wantRepl {
				t.Errorf("got scale %v replicas %d (%s), want %v %d", d.Scale, d.Replicas, d.Why, tt.wantScale, tt.wantRepl)
			}
			if tt.wantEvent != "" && !hasEvent(d, tt.wantEvent) {
				t.Errorf("missing event %s in %+v", tt.wantEvent, d.Events)
			}
		})
	}
}

func TestScaleOutResetsTimers(t *testing.T) {
	st := State{IdleSince: map[int]time.Time{0: t0}, StuckSince: t0}
	d := Decide(cfg(), obs(10*time.Second, 1, 1, full(0)), st)
	if d.Scale != ScaleOut {
		t.Fatalf("want scale out, got %v", d.Scale)
	}
	if len(d.State.IdleSince) != 0 || !d.State.StuckSince.IsZero() {
		t.Errorf("timers not reset: %+v", d.State)
	}
	if len(st.IdleSince) != 1 {
		t.Error("Decide modified the previous state")
	}
}

// step runs one loop and carries the state and replicas forward.
type sim struct {
	t     *testing.T
	cfg   Config
	state State
	repl  int
}

func (s *sim) loop(at time.Duration, queued int, runners ...Runner) Decision {
	s.t.Helper()
	d := Decide(s.cfg, obs(at, s.repl, queued, runners...), s.state)
	s.state, s.repl = d.State, d.Replicas
	return d
}

// A workflow bigger than any runner pod: the idle runner never takes it.
func TestOversizedWorkflow(t *testing.T) {
	s := &sim{t: t, cfg: cfg(), repl: 2}
	// Two runners awake, both idle, one oversized workflow queued.
	if d := s.loop(0, 1, idle(0), idle(1)); d.Scale != ScaleNone || d.Stuck {
		t.Fatalf("t=0: want nothing, got %v stuck=%v", d.Scale, d.Stuck)
	}
	if d := s.loop(179*time.Second, 1, idle(0), idle(1)); d.Stuck {
		t.Fatal("stuck before 180s")
	}
	d := s.loop(180*time.Second, 1, idle(0), idle(1))
	if !d.Stuck || !hasEvent(d, "StuckQueue") {
		t.Fatalf("want stuck + StuckQueue at 180s, got stuck=%v events=%+v", d.Stuck, d.Events)
	}
	if !strings.Contains(d.Events[0].Message, "2048/4096") {
		t.Errorf("stuck message lacks the runner size: %s", d.Events[0].Message)
	}
	// Stuck: the queue is ignored, so the extra runner parks once idle long enough.
	if d := s.loop(239*time.Second, 1, idle(0), idle(1)); d.Scale != ScaleNone {
		t.Fatalf("parked before idle timeout: %v", d.Scale)
	}
	if d := s.loop(240*time.Second, 1, idle(0), idle(1)); d.Scale != ScaleIn || d.Replicas != 1 {
		t.Fatalf("want park to 1 while stuck, got %v %d", d.Scale, d.Replicas)
	}
	// Never below the minimum, never out for the stuck workflow.
	for at := 255 * time.Second; at < time.Hour; at += 15 * time.Second {
		if d := s.loop(at, 1, idle(0)); d.Scale != ScaleNone {
			t.Fatalf("t=%s: want nothing, got %v", at, d.Scale)
		}
	}
	// Queue drained (cancelled): stuck clears.
	if d := s.loop(time.Hour, 0, idle(0)); d.Stuck || !d.State.StuckSince.IsZero() {
		t.Error("stuck not cleared once the queue is empty")
	}
}

// A queued workflow with the runner busy wakes exactly one more runner, and
// no second one while the new runner waits idle for SG's retry.
func TestNoOvershoot(t *testing.T) {
	s := &sim{t: t, cfg: cfg(), repl: 1}
	if d := s.loop(0, 1, full(0)); d.Scale != ScaleOut || d.Replicas != 2 {
		t.Fatalf("want +1, got %v %d", d.Scale, d.Replicas)
	}
	// Runner 1 starting: not in SG yet, then registered but not connected.
	if d := s.loop(15*time.Second, 1, full(0)); d.Scale != ScaleNone || d.Settling != 1 {
		t.Fatalf("want settling, got %v settling=%d", d.Scale, d.Settling)
	}
	if d := s.loop(30*time.Second, 1, full(0), unconnected(1, StatusActive)); d.Scale != ScaleNone || d.Settling != 1 {
		t.Fatalf("want settling, got %v settling=%d", d.Scale, d.Settling)
	}
	// Connected and idle: SG's retry will place the workflow there.
	for at := 45 * time.Second; at < 150*time.Second; at += 15 * time.Second {
		if d := s.loop(at, 1, full(0), idle(1)); d.Scale != ScaleNone {
			t.Fatalf("t=%s: overshoot: %v to %d", at, d.Scale, d.Replicas)
		}
	}
	// Placed.
	if d := s.loop(150*time.Second, 0, full(0), full(1)); d.Scale != ScaleNone || d.Replicas != 2 {
		t.Fatalf("want 2 runners, got %v %d", d.Scale, d.Replicas)
	}
}

// Two workflows that each fill a runner: headroom 0 ends with 2 runners,
// headroom 20 with a warm third.
func TestHeadroom(t *testing.T) {
	for _, tc := range []struct {
		headroom int
		want     int
	}{{0, 2}, {20, 3}} {
		c := cfg()
		c.HeadroomPct = tc.headroom
		s := &sim{t: t, cfg: c, repl: 1}
		s.loop(0, 2, idle(0))                       // runner 0 idle: SG places one
		s.loop(15*time.Second, 1, full(0))          // one left queued: +1
		s.loop(30*time.Second, 1, full(0))          // runner 1 settling
		s.loop(45*time.Second, 1, full(0), idle(1)) // idle: SG places the second
		s.loop(60*time.Second, 0, full(0), full(1)) // both full
		var runners = []Runner{full(0), full(1)}
		if s.repl == 3 {
			runners = append(runners, idle(2))
			s.loop(75*time.Second, 0, full(0), full(1)) // runner 2 settling
		}
		for at := 90 * time.Second; at < time.Hour; at += 15 * time.Second {
			s.loop(at, 0, runners...)
		}
		if s.repl != tc.want {
			t.Errorf("headroom %d: %d runners, want %d", tc.headroom, s.repl, tc.want)
		}
	}
}

// A runner that never connects: waited for, then left out, warned about and
// drained; then it connects and the scaler undoes its own drain.
func TestSettleTimeout(t *testing.T) {
	s := &sim{t: t, cfg: cfg(), repl: 2}
	broken := unconnected(1, StatusActive)
	d := s.loop(0, 1, full(0), broken)
	if d.Scale != ScaleNone || d.Settling != 1 || len(d.StatusChanges) != 0 {
		t.Fatalf("want settling, got %+v", d)
	}
	if d := s.loop(299*time.Second, 1, full(0), broken); d.Scale != ScaleNone || d.Settling != 1 {
		t.Fatalf("decided before the settle timeout: %v", d.Scale)
	}
	d = s.loop(300*time.Second, 1, full(0), broken)
	if d.Settling != 0 || !hasEvent(d, "RunnerNotConnected") {
		t.Fatalf("want timed out + warning, got settling=%d events=%+v", d.Settling, d.Events)
	}
	want := []StatusChange{{Ordinal: 1, RunnerID: id(1), Claim: claimName(1), Status: StatusDraining, Reason: "DrainedUnconnectedRunner"}}
	if !reflect.DeepEqual(d.StatusChanges, want) {
		t.Fatalf("status changes = %+v, want %+v", d.StatusChanges, want)
	}
	if d.Scale != ScaleOut || d.Replicas != 3 {
		t.Fatalf("broken runner should not block scaling: %v %d", d.Scale, d.Replicas)
	}
	// Already drained: no second drain, still warned.
	drained := unconnected(1, StatusDraining)
	d = Decide(s.cfg, obs(400*time.Second, 2, 0, full(0), drained), d.State)
	if len(d.StatusChanges) != 0 || !hasEvent(d, "RunnerNotConnected") {
		t.Fatalf("want warning only, got %+v", d)
	}
}

func TestParkedRunnerDrains(t *testing.T) {
	mark := func(o Observation, n int) Observation {
		c := o.Claims[n]
		c.DrainedByScaler = true
		o.Claims[n] = c
		return o
	}
	withClaim := func(o Observation, n int) Observation {
		o.Claims[n] = Claim{Name: claimName(n), ParkedAt: t0, Stamped: true}
		return o
	}
	tests := []struct {
		name      string
		obs       Observation
		want      []StatusChange
		wantClear []string
	}{
		{name: "parked, ACTIVE, gone: drain",
			obs:  withClaim(obs(0, 1, 0, full(0), unconnected(1, StatusActive)), 1),
			want: []StatusChange{{Ordinal: 1, RunnerID: id(1), Claim: claimName(1), Status: StatusDraining, Reason: "DrainedParkedRunner"}}},
		{name: "parked, ACTIVE, still connected (preStop running): leave it",
			obs: withClaim(obs(0, 1, 0, full(0), idle(1)), 1)},
		{name: "parked, DRAINING: leave it",
			obs: withClaim(obs(0, 1, 0, full(0), unconnected(1, StatusDraining)), 1)},
		{name: "parked, ACTIVE, no PVC (reaped): leave it",
			obs: obs(0, 1, 0, full(0), unconnected(1, StatusActive))},
		{name: "parked, marked but still ACTIVE (drain failed): drain again",
			obs:  mark(withClaim(obs(0, 1, 0, full(0), unconnected(1, StatusActive)), 1), 1),
			want: []StatusChange{{Ordinal: 1, RunnerID: id(1), Claim: claimName(1), Status: StatusDraining, Reason: "DrainedParkedRunner"}}},
		{name: "woke, DRAINING, marked: reactivate",
			obs:  mark(obs(0, 2, 0, full(0), func() Runner { r := full(1); r.Status = StatusDraining; return r }()), 1),
			want: []StatusChange{{Ordinal: 1, RunnerID: id(1), Claim: claimName(1), Status: StatusActive, Reason: "Reactivated"}}},
		{name: "woke, DRAINING, not marked (drained by someone else): leave it",
			obs: obs(0, 2, 0, full(0), func() Runner { r := full(1); r.Status = StatusDraining; return r }())},
		{name: "woke, DRAINING, marked, not connected yet: wait",
			obs: mark(obs(0, 2, 0, full(0), unconnected(1, StatusDraining)), 1)},
		{name: "woke, ACTIVE, marked: clear the stale mark",
			obs: mark(obs(0, 2, 0, full(0), full(1)), 1), wantClear: []string{claimName(1)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := Decide(cfg(), tt.obs, State{})
			if !reflect.DeepEqual(d.StatusChanges, tt.want) {
				t.Errorf("status changes = %+v, want %+v", d.StatusChanges, tt.want)
			}
			if !reflect.DeepEqual(d.ClearDrainMarks, tt.wantClear) {
				t.Errorf("clear marks = %v, want %v", d.ClearDrainMarks, tt.wantClear)
			}
		})
	}
}

// The runner being parked this loop is not reactivated.
func TestNoReactivateWhileParking(t *testing.T) {
	r := idle(1)
	r.Status = StatusDraining
	o := obs(time.Hour, 2, 0, idle(0), r)
	o.Claims[1] = Claim{Name: claimName(1), DrainedByScaler: true}
	d := Decide(cfg(), o, State{IdleSince: map[int]time.Time{1: t0}})
	if d.Scale != ScaleIn || len(d.StatusChanges) != 0 {
		t.Errorf("got %v changes=%+v", d.Scale, d.StatusChanges)
	}
}

func TestIdleTimerTracksTopOnly(t *testing.T) {
	d := Decide(cfg(), obs(0, 3, 0, idle(0), idle(1), full(2)), State{IdleSince: map[int]time.Time{1: t0.Add(-time.Hour)}})
	if len(d.State.IdleSince) != 0 {
		t.Errorf("stale idle timers kept: %v", d.State.IdleSince)
	}
	d = Decide(cfg(), obs(0, 3, 0, idle(0), idle(1), idle(2)), State{})
	if !d.State.IdleSince[2].Equal(t0) || len(d.State.IdleSince) != 1 {
		t.Errorf("idle timer for top not started: %v", d.State.IdleSince)
	}
}

func TestPlanReap(t *testing.T) {
	ttl := 12 * time.Hour
	now := t0.Add(ttl)
	cl := map[int]Claim{
		0: {Name: "s-0", Stamped: true, ParkedAt: t0},                  // awake: clear
		1: {Name: "s-1"},                                               // awake: nothing
		2: {Name: "s-2"},                                               // parked: stamp
		3: {Name: "s-3", Stamped: true},                                // unreadable stamp: restamp
		4: {Name: "s-4", Stamped: true, ParkedAt: now.Add(-time.Hour)}, // within TTL
		5: {Name: "s-5", Stamped: true, ParkedAt: t0},                  // past TTL, no Job: start
		6: {Name: "s-6", Stamped: true, ParkedAt: t0},                  // Job running
		7: {Name: "s-7", Stamped: true, ParkedAt: t0},                  // Job done: cleanup
		8: {Name: "s-8", Stamped: true, ParkedAt: t0},                  // Job failed: retry
	}
	jobs := map[int]JobState{6: JobRunning, 7: JobSucceeded, 8: JobFailed}
	got := PlanReap(cl, jobs, 2, now, ttl)
	want := []ReapAction{
		{Kind: ReapClearStamp, Ordinal: 0, Claim: "s-0"},
		{Kind: ReapStamp, Ordinal: 2, Claim: "s-2"},
		{Kind: ReapStamp, Ordinal: 3, Claim: "s-3"},
		{Kind: ReapStartJob, Ordinal: 5, Claim: "s-5", ParkedFor: ttl},
		{Kind: ReapCleanup, Ordinal: 7, Claim: "s-7", ParkedFor: ttl},
		{Kind: ReapRetry, Ordinal: 8, Claim: "s-8", ParkedFor: ttl},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PlanReap =\n%+v\nwant\n%+v", got, want)
	}
}

// Reaping uses the replicas after this loop's scale in.
func TestDecideStampsJustParked(t *testing.T) {
	o := obs(time.Hour, 2, 0, idle(0), idle(1))
	d := Decide(cfg(), o, State{IdleSince: map[int]time.Time{1: t0}})
	want := []ReapAction{{Kind: ReapStamp, Ordinal: 1, Claim: claimName(1)}}
	if d.Scale != ScaleIn || !reflect.DeepEqual(d.Reap, want) {
		t.Errorf("got %v reap=%+v", d.Scale, d.Reap)
	}
}

func TestStateRoundTrip(t *testing.T) {
	s := State{
		IdleSince:        map[int]time.Time{2: t0},
		StuckSince:       t0.Add(time.Minute),
		UnconnectedSince: map[int]time.Time{0: t0, 3: t0.Add(time.Second)},
	}
	ann := map[string]string{}
	for k, v := range EncodeState(s) {
		if v != nil {
			ann[k] = *v
		}
	}
	if ann[AnnotationIdleSince] != `{"2":1700000000}` {
		t.Errorf("idle annotation = %q", ann[AnnotationIdleSince])
	}
	if got := DecodeState(ann); !reflect.DeepEqual(got, s) {
		t.Errorf("round trip = %+v, want %+v", got, s)
	}
	empty := EncodeState(State{})
	for _, k := range StateAnnotations {
		if v, ok := empty[k]; !ok || v != nil {
			t.Errorf("empty state should remove %s", k)
		}
	}
	bad := DecodeState(map[string]string{AnnotationIdleSince: "{", AnnotationStuckSince: "x",
		AnnotationUnconnectedSince: `{"a":1,"-1":2,"4":0,"5":7}`})
	if len(bad.IdleSince) != 0 || !bad.StuckSince.IsZero() || len(bad.UnconnectedSince) != 1 {
		t.Errorf("bad annotations decoded to %+v", bad)
	}
}

// A woken runner the scaler reactivates this loop counts as ACTIVE: an
// idle one takes the queued workflow, so no other runner is woken.
func TestReactivatedRunnerCountsAsActive(t *testing.T) {
	r := idle(1)
	r.Status = StatusDraining
	o := obs(0, 2, 1, full(0), r)
	o.Claims[1] = Claim{Name: claimName(1), DrainedByScaler: true}
	d := Decide(cfg(), o, State{})
	if d.Scale != ScaleNone || len(d.StatusChanges) != 1 || d.StatusChanges[0].Status != StatusActive {
		t.Errorf("got %v (%s) changes=%+v", d.Scale, d.Why, d.StatusChanges)
	}
	if o.Runners[1].Status != StatusDraining {
		t.Error("Decide modified the observation")
	}
	// Drained by someone else: it stays DRAINING and doesn't count.
	o.Claims[1] = Claim{Name: claimName(1)}
	if d := Decide(cfg(), o, State{}); d.Scale != ScaleOut {
		t.Errorf("want scale out past a runner drained on purpose, got %v", d.Scale)
	}
}

package decide

import (
	"encoding/json"
	"strconv"
	"time"
)

// Annotations on the StatefulSet that keep the scaler's timers across
// restarts and leader changes. Values are Unix epochs; per-ordinal timers
// are JSON objects keyed by ordinal.
const (
	AnnotationIdleSince        = "sg-runner.stackguardian.io/scaler-idle-since"
	AnnotationStuckSince       = "sg-runner.stackguardian.io/scaler-stuck-since"
	AnnotationUnconnectedSince = "sg-runner.stackguardian.io/scaler-unconnected-since"
)

// StateAnnotations lists every annotation the state is stored in.
var StateAnnotations = []string{AnnotationIdleSince, AnnotationStuckSince, AnnotationUnconnectedSince}

// DecodeState reads the timers from StatefulSet annotations. Unreadable
// values are dropped: a timer that restarts is the safe failure.
func DecodeState(annotations map[string]string) State {
	s := State{IdleSince: decodeTimers(annotations[AnnotationIdleSince]),
		UnconnectedSince: decodeTimers(annotations[AnnotationUnconnectedSince])}
	if v, err := strconv.ParseInt(annotations[AnnotationStuckSince], 10, 64); err == nil && v > 0 {
		s.StuckSince = time.Unix(v, 0)
	}
	return s
}

// EncodeState renders the timers as annotation values; an empty timer maps
// to nil (remove the annotation).
func EncodeState(s State) map[string]*string {
	out := map[string]*string{
		AnnotationIdleSince:        encodeTimers(s.IdleSince),
		AnnotationUnconnectedSince: encodeTimers(s.UnconnectedSince),
		AnnotationStuckSince:       nil,
	}
	if !s.StuckSince.IsZero() {
		v := strconv.FormatInt(s.StuckSince.Unix(), 10)
		out[AnnotationStuckSince] = &v
	}
	return out
}

func decodeTimers(raw string) map[int]time.Time {
	out := map[int]time.Time{}
	if raw == "" {
		return out
	}
	var m map[string]int64
	if json.Unmarshal([]byte(raw), &m) != nil {
		return out
	}
	for k, v := range m {
		n, err := strconv.Atoi(k)
		if err != nil || n < 0 || v <= 0 {
			continue
		}
		out[n] = time.Unix(v, 0)
	}
	return out
}

func encodeTimers(t map[int]time.Time) *string {
	if len(t) == 0 {
		return nil
	}
	m := make(map[string]int64, len(t))
	for n, at := range t {
		m[strconv.Itoa(n)] = at.Unix()
	}
	b, _ := json.Marshal(m) // map keys are sorted: stable output
	v := string(b)
	return &v
}

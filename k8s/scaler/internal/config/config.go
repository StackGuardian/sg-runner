// Package config reads the scaler's settings from the environment, with the
// names and defaults scaler.sh used.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/StackGuardian/sg-runner/k8s/scaler/internal/decide"
)

const serviceAccountNamespace = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// Config is everything the scaler is told from outside.
type Config struct {
	Rules             decide.Config
	Interval          time.Duration
	StatefulSet       string
	Image             string
	CredentialsSecret string
	CredentialsDir    string
	Namespace         string
	MetricsAddr       string
	LeaderElect       bool
	// MinRaised reports a SCALER_MIN below 1 (MinGiven) raised to 1.
	MinRaised bool
	MinGiven  int
}

// Load reads the environment through getenv (os.Getenv when nil).
func Load(getenv func(string) string) (Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	var errs []string
	str := func(key, def string) string {
		if v := strings.TrimSpace(getenv(key)); v != "" {
			return v
		}
		return def
	}
	num := func(key string, def, lowest int) int {
		raw := str(key, "")
		if raw == "" {
			return def
		}
		v, err := strconv.Atoi(raw)
		if err != nil || v < lowest {
			errs = append(errs, fmt.Sprintf("%s=%q: want an integer >= %d", key, raw, lowest))
			return def
		}
		return v
	}
	secs := func(key string, def, lowest int) time.Duration {
		return time.Duration(num(key, def, lowest)) * time.Second
	}

	c := Config{
		Interval:          secs("SCALER_INTERVAL", 15, 1),
		StatefulSet:       str("SCALER_STATEFULSET", "sg-runner"),
		Image:             str("SCALER_IMAGE", "sg-runner-k8s:dev"),
		CredentialsSecret: str("SCALER_CREDENTIALS_SECRET", "sg-runner-credentials"),
		CredentialsDir:    str("SG_CREDENTIALS_DIR", "/etc/sg-runner/credentials"),
		MetricsAddr:       str("SCALER_METRICS_ADDR", ":9090"),
		Rules: decide.Config{
			Min:           num("SCALER_MIN", 1, -1<<31),
			Max:           num("SCALER_MAX", 10, 1),
			HeadroomPct:   num("SCALER_HEADROOM_PCT", 0, 0),
			IdleAfter:     secs("SCALER_IDLE_SECONDS", 60, 0),
			ParkTTL:       secs("SCALER_PARK_TTL", 43200, 0),
			StuckAfter:    secs("SCALER_STUCK_SECONDS", 180, 0),
			SettleTimeout: secs("SCALER_SETTLE_TIMEOUT", 300, 0),
		},
	}
	if c.Rules.HeadroomPct > 100 {
		errs = append(errs, fmt.Sprintf("SCALER_HEADROOM_PCT=%d: want 0-100", c.Rules.HeadroomPct))
	}
	// SG pauses workflows without an ACTIVE, connected runner.
	if c.Rules.Min < 1 {
		c.MinRaised, c.MinGiven = true, c.Rules.Min
		c.Rules.Min = 1
	}
	if c.Rules.Min > c.Rules.Max {
		errs = append(errs, fmt.Sprintf("SCALER_MIN=%d is above SCALER_MAX=%d", c.Rules.Min, c.Rules.Max))
	}
	switch v := strings.ToLower(str("SCALER_LEADER_ELECT", "true")); v {
	case "true", "1", "yes":
		c.LeaderElect = true
	case "false", "0", "no":
	default:
		errs = append(errs, fmt.Sprintf("SCALER_LEADER_ELECT=%q: want true or false", v))
	}

	c.Namespace = str("POD_NAMESPACE", "")
	if c.Namespace == "" {
		if b, err := os.ReadFile(serviceAccountNamespace); err == nil {
			c.Namespace = strings.TrimSpace(string(b))
		}
	}
	if c.Namespace == "" {
		errs = append(errs, "no namespace: set POD_NAMESPACE")
	}
	if len(errs) > 0 {
		return c, fmt.Errorf("invalid configuration: %s", strings.Join(errs, "; "))
	}
	return c, nil
}

// Package steps is the step broker: it runs each workflow step of the run
// controllers in a runner pod as a pod of its own. See k8s/docs/steps-api.md.
package steps

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
)

// Config is everything the broker is told from outside.
type Config struct {
	SocketPath string
	// WorkspacesDir is the run controllers' workspace root: request paths
	// start with it.
	WorkspacesDir string
	// WorkspaceClaim is the PVC holding WorkspacesDir, and
	// WorkspaceSubPathPrefix the directory inside it ("" for its root).
	WorkspaceClaim         string
	WorkspaceSubPathPrefix string
	// The runner pod the broker runs in (downward API).
	RunnerPodName string
	RunnerPodUID  types.UID
	NodeName      string
	Namespace     string
	// Step pod settings: extra labels, node selector and tolerations.
	StepLabels       map[string]string
	StepNodeSelector map[string]string
	StepTolerations  []corev1.Toleration
	// StepImagePullPolicy overrides every step's pull policy ("" for the
	// automatic one: Always for latest or no tag, else IfNotPresent).
	StepImagePullPolicy corev1.PullPolicy
	// SchedulingTimeout fails a step the scheduler can't place, StartTimeout
	// one whose container hasn't started; FinishedTTL is how long the GC
	// keeps finished steps.
	SchedulingTimeout time.Duration
	StartTimeout      time.Duration
	FinishedTTL       time.Duration
	// FinishedGrace is how long a step's pod stays after a client got its
	// terminal state, for log streams that open late or reconnect.
	FinishedGrace time.Duration
	// DrainedMarker is the file the runner's drain creates when done.
	DrainedMarker string
}

// DefaultDrainedMarker is DRAINED_MARKER's default, also for wait-drained.
const DefaultDrainedMarker = "/var/run/sg-runner-drained"

// LoadConfig reads the environment through getenv (os.Getenv when nil).
func LoadConfig(getenv func(string) string) (Config, error) {
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
	required := func(key string) string {
		v := str(key, "")
		if v == "" {
			errs = append(errs, key+" is required")
		}
		return v
	}
	duration := func(key, def string) time.Duration {
		raw := str(key, def)
		d, err := time.ParseDuration(raw)
		// Only FINISHED_GRACE may be 0 (delete right away).
		if err != nil || d < 0 || d == 0 && key != "FINISHED_GRACE" {
			errs = append(errs, fmt.Sprintf("%s=%q: want a positive Go duration (e.g. 5m)", key, raw))
		}
		return d
	}

	c := Config{
		SocketPath:        str("SOCKET_PATH", "/run/sg-steps/steps.sock"),
		WorkspacesDir:     str("WORKSPACES_DIR", "/var/tmp/workspace"),
		WorkspaceClaim:    required("WORKSPACE_CLAIM"),
		RunnerPodName:     required("RUNNER_POD_NAME"),
		RunnerPodUID:      types.UID(required("RUNNER_POD_UID")),
		NodeName:          required("NODE_NAME"),
		Namespace:         required("NAMESPACE"),
		SchedulingTimeout: duration("SCHEDULING_TIMEOUT", "5m"),
		StartTimeout:      duration("START_TIMEOUT", "30m"),
		FinishedTTL:       duration("FINISHED_TTL", "10m"),
		FinishedGrace:     duration("FINISHED_GRACE", "10s"),
		DrainedMarker:     str("DRAINED_MARKER", DefaultDrainedMarker),
	}

	if !path.IsAbs(c.WorkspacesDir) {
		errs = append(errs, fmt.Sprintf("WORKSPACES_DIR=%q: want an absolute path", c.WorkspacesDir))
	}
	c.WorkspacesDir = path.Clean(c.WorkspacesDir)
	if c.WorkspacesDir == "/" {
		errs = append(errs, "WORKSPACES_DIR: the filesystem root is not a workspace root")
	}
	if p := str("WORKSPACE_SUBPATH_PREFIX", ""); p != "" {
		if path.IsAbs(p) || hasDotDot(p) {
			errs = append(errs, fmt.Sprintf("WORKSPACE_SUBPATH_PREFIX=%q: want a relative path without ..", p))
		}
		if p = path.Clean(p); p != "." {
			c.WorkspaceSubPathPrefix = p
		}
	}
	if c.WorkspaceClaim != "" {
		for _, msg := range validation.IsDNS1123Subdomain(c.WorkspaceClaim) {
			errs = append(errs, fmt.Sprintf("WORKSPACE_CLAIM=%q: %s", c.WorkspaceClaim, msg))
		}
	}
	// Step pods and the runner label carry the name: it has to be a label.
	if c.RunnerPodName != "" {
		for _, msg := range validation.IsDNS1123Label(c.RunnerPodName) {
			errs = append(errs, fmt.Sprintf("RUNNER_POD_NAME=%q: %s", c.RunnerPodName, msg))
		}
	}

	if err := strictJSON(str("STEP_LABELS", "{}"), &c.StepLabels); err != nil {
		errs = append(errs, fmt.Sprintf("STEP_LABELS: want a JSON object of strings: %v", err))
	}
	for k, v := range c.StepLabels {
		for _, msg := range append(validation.IsQualifiedName(k), validation.IsValidLabelValue(v)...) {
			errs = append(errs, fmt.Sprintf("STEP_LABELS: label %q=%q: %s", k, v, msg))
		}
	}
	if err := strictJSON(str("STEP_NODE_SELECTOR", "{}"), &c.StepNodeSelector); err != nil {
		errs = append(errs, fmt.Sprintf("STEP_NODE_SELECTOR: want a JSON object of strings: %v", err))
	}
	if err := strictJSON(str("STEP_TOLERATIONS", "[]"), &c.StepTolerations); err != nil {
		errs = append(errs, fmt.Sprintf("STEP_TOLERATIONS: want a JSON array of tolerations: %v", err))
	}

	switch p := corev1.PullPolicy(str("STEP_IMAGE_PULL_POLICY", "")); p {
	case "", corev1.PullAlways, corev1.PullIfNotPresent, corev1.PullNever:
		c.StepImagePullPolicy = p
	default:
		errs = append(errs, fmt.Sprintf("STEP_IMAGE_PULL_POLICY=%q: want Always, IfNotPresent or Never", p))
	}

	if len(errs) > 0 {
		return c, fmt.Errorf("invalid configuration: %s", strings.Join(errs, "; "))
	}
	return c, nil
}

// strictJSON decodes raw into v, rejecting unknown fields and trailing data.
func strictJSON(raw string, v any) error {
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing data")
	}
	return nil
}

// hasDotDot reports a ".." segment in a slash-separated path.
func hasDotDot(p string) bool {
	for _, s := range strings.Split(p, "/") {
		if s == ".." {
			return true
		}
	}
	return false
}

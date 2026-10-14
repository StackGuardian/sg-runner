package steps

import (
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// required is the downward API and claim every configuration needs.
func required(extra map[string]string) map[string]string {
	m := map[string]string{
		"WORKSPACE_CLAIM": "sg-runner-0-workspace", "RUNNER_POD_NAME": "sg-runner-0",
		"RUNNER_POD_UID": "uid-0", "NODE_NAME": "node-a", "NAMESPACE": "sg",
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func TestConfigDefaults(t *testing.T) {
	c, err := LoadConfig(env(required(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if c.SocketPath != "/run/sg-steps/steps.sock" || c.WorkspacesDir != "/var/tmp/workspace" ||
		c.WorkspaceClaim != "sg-runner-0-workspace" || c.WorkspaceSubPathPrefix != "" ||
		c.RunnerPodName != "sg-runner-0" || c.RunnerPodUID != types.UID("uid-0") || c.NodeName != "node-a" ||
		c.Namespace != "sg" || len(c.StepLabels) != 0 || len(c.StepNodeSelector) != 0 || len(c.StepTolerations) != 0 ||
		c.SchedulingTimeout != 5*time.Minute || c.StartTimeout != 30*time.Minute || c.FinishedTTL != time.Hour ||
		c.DrainedMarker != "/var/run/sg-runner-drained" || c.BrokerImage != "" || c.BrokerImagePullPolicy != "" ||
		c.BrokerImagePullSecrets != nil || c.StepImagePullPolicy != "" {
		t.Errorf("defaults %+v", c)
	}
}

func TestConfigOverrides(t *testing.T) {
	c, err := LoadConfig(env(required(map[string]string{
		"SOCKET_PATH": "/s/x.sock", "WORKSPACES_DIR": "/w/", "WORKSPACE_SUBPATH_PREFIX": "runners/r0/",
		"STEP_LABELS":        `{"app.kubernetes.io/name":"sg-runner"}`,
		"STEP_NODE_SELECTOR": `{"pool":"steps"}`,
		"STEP_TOLERATIONS":   `[{"key":"dedicated","operator":"Exists","effect":"NoSchedule"}]`,
		"SCHEDULING_TIMEOUT": "90s", "START_TIMEOUT": "1h", "FINISHED_TTL": "1m", "DRAINED_MARKER": "/d",
		"STEP_IMAGE_PULL_POLICY": "Never", "BROKER_IMAGE": "reg/scaler:1", "BROKER_IMAGE_PULL_POLICY": "Always",
		"BROKER_IMAGE_PULL_SECRETS": "regcred, other ,",
	})))
	if err != nil {
		t.Fatal(err)
	}
	if c.SocketPath != "/s/x.sock" || c.WorkspacesDir != "/w" || c.WorkspaceSubPathPrefix != "runners/r0" ||
		c.StepLabels["app.kubernetes.io/name"] != "sg-runner" || c.StepNodeSelector["pool"] != "steps" ||
		len(c.StepTolerations) != 1 || c.StepTolerations[0].Key != "dedicated" ||
		c.SchedulingTimeout != 90*time.Second || c.StartTimeout != time.Hour || c.FinishedTTL != time.Minute ||
		c.DrainedMarker != "/d" || c.StepImagePullPolicy != corev1.PullNever || c.BrokerImage != "reg/scaler:1" ||
		c.BrokerImagePullPolicy != corev1.PullAlways || strings.Join(c.BrokerImagePullSecrets, ",") != "regcred,other" {
		t.Errorf("overrides %+v", c)
	}
}

func TestConfigInvalid(t *testing.T) {
	for name, m := range map[string]map[string]string{
		"no claim":            {"WORKSPACE_CLAIM": " "},
		"no runner pod":       {"RUNNER_POD_NAME": ""},
		"no uid":              {"RUNNER_POD_UID": ""},
		"no node":             {"NODE_NAME": ""},
		"no namespace":        {"NAMESPACE": ""},
		"runner not a label":  {"RUNNER_POD_NAME": "Runner_0"},
		"claim not a name":    {"WORKSPACE_CLAIM": "Bad Claim"},
		"relative workspaces": {"WORKSPACES_DIR": "var/tmp"},
		"root workspaces":     {"WORKSPACES_DIR": "/"},
		"absolute prefix":     {"WORKSPACE_SUBPATH_PREFIX": "/x"},
		"dotdot prefix":       {"WORKSPACE_SUBPATH_PREFIX": "a/../../b"},
		"bad duration":        {"START_TIMEOUT": "30"},
		"zero duration":       {"FINISHED_TTL": "0s"},
		"labels not json":     {"STEP_LABELS": "a=b"},
		"bad label":           {"STEP_LABELS": `{"a":"not ok"}`},
		"selector trailing":   {"STEP_NODE_SELECTOR": `{"a":"b"} {}`},
		"toleration unknown":  {"STEP_TOLERATIONS": `[{"keyy":"a"}]`},
		"bad pull policy":     {"STEP_IMAGE_PULL_POLICY": "never"},
		"zero start timeout":  {"START_TIMEOUT": "0s"},
		"bad broker policy":   {"BROKER_IMAGE_PULL_POLICY": "sometimes"},
		"bad pull secret":     {"BROKER_IMAGE_PULL_SECRETS": "Not_A_Name"},
	} {
		if _, err := LoadConfig(env(required(m))); err == nil || !strings.Contains(err.Error(), "invalid configuration") {
			t.Errorf("%s: want an error, got %v", name, err)
		}
	}
}

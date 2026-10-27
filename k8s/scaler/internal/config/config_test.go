package config

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDefaults(t *testing.T) {
	c, err := Load(env(map[string]string{"POD_NAMESPACE": "sg-runner"}))
	if err != nil {
		t.Fatal(err)
	}
	r := c.Rules
	if c.Interval != 15*time.Second || r.Min != 1 || r.Max != 10 || r.HeadroomPct != 0 ||
		r.IdleAfter != 60*time.Second || r.ParkTTL != 43200*time.Second || r.StuckAfter != 180*time.Second ||
		r.SettleTimeout != 300*time.Second || c.StatefulSet != "sg-runner" || c.Image != "sg-runner-k8s:dev" ||
		c.CredentialsSecret != "sg-runner-credentials" || c.ConfigMap != "sg-runner-config" ||
		c.CredentialsDir != "/etc/sg-runner/credentials" ||
		c.MetricsAddr != ":9090" || !c.LeaderElect || c.Namespace != "sg-runner" || c.MinRaised ||
		!c.Nudge || c.NudgeImage != "registry.k8s.io/pause:3.10" || c.NudgeCooldown != 180*time.Second {
		t.Errorf("defaults %+v", c)
	}
}

func TestOverrides(t *testing.T) {
	c, err := Load(env(map[string]string{
		"POD_NAMESPACE": "ns", "SCALER_INTERVAL": "5", "SCALER_MIN": "0", "SCALER_MAX": "3",
		"SCALER_HEADROOM_PCT": "20", "SCALER_LEADER_ELECT": "false", "SG_CREDENTIALS_DIR": "/c",
		"SCALER_STATEFULSET": "r", "SCALER_IMAGE": "i:1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Interval != 5*time.Second || c.Rules.Min != 1 || !c.MinRaised || c.MinGiven != 0 || c.Rules.Max != 3 ||
		c.Rules.HeadroomPct != 20 || c.LeaderElect || c.CredentialsDir != "/c" || c.StatefulSet != "r" || c.Image != "i:1" {
		t.Errorf("overrides %+v", c)
	}
}

func TestInvalid(t *testing.T) {
	for _, m := range []map[string]string{
		{"SCALER_MAX": "x"},
		{"SCALER_MAX": "0"},
		{"SCALER_INTERVAL": "0"},
		{"SCALER_HEADROOM_PCT": "101"},
		{"SCALER_MIN": "5", "SCALER_MAX": "2"},
		{"SCALER_LEADER_ELECT": "maybe"},
	} {
		m["POD_NAMESPACE"] = "ns"
		if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), "invalid configuration") {
			t.Errorf("%v: want an error, got %v", m, err)
		}
	}
}

func TestReapPod(t *testing.T) {
	c, err := Load(env(map[string]string{
		"POD_NAMESPACE":                  "ns",
		"SCALER_REAP_POD_LABELS":         `{"app.kubernetes.io/part-of":"sg-runner","np":"egress"}`,
		"SCALER_REAP_IMAGE_PULL_SECRETS": "regcred, other ,",
		"SCALER_REAP_NODE_SELECTOR":      `{"kubernetes.io/os":"linux"}`,
		"SCALER_REAP_TOLERATIONS":        `[{"key":"dedicated","operator":"Equal","value":"runners","effect":"NoSchedule"}]`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	o := c.ReapPod
	if o.Labels["np"] != "egress" || len(o.Labels) != 2 || strings.Join(o.ImagePullSecrets, ",") != "regcred,other" ||
		o.NodeSelector["kubernetes.io/os"] != "linux" || len(o.Tolerations) != 1 || o.Tolerations[0].Value != "runners" {
		t.Errorf("reap pod %+v", o)
	}
	for k, v := range map[string]string{
		"SCALER_REAP_POD_LABELS":         `["a"]`,
		"SCALER_REAP_IMAGE_PULL_SECRETS": "Bad_Name",
		"SCALER_REAP_NODE_SELECTOR":      `{"a":1}`,
		"SCALER_REAP_TOLERATIONS":        `[{"keyy":"x"}]`,
	} {
		_, err := Load(env(map[string]string{"POD_NAMESPACE": "ns", k: v}))
		if err == nil || !strings.Contains(err.Error(), k) {
			t.Errorf("%s=%s: want an error naming it, got %v", k, v, err)
		}
	}
	if _, err := Load(env(map[string]string{"POD_NAMESPACE": "ns", "SCALER_REAP_POD_LABELS": `{"bad key!":"x"}`})); err == nil {
		t.Error("want an invalid label key rejected")
	}
}

// The Helm chart renders unset values as "", {} and [].
func TestReapPodChartDefaults(t *testing.T) {
	c, err := Load(env(map[string]string{
		"POD_NAMESPACE":                  "ns",
		"SCALER_REAP_POD_LABELS":         `{}`,
		"SCALER_REAP_IMAGE_PULL_SECRETS": "",
		"SCALER_REAP_NODE_SELECTOR":      `{}`,
		"SCALER_REAP_TOLERATIONS":        `[]`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	o := c.ReapPod
	if len(o.Labels) != 0 || len(o.ImagePullSecrets) != 0 || len(o.NodeSelector) != 0 || len(o.Tolerations) != 0 {
		t.Errorf("want no reap pod settings, got %+v", o)
	}
}

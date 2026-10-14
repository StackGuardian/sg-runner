package steps

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	testOrg = "/orgs/example-org"
	testRun = "/wfgrps/x/wfs/y/wfruns/z"
	testWS  = "/var/tmp/workspace/orgs/example-org/wfgrps/x/wfs/y/wfruns/z"
	testID  = "sg-runner-0-s-7f3k9q2x"
)

func testConfig() Config {
	return Config{
		SocketPath: "/run/sg-steps/steps.sock", WorkspacesDir: "/var/tmp/workspace",
		WorkspaceClaim: "sg-runner-0-workspace", RunnerPodName: "sg-runner-0", RunnerPodUID: "uid-0",
		NodeName: "node-a", Namespace: "sg",
		StepLabels:        map[string]string{"app.kubernetes.io/name": "sg-runner", LabelComponent: "overridden"},
		StepNodeSelector:  map[string]string{"pool": "steps"},
		StepTolerations:   []corev1.Toleration{{Key: "dedicated", Operator: corev1.TolerationOpExists}},
		SchedulingTimeout: 5 * time.Minute, StartTimeout: 30 * time.Minute, FinishedTTL: time.Hour,
		BrokerImage: "reg.example.com/sg-runner-scaler:1", BrokerImagePullPolicy: corev1.PullIfNotPresent,
		BrokerImagePullSecrets: []string{"regcred"},
		DrainedMarker:          "/var/run/sg-runner-drained",
	}
}

func testRequest() Request {
	return Request{
		Name: "example-org-plan-0", Org: testOrg, Run: testRun, StepIdx: 2,
		Image: "registry.example.com/team/image:1.2",
		Args:  []string{"sh", "-c", "echo $(HOME) $HOME"},
		Env:   map[string]string{"SG_WORKFLOW_RUN_PAYLOAD": "{}", "a.b-c_D": "x"},
		Mounts: []Mount{
			{Source: testWS + "/shared-workspace", Target: "/mnt/sg_workspace"},
			{Source: testWS + "/artifacts/", Target: "/mnt/artifacts/", ReadOnly: true},
		},
		CPUShares: 512, MemoryMiB: 1024, TimeoutSeconds: 2100,
	}
}

func TestValidate(t *testing.T) {
	cfg := testConfig()
	cases := map[string]struct {
		edit   func(*Request)
		reason string
	}{
		"valid":                 {func(r *Request) {}, ""},
		"no mounts or env":      {func(r *Request) { r.Mounts, r.Env, r.Args = nil, nil, nil }, ""},
		"no org":                {func(r *Request) { r.Org = "" }, ReasonInvalidRequest},
		"no run":                {func(r *Request) { r.Run = "" }, ReasonInvalidRequest},
		"dotdot run":            {func(r *Request) { r.Run = "/../../../etc" }, ReasonInvalidRequest},
		"no image":              {func(r *Request) { r.Image = "" }, ReasonInvalidRequest},
		"image with space":      {func(r *Request) { r.Image = "a b" }, ReasonInvalidRequest},
		"negative cpu":          {func(r *Request) { r.CPUShares = -1 }, ReasonInvalidRequest},
		"negative timeout":      {func(r *Request) { r.TimeoutSeconds = -1 }, ReasonInvalidRequest},
		"auth without registry": {func(r *Request) { r.RegistryAuth = &RegistryAuth{Username: "u"} }, ReasonInvalidRequest},
		"bad env key":           {func(r *Request) { r.Env["A=B"] = "" }, ReasonInvalidEnv},
		"empty env key":         {func(r *Request) { r.Env[""] = "" }, ReasonInvalidEnv},
		"long env key":          {func(r *Request) { r.Env[strings.Repeat("a", 254)] = "" }, ReasonInvalidEnv},
		"env too large": {func(r *Request) {
			r.Env = map[string]string{"A": strings.Repeat("x", MaxEnvBytes)}
		}, ReasonEnvTooLarge},
		"env at the limit": {func(r *Request) {
			r.Env = map[string]string{"A": strings.Repeat("x", MaxEnvBytes-1)}
		}, ""},
		"mount the run dir":       {func(r *Request) { r.Mounts[0].Source = testWS }, ReasonInvalidMount},
		"mount the run dir slash": {func(r *Request) { r.Mounts[0].Source = testWS + "/" }, ReasonInvalidMount},
		"mount the root":          {func(r *Request) { r.Mounts[0].Source = "/var/tmp/workspace" }, ReasonInvalidMount},
		"mount the socket dir":    {func(r *Request) { r.Mounts[0].Source = "/var/tmp/workspace/.sg-runner" }, ReasonInvalidMount},
		"mount another run": {func(r *Request) {
			r.Mounts[0].Source = "/var/tmp/workspace/orgs/example-org/wfgrps/x/wfs/y/wfruns/zz/shared"
		}, ReasonInvalidMount},
		"mount with dotdot": {func(r *Request) { r.Mounts[0].Source = testWS + "/a/../../z/a" }, ReasonInvalidMount},
		"mount relative":    {func(r *Request) { r.Mounts[0].Source = "orgs/example-org" }, ReasonInvalidMount},
		"mount elsewhere":   {func(r *Request) { r.Mounts[0].Source = "/etc" }, ReasonInvalidMount},
		"target relative":   {func(r *Request) { r.Mounts[0].Target = "mnt" }, ReasonInvalidMount},
		"target root":       {func(r *Request) { r.Mounts[0].Target = "/" }, ReasonInvalidMount},
		"target twice":      {func(r *Request) { r.Mounts[1].Target = "/mnt/sg_workspace/" }, ReasonInvalidMount},
	}
	for name, c := range cases {
		r := testRequest()
		c.edit(&r)
		err := cfg.Validate(&r)
		if c.reason == "" {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		var e *Error
		if !errors.As(err, &e) || e.Reason != c.reason || e.Status != 400 {
			t.Errorf("%s: got %v, want %s", name, err, c.reason)
		}
	}
}

func TestNewID(t *testing.T) {
	cfg := testConfig()
	// 252 and up are skipped; the rest map onto a-z0-9.
	random := bytes.NewReader(append([]byte{255, 0, 25, 26, 35, 36, 252, 71, 1, 2}, make([]byte, 22)...))
	id, err := cfg.NewID(random)
	if err != nil {
		t.Fatal(err)
	}
	if id != "sg-runner-0-s-az09a9bc" {
		t.Errorf("NewID = %q", id)
	}
	if !cfg.idRE().MatchString(id) {
		t.Errorf("%q doesn't match the id pattern", id)
	}
	if _, err := cfg.NewID(bytes.NewReader([]byte{1, 2})); err == nil {
		t.Error("want an error from a short random source")
	}
}

func TestIDPattern(t *testing.T) {
	cfg := testConfig()
	re := cfg.idRE()
	for id, want := range map[string]bool{
		testID:                       true,
		"sg-runner-0-s-7f3k9q2":      false,
		"sg-runner-0-s-7F3K9Q2X":     false,
		"sg-runner-1-s-7f3k9q2x":     false,
		"sg-runner-0":                false,
		"x-sg-runner-0-s-7f3k9q2x":   false,
		"sg-runner-0-s-7f3k9q2x-env": false,
	} {
		if re.MatchString(id) != want {
			t.Errorf("%q: match = %v, want %v", id, !want, want)
		}
	}
}

func TestRunLabel(t *testing.T) {
	short := RunLabel(testOrg, testRun)
	if !strings.HasPrefix(short, "wfgrps-x-wfs-y-wfruns-z-") || len(short) != len("wfgrps-x-wfs-y-wfruns-z-")+8 {
		t.Errorf("RunLabel = %q", short)
	}
	if RunLabel("/orgs/other", testRun) == short {
		t.Error("the same run of two orgs got the same label")
	}
	long := RunLabel(testOrg, "/wfgrps/"+strings.Repeat("g", 80)+"/wfs/y/wfruns/z")
	for _, v := range []string{short, long, RunLabel(testOrg, "/"), RunLabel(testOrg, "/a/"+strings.Repeat("-", 60))} {
		if msgs := validation.IsValidLabelValue(v); len(msgs) > 0 || v == "" {
			t.Errorf("RunLabel %q: %v", v, msgs)
		}
	}
	if len(long) != 63 {
		t.Errorf("long RunLabel is %d characters: %q", len(long), long)
	}
}

func TestPullPolicy(t *testing.T) {
	for image, want := range map[string]corev1.PullPolicy{
		"ubuntu":                                      corev1.PullAlways,
		"ubuntu:latest":                               corev1.PullAlways,
		"ubuntu:24.04":                                corev1.PullIfNotPresent,
		"localhost:5000/team/img":                     corev1.PullAlways,
		"localhost:5000/team/img:1":                   corev1.PullIfNotPresent,
		"localhost:5000/team/img:latest":              corev1.PullAlways,
		"123.dkr.ecr.eu-central-1.amazonaws.com/x:v2": corev1.PullIfNotPresent,
		"ubuntu@sha256:abcd":                          corev1.PullIfNotPresent,
		"ubuntu:latest@sha256:abcd":                   corev1.PullIfNotPresent,
	} {
		if got := PullPolicy(image); got != want {
			t.Errorf("PullPolicy(%q) = %s, want %s", image, got, want)
		}
	}
}

func TestCPURequest(t *testing.T) {
	for shares, want := range map[int64]string{0: "1m", 1: "1m", 2: "2m", 512: "500m", 1024: "1", 1536: "1500m", 100: "98m", 4096: "4"} {
		q := CPURequest(shares)
		if got := q.String(); got != want {
			t.Errorf("CPURequest(%d) = %s, want %s", shares, got, want)
		}
	}
}

func TestSecrets(t *testing.T) {
	cfg := testConfig()
	r := testRequest()
	env := cfg.EnvSecret(testID, &r)
	if env.Name != testID+"-env" || env.Namespace != "sg" || env.Type != corev1.SecretTypeOpaque ||
		string(env.Data["SG_WORKFLOW_RUN_PAYLOAD"]) != "{}" || string(env.Data["a.b-c_D"]) != "x" || len(env.Data) != 2 {
		t.Errorf("env Secret %+v", env)
	}
	checkOwnedAndLabeled(t, env.ObjectMeta)

	if s, err := cfg.PullSecret(testID, &r); s != nil || err != nil {
		t.Errorf("PullSecret without registryAuth = %v, %v", s, err)
	}
	r.RegistryAuth = &RegistryAuth{Registry: "https://index.docker.io/v1/", Username: "u", Password: "p:w"}
	pull, err := cfg.PullSecret(testID, &r)
	if err != nil {
		t.Fatal(err)
	}
	if pull.Name != testID+"-pull" || pull.Type != corev1.SecretTypeDockerConfigJson {
		t.Errorf("pull Secret %+v", pull)
	}
	checkOwnedAndLabeled(t, pull.ObjectMeta)
	var dc struct {
		Auths map[string]struct{ Username, Password, Auth string }
	}
	if err := json.Unmarshal(pull.Data[corev1.DockerConfigJsonKey], &dc); err != nil {
		t.Fatal(err)
	}
	a := dc.Auths["https://index.docker.io/v1/"]
	if a.Username != "u" || a.Password != "p:w" || a.Auth != base64.StdEncoding.EncodeToString([]byte("u:p:w")) || len(dc.Auths) != 1 {
		t.Errorf("dockerconfigjson %s", pull.Data[corev1.DockerConfigJsonKey])
	}
}

func checkOwnedAndLabeled(t *testing.T, m metav1.ObjectMeta) {
	t.Helper()
	want := []metav1.OwnerReference{{APIVersion: "v1", Kind: "Pod", Name: "sg-runner-0", UID: "uid-0"}}
	if !reflect.DeepEqual(m.OwnerReferences, want) {
		t.Errorf("%s: ownerReferences %+v", m.Name, m.OwnerReferences)
	}
	if m.Labels[LabelComponent] != ComponentStep || m.Labels[LabelRunner] != "sg-runner-0" ||
		m.Labels[LabelRun] != RunLabel(testOrg, testRun) || m.Labels["app.kubernetes.io/name"] != "sg-runner" {
		t.Errorf("%s: labels %v", m.Name, m.Labels)
	}
}

func TestPod(t *testing.T) {
	cfg := testConfig()
	cfg.WorkspaceSubPathPrefix = "shared/r0"
	r := testRequest()
	p := cfg.Pod(testID, &r, true, Wrap{Reason: "test"})

	if p.Name != testID || p.Namespace != "sg" {
		t.Errorf("name %s/%s", p.Namespace, p.Name)
	}
	checkOwnedAndLabeled(t, p.ObjectMeta)
	if want := map[string]string{AnnotationOrg: testOrg, AnnotationRun: testRun, AnnotationStepIdx: "2",
		AnnotationName: "example-org-plan-0", AnnotationWrapped: "false", AnnotationNotWrappedReason: "test"}; !reflect.DeepEqual(p.Annotations, want) {
		t.Errorf("annotations %v", p.Annotations)
	}

	s := p.Spec
	if s.RestartPolicy != corev1.RestartPolicyNever || *s.TerminationGracePeriodSeconds != 30 ||
		*s.ActiveDeadlineSeconds != 2100+1800+300 || *s.AutomountServiceAccountToken || *s.EnableServiceLinks ||
		s.SecurityContext.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault ||
		!reflect.DeepEqual(s.NodeSelector, cfg.StepNodeSelector) || !reflect.DeepEqual(s.Tolerations, cfg.StepTolerations) ||
		!reflect.DeepEqual(s.ImagePullSecrets, []corev1.LocalObjectReference{{Name: testID + "-pull"}}) {
		t.Errorf("pod spec %+v", s)
	}
	terms := s.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
	if want := []corev1.NodeSelectorTerm{{MatchFields: []corev1.NodeSelectorRequirement{{
		Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: []string{"node-a"}}}}}; !reflect.DeepEqual(terms, want) {
		t.Errorf("node affinity %+v", terms)
	}
	if want := []corev1.Volume{{Name: "workspace", VolumeSource: corev1.VolumeSource{
		PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "sg-runner-0-workspace"}}}}; !reflect.DeepEqual(s.Volumes, want) {
		t.Errorf("volumes %+v", s.Volumes)
	}

	if len(s.Containers) != 1 {
		t.Fatalf("%d containers", len(s.Containers))
	}
	c := s.Containers[0]
	if c.Name != "step" || c.Image != r.Image || c.ImagePullPolicy != corev1.PullIfNotPresent || c.Command != nil ||
		s.InitContainers != nil || c.TerminationMessagePath != "/dev/termination-log" ||
		!reflect.DeepEqual(c.Args, []string{"sh", "-c", "echo $$(HOME) $$HOME"}) ||
		*c.SecurityContext.Privileged || c.SecurityContext.Capabilities != nil {
		t.Errorf("container %+v", c)
	}
	if want := []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{
		LocalObjectReference: corev1.LocalObjectReference{Name: testID + "-env"}}}}; !reflect.DeepEqual(c.EnvFrom, want) {
		t.Errorf("envFrom %+v", c.EnvFrom)
	}
	if req := c.Resources.Requests; req.Cpu().String() != "500m" || req.Memory().String() != "1Gi" ||
		c.Resources.Limits.Memory().String() != "1Gi" || c.Resources.Limits.Cpu().String() != "0" {
		t.Errorf("resources %+v", c.Resources)
	}
	wantMounts := []corev1.VolumeMount{
		{Name: "workspace", MountPath: "/mnt/sg_workspace", SubPath: "shared/r0/orgs/example-org/wfgrps/x/wfs/y/wfruns/z/shared-workspace"},
		{Name: "workspace", MountPath: "/mnt/artifacts", SubPath: "shared/r0/orgs/example-org/wfgrps/x/wfs/y/wfruns/z/artifacts", ReadOnly: true},
	}
	if !reflect.DeepEqual(c.VolumeMounts, wantMounts) {
		t.Errorf("volume mounts %+v", c.VolumeMounts)
	}
}

func TestPodMinimal(t *testing.T) {
	cfg := testConfig()
	r := Request{Org: testOrg, Run: testRun, Image: "alpine",
		Mounts: []Mount{{Source: testWS + "/w", Target: "/w"}}}
	p := cfg.Pod(testID, &r, false, Wrap{Reason: "test"})
	c := p.Spec.Containers[0]
	if p.Spec.ActiveDeadlineSeconds != nil || p.Spec.ImagePullSecrets != nil || c.Args != nil ||
		c.ImagePullPolicy != corev1.PullAlways || c.Resources.Requests.Cpu().String() != "1m" ||
		c.Resources.Limits != nil || c.Resources.Requests.Memory().Value() != 0 {
		t.Errorf("minimal pod %+v", p.Spec)
	}
	if c.VolumeMounts[0].SubPath != "orgs/example-org/wfgrps/x/wfs/y/wfruns/z/w" {
		t.Errorf("subPath without a prefix: %s", c.VolumeMounts[0].SubPath)
	}
	r.Mounts = nil
	if p := cfg.Pod(testID, &r, false, Wrap{Reason: "test"}); p.Spec.Volumes != nil || p.Spec.Containers[0].VolumeMounts != nil {
		t.Errorf("a step without mounts got the workspace: %+v", p.Spec.Volumes)
	}
}

func TestPodPullPolicyOverride(t *testing.T) {
	cfg := testConfig()
	for _, image := range []string{"alpine", "alpine:3.20"} {
		r := Request{Org: testOrg, Run: testRun, Image: image}
		for _, p := range []corev1.PullPolicy{corev1.PullNever, corev1.PullAlways, corev1.PullIfNotPresent} {
			cfg.StepImagePullPolicy = p
			if got := cfg.Pod(testID, &r, false, Wrap{Reason: "test"}).Spec.Containers[0].ImagePullPolicy; got != p {
				t.Errorf("%s with %s: %s", image, p, got)
			}
		}
	}
}

func TestWrapCommand(t *testing.T) {
	cfg := ImageConfig{Entrypoint: []string{"/entry", "--flag"}, Cmd: []string{"default"}}
	for name, c := range map[string]struct {
		cfg  ImageConfig
		args []string
		want []string
	}{
		"entrypoint and cmd":   {cfg, nil, []string{WrapperPath, "--", "/entry", "--flag", "default"}},
		"args replace the cmd": {cfg, []string{"plan", "-x"}, []string{WrapperPath, "--", "/entry", "--flag", "plan", "-x"}},
		"empty args keep cmd":  {cfg, []string{}, []string{WrapperPath, "--", "/entry", "--flag", "default"}},
		"cmd only":             {ImageConfig{Cmd: []string{"sh"}}, nil, []string{WrapperPath, "--", "sh"}},
		"args only":            {ImageConfig{}, []string{"run"}, []string{WrapperPath, "--", "run"}},
		"nothing":              {ImageConfig{}, nil, nil},
	} {
		if got := wrapCommand(c.cfg, c.args); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
}

func TestWrappedPod(t *testing.T) {
	cfg := testConfig()
	r := testRequest()
	r.RegistryAuth = &RegistryAuth{Registry: "registry.example.com"}
	cmd := wrapCommand(ImageConfig{Entrypoint: []string{"/entry"}}, r.Args)
	p := cfg.Pod(testID, &r, true, Wrap{Command: cmd})

	if p.Annotations[AnnotationWrapped] != "true" || p.Annotations[AnnotationNotWrappedReason] != "" {
		t.Errorf("annotations %v", p.Annotations)
	}
	c := p.Spec.Containers[0]
	want := []string{WrapperPath, "--", "/entry", "sh", "-c", "echo $$(HOME) $$HOME"}
	if !reflect.DeepEqual(c.Command, want) || c.Args != nil {
		t.Errorf("command %q args %q", c.Command, c.Args)
	}
	if last := c.VolumeMounts[len(c.VolumeMounts)-1]; last != (corev1.VolumeMount{Name: "sg-wrapper", MountPath: "/sg-wrapper", ReadOnly: true}) {
		t.Errorf("wrapper mount %+v", last)
	}
	if len(p.Spec.InitContainers) != 1 {
		t.Fatalf("init containers %+v", p.Spec.InitContainers)
	}
	ic := p.Spec.InitContainers[0]
	sc := ic.SecurityContext
	if ic.Name != "sg-wrapper-install" || ic.Image != cfg.BrokerImage || ic.ImagePullPolicy != corev1.PullIfNotPresent ||
		!reflect.DeepEqual(ic.Command, []string{"/sg-step-wrapper", "install", "/sg-wrapper/sg-step-wrapper"}) ||
		!reflect.DeepEqual(ic.VolumeMounts, []corev1.VolumeMount{{Name: "sg-wrapper", MountPath: "/sg-wrapper"}}) ||
		ic.Resources.Requests.Cpu().String() != "10m" || ic.Resources.Requests.Memory().String() != "16Mi" ||
		!*sc.RunAsNonRoot || *sc.RunAsUser != 65532 || *sc.AllowPrivilegeEscalation || !*sc.ReadOnlyRootFilesystem ||
		!reflect.DeepEqual(sc.Capabilities.Drop, []corev1.Capability{"ALL"}) {
		t.Errorf("init container %+v", ic)
	}
	if want := []corev1.LocalObjectReference{{Name: testID + "-pull"}, {Name: "regcred"}}; !reflect.DeepEqual(p.Spec.ImagePullSecrets, want) {
		t.Errorf("pull secrets %+v", p.Spec.ImagePullSecrets)
	}
	var names []string
	for _, v := range p.Spec.Volumes {
		names = append(names, v.Name)
	}
	if strings.Join(names, ",") != "workspace,sg-wrapper" || p.Spec.Volumes[1].EmptyDir == nil {
		t.Errorf("volumes %+v", p.Spec.Volumes)
	}
}

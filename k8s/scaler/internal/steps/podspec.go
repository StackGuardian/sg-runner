package steps

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"regexp"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/utils/ptr"
)

// Labels on step pods and their Secrets (next to STEP_LABELS, which lose).
const (
	LabelComponent = "app.kubernetes.io/component"
	LabelRunner    = "sg-runner.stackguardian.io/runner"
	LabelRun       = "sg-runner.stackguardian.io/run"
	ComponentStep  = "step"
)

// Annotations on step pods: the request's raw values.
const (
	AnnotationOrg     = "sg-runner.stackguardian.io/org"
	AnnotationRun     = "sg-runner.stackguardian.io/run"
	AnnotationStepIdx = "sg-runner.stackguardian.io/step-idx"
	AnnotationName    = "sg-runner.stackguardian.io/name"
)

// ContainerName is the step pod's only container.
const ContainerName = "step"

// MaxEnvBytes caps the env's keys and values together (a Secret holds 1 MiB).
const MaxEnvBytes = 1_000_000

// StopSlack is added to a step's own timeout and START_TIMEOUT for the pod's
// activeDeadlineSeconds.
const StopSlack int64 = 300

// Mount is a directory of the run's workspace a step sees.
type Mount struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"readOnly"`
}

// RegistryAuth is the credential for pulling a step's image.
type RegistryAuth struct {
	Registry string `json:"registry"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Request is POST /v1/steps.
type Request struct {
	Name           string            `json:"name"`
	Org            string            `json:"org"`
	Run            string            `json:"run"`
	StepIdx        int               `json:"stepIdx"`
	Image          string            `json:"image"`
	Args           []string          `json:"args"`
	Env            map[string]string `json:"env"`
	Mounts         []Mount           `json:"mounts"`
	CPUShares      int64             `json:"cpuShares"`
	MemoryMiB      int64             `json:"memoryMiB"`
	RegistryAuth   *RegistryAuth     `json:"registryAuth"`
	TimeoutSeconds int64             `json:"timeoutSeconds"`
}

// Error is an API error: the response's status, reason and message.
type Error struct {
	Status  int    `json:"-"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Reason + ": " + e.Message }

// API error reasons.
const (
	ReasonInvalidRequest  = "InvalidRequest"
	ReasonInvalidMount    = "InvalidMount"
	ReasonInvalidEnv      = "InvalidEnv"
	ReasonEnvTooLarge     = "EnvTooLarge"
	ReasonNotFound        = "NotFound"
	ReasonKubernetesError = "KubernetesError"
)

func badRequest(reason, format string, a ...any) *Error {
	return &Error{Status: 400, Reason: reason, Message: fmt.Sprintf(format, a...)}
}

var envKeyRE = regexp.MustCompile(`^[-._a-zA-Z0-9]+$`)

// Validate checks a request against the contract; the error is an *Error.
func (c *Config) Validate(r *Request) error {
	if r.Org == "" || r.Run == "" {
		return badRequest(ReasonInvalidRequest, "org and run are required")
	}
	if hasDotDot(r.Org) || hasDotDot(r.Run) {
		return badRequest(ReasonInvalidRequest, "org and run must not contain ..")
	}
	if r.Image == "" || strings.ContainsAny(r.Image, " \t\r\n") {
		return badRequest(ReasonInvalidRequest, "image %q: want an image reference", r.Image)
	}
	if r.StepIdx < 0 || r.CPUShares < 0 || r.MemoryMiB < 0 || r.TimeoutSeconds < 0 {
		return badRequest(ReasonInvalidRequest, "stepIdx, cpuShares, memoryMiB and timeoutSeconds must not be negative")
	}
	if a := r.RegistryAuth; a != nil && a.Registry == "" {
		return badRequest(ReasonInvalidRequest, "registryAuth.registry is required")
	}

	size := 0
	for k, v := range r.Env {
		// Secret keys are also at most 253 characters.
		if !envKeyRE.MatchString(k) || len(validation.IsConfigMapKey(k)) > 0 {
			return badRequest(ReasonInvalidEnv, "env key %q: want [-._a-zA-Z0-9]+, at most 253 characters", k)
		}
		size += len(k) + len(v)
	}
	if size > MaxEnvBytes {
		return badRequest(ReasonEnvTooLarge, "env is %d bytes, over %d", size, MaxEnvBytes)
	}

	ws := c.RunWorkspace(r)
	if !strings.HasPrefix(ws, c.WorkspacesDir+"/") {
		return badRequest(ReasonInvalidRequest, "run workspace %s is outside %s", ws, c.WorkspacesDir)
	}
	targets := map[string]bool{}
	for _, m := range r.Mounts {
		src := path.Clean(m.Source)
		if !path.IsAbs(m.Source) || hasDotDot(m.Source) || !strings.HasPrefix(src, ws+"/") {
			return badRequest(ReasonInvalidMount, "mount source %s is outside the run's workspace %s", m.Source, ws)
		}
		dst := path.Clean(m.Target)
		if !path.IsAbs(m.Target) || dst == "/" {
			return badRequest(ReasonInvalidMount, "mount target %q: want an absolute path below /", m.Target)
		}
		if targets[dst] {
			return badRequest(ReasonInvalidMount, "mount target %s is used twice", dst)
		}
		targets[dst] = true
	}
	return nil
}

// RunWorkspace is a request's run directory, as the controllers see it.
func (c *Config) RunWorkspace(r *Request) string {
	return path.Join(c.WorkspacesDir, r.Org, r.Run)
}

// subPath is where a validated mount source is inside the workspace claim.
func (c *Config) subPath(source string) string {
	rel := strings.TrimPrefix(path.Clean(source), c.WorkspacesDir+"/")
	if c.WorkspaceSubPathPrefix == "" {
		return rel
	}
	return path.Join(c.WorkspaceSubPathPrefix, rel)
}

const idAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

// NewID is a step id (and pod name): `<runner pod>-s-<8 random [a-z0-9]>`.
func (c *Config) NewID(random io.Reader) (string, error) {
	out := make([]byte, 0, 8)
	b := make([]byte, 16)
	for len(out) < 8 {
		if _, err := io.ReadFull(random, b); err != nil {
			return "", err
		}
		for _, x := range b {
			// Rejection sampling: 252 is the largest multiple of 36 below 256.
			if x < 252 && len(out) < 8 {
				out = append(out, idAlphabet[x%36])
			}
		}
	}
	return c.RunnerPodName + "-s-" + string(out), nil
}

// idRE matches the ids of this runner's steps.
func (c *Config) idRE() *regexp.Regexp {
	return regexp.MustCompile(`^` + regexp.QuoteMeta(c.RunnerPodName) + `-s-[a-z0-9]{8}$`)
}

// EnvSecretName and PullSecretName are a step's Secrets.
func EnvSecretName(id string) string  { return id + "-env" }
func PullSecretName(id string) string { return id + "-pull" }

// RunLabel is a label value for a run: its sanitized id, cut to fit, and a
// short hash of org and run so cut or sanitized ids stay apart.
func RunLabel(org, run string) string {
	sum := sha256.Sum256([]byte(org + run))
	hash := hex.EncodeToString(sum[:4])
	var b strings.Builder
	for _, r := range run {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	// Label values start and end alphanumeric.
	notAlnum := func(r rune) bool { return r == '-' || r == '_' || r == '.' }
	text := strings.TrimLeftFunc(b.String(), notAlnum)
	if n := validation.LabelValueMaxLength - len(hash) - 1; len(text) > n {
		text = text[:n]
	}
	text = strings.TrimRightFunc(text, notAlnum)
	if text == "" {
		return hash
	}
	return text + "-" + hash
}

// labels are a step's pod and Secret labels.
func (c *Config) labels(r *Request) map[string]string {
	out := map[string]string{}
	for k, v := range c.StepLabels {
		out[k] = v
	}
	out[LabelComponent] = ComponentStep
	out[LabelRunner] = c.RunnerPodName
	out[LabelRun] = RunLabel(r.Org, r.Run)
	return out
}

// meta is a step object's metadata, owned by the runner pod so it goes with
// it. blockOwnerDeletion stays unset: it would need delete rights on pods'
// finalizers.
func (c *Config) meta(name string, r *Request) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:      name,
		Namespace: c.Namespace,
		Labels:    c.labels(r),
		OwnerReferences: []metav1.OwnerReference{{
			APIVersion: "v1", Kind: "Pod", Name: c.RunnerPodName, UID: c.RunnerPodUID,
		}},
	}
}

// EnvSecret holds a step's env, loaded with envFrom.
func (c *Config) EnvSecret(id string, r *Request) *corev1.Secret {
	data := make(map[string][]byte, len(r.Env))
	for k, v := range r.Env {
		data[k] = []byte(v)
	}
	return &corev1.Secret{
		ObjectMeta: c.meta(EnvSecretName(id), r),
		Type:       corev1.SecretTypeOpaque,
		Data:       data,
	}
}

// PullSecret is the image pull Secret of a request with registryAuth, nil
// without.
func (c *Config) PullSecret(id string, r *Request) (*corev1.Secret, error) {
	a := r.RegistryAuth
	if a == nil {
		return nil, nil
	}
	cfg, err := json.Marshal(map[string]any{"auths": map[string]any{
		a.Registry: map[string]string{
			"username": a.Username,
			"password": a.Password,
			"auth":     base64.StdEncoding.EncodeToString([]byte(a.Username + ":" + a.Password)),
		},
	}})
	if err != nil {
		return nil, err
	}
	return &corev1.Secret{
		ObjectMeta: c.meta(PullSecretName(id), r),
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{corev1.DockerConfigJsonKey: cfg},
	}, nil
}

// PullPolicy is Always for a latest or absent tag, as Docker pulls those.
func PullPolicy(image string) corev1.PullPolicy {
	if strings.Contains(image, "@") {
		return corev1.PullIfNotPresent
	}
	name := image[strings.LastIndex(image, "/")+1:]
	i := strings.LastIndex(name, ":")
	if i < 0 || name[i+1:] == "latest" {
		return corev1.PullAlways
	}
	return corev1.PullIfNotPresent
}

// CPURequest is Docker CPU shares as a request: shares/1024 cores, in
// millicores rounded up, at least 1m.
func CPURequest(shares int64) resource.Quantity {
	m := (shares*1000 + 1023) / 1024
	if m < 1 {
		m = 1
	}
	return *resource.NewMilliQuantity(m, resource.DecimalSI)
}

// Pod is a step's pod.
func (c *Config) Pod(id string, r *Request, withPullSecret bool) *corev1.Pod {
	meta := c.meta(id, r)
	meta.Annotations = map[string]string{
		AnnotationOrg:     r.Org,
		AnnotationRun:     r.Run,
		AnnotationStepIdx: strconv.Itoa(r.StepIdx),
		AnnotationName:    r.Name,
	}

	// Docker never expands $(VAR) in a command; the kubelet does unless
	// escaped as $$(VAR).
	var args []string
	for _, a := range r.Args {
		args = append(args, strings.ReplaceAll(a, "$", "$$"))
	}

	res := corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: CPURequest(r.CPUShares)}}
	if r.MemoryMiB > 0 {
		mem := *resource.NewQuantity(r.MemoryMiB*1024*1024, resource.BinarySI)
		res.Requests[corev1.ResourceMemory] = mem
		res.Limits = corev1.ResourceList{corev1.ResourceMemory: mem}
	}

	var mounts []corev1.VolumeMount
	var volumes []corev1.Volume
	for _, m := range r.Mounts {
		mounts = append(mounts, corev1.VolumeMount{
			Name: "workspace", MountPath: path.Clean(m.Target), SubPath: c.subPath(m.Source), ReadOnly: m.ReadOnly,
		})
	}
	if len(mounts) > 0 {
		volumes = []corev1.Volume{{Name: "workspace", VolumeSource: corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: c.WorkspaceClaim}}}}
	}

	var pullSecrets []corev1.LocalObjectReference
	if withPullSecret {
		pullSecrets = []corev1.LocalObjectReference{{Name: PullSecretName(id)}}
	}

	pullPolicy := c.StepImagePullPolicy
	if pullPolicy == "" {
		pullPolicy = PullPolicy(r.Image)
	}

	var deadline *int64
	if r.TimeoutSeconds > 0 {
		deadline = ptr.To(r.TimeoutSeconds + int64(c.StartTimeout.Seconds()) + StopSlack)
	}

	return &corev1.Pod{
		ObjectMeta: meta,
		Spec: corev1.PodSpec{
			RestartPolicy:                 corev1.RestartPolicyNever,
			TerminationGracePeriodSeconds: ptr.To[int64](30),
			ActiveDeadlineSeconds:         deadline,
			AutomountServiceAccountToken:  ptr.To(false),
			EnableServiceLinks:            ptr.To(false),
			ImagePullSecrets:              pullSecrets,
			NodeSelector:                  c.StepNodeSelector,
			Tolerations:                   c.StepTolerations,
			// The workspace claim is the runner's, attached to its node.
			Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchFields: []corev1.NodeSelectorRequirement{{
						Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: []string{c.NodeName},
					}}}},
				},
			}},
			SecurityContext: &corev1.PodSecurityContext{
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{{
				Name:            ContainerName,
				Image:           r.Image,
				ImagePullPolicy: pullPolicy,
				Args:            args,
				EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: EnvSecretName(id)}}}},
				Resources:       res,
				VolumeMounts:    mounts,
				SecurityContext: &corev1.SecurityContext{Privileged: ptr.To(false)},
			}},
			Volumes: volumes,
		},
	}
}

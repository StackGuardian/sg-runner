{{/*
Chart name.
*/}}
{{- define "sg-runner.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified release name; also the runner StatefulSet's name. Kept to 52
characters: the StatefulSet controller adds a `controller-revision-hash` label
of <name>-<hash> that must fit in 63.
*/}}
{{- define "sg-runner.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 52 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 52 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 52 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Runner StatefulSet (and headless Service) name. Pods are <name>-<ordinal>, PVCs
state-<name>-<ordinal> and docker-<name>-<ordinal>; the scaler maps SG runners
to ordinals through that name.
*/}}
{{- define "sg-runner.runnerName" -}}
{{- include "sg-runner.fullname" . }}
{{- end }}

{{- define "sg-runner.scalerName" -}}
{{- printf "%s-scaler" (include "sg-runner.fullname" .) }}
{{- end }}

{{- define "sg-runner.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels. Pass a dict with "ctx" (root context) and "component".
*/}}
{{- define "sg-runner.labels" -}}
helm.sh/chart: {{ include "sg-runner.chart" .ctx }}
{{ include "sg-runner.selectorLabels" . }}
{{- if .ctx.Chart.AppVersion }}
app.kubernetes.io/version: {{ .ctx.Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .ctx.Release.Service }}
app.kubernetes.io/part-of: sg-runner
{{- end }}

{{/*
Selector labels: runner and scaler pods share name/instance, the component
tells them apart.
*/}}
{{- define "sg-runner.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sg-runner.name" .ctx }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
Labels of reap Job pods: the runner's selector labels with component reaper,
so the NetworkPolicy covers them too.
*/}}
{{- define "sg-runner.reaperLabels" -}}
{{- include "sg-runner.selectorLabels" (dict "ctx" . "component" "reaper") }}
{{- end }}

{{/*
Env for whatever starts reap Jobs (the scaler, the uninstall hook): the
StatefulSet, and how to run reap Job pods.
*/}}
{{- define "sg-runner.reapEnv" -}}
- name: POD_NAMESPACE
  valueFrom:
    fieldRef: { fieldPath: metadata.namespace }
- { name: SCALER_STATEFULSET, value: {{ include "sg-runner.runnerName" . | quote }} }
# Reap Jobs run the runner image (not the scaler's) with the node token
# Secret and the runner group ConfigMap.
- { name: SCALER_IMAGE, value: {{ include "sg-runner.image" . | quote }} }
- { name: SCALER_CREDENTIALS_SECRET, value: {{ include "sg-runner.credentialsSecretName" . | quote }} }
- { name: SCALER_CONFIGMAP, value: {{ include "sg-runner.configName" . | quote }} }
# Reap Job pods: labelled like runners (component reaper) so the
# NetworkPolicy covers them, scheduled like runners (they mount a runner's
# state PVC, which may be bound to a node or zone).
- name: SCALER_REAP_POD_LABELS
  value: {{ include "sg-runner.reaperLabels" . | fromYaml | toJson | quote }}
- name: SCALER_REAP_IMAGE_PULL_SECRETS
  value: {{ include "sg-runner.pullSecretNames" . | quote }}
- name: SCALER_REAP_NODE_SELECTOR
  value: {{ default dict .Values.runner.nodeSelector | toJson | quote }}
- name: SCALER_REAP_TOLERATIONS
  value: {{ default list .Values.runner.tolerations | toJson | quote }}
{{- end }}

{{/*
A label map as a selector string: k1=v1,k2=v2 (sorted).
*/}}
{{- define "sg-runner.selectorString" -}}
{{- $pairs := list }}
{{- range $k := keys . | sortAlpha }}
{{- $pairs = append $pairs (printf "%s=%s" $k (get $ $k)) }}
{{- end }}
{{- join "," $pairs }}
{{- end }}

{{/*
imagePullSecrets names, comma-separated. Entries are Secret names or
{name: ...} objects, mixed as you like.
*/}}
{{- define "sg-runner.pullSecretNames" -}}
{{- $names := list }}
{{- range .Values.imagePullSecrets }}
{{- if kindIs "string" . }}
{{- $names = append $names . }}
{{- else }}
{{- $names = append $names .name }}
{{- end }}
{{- end }}
{{- join "," $names }}
{{- end }}

{{/*
imagePullSecrets as a pod spec takes them ({name: ...} each), for every pod
the chart renders.
*/}}
{{- define "sg-runner.imagePullSecrets" -}}
{{- $refs := list }}
{{- range splitList "," (include "sg-runner.pullSecretNames" .) }}
{{- with . }}
{{- $refs = append $refs (dict "name" .) }}
{{- end }}
{{- end }}
{{- with $refs }}
{{- toYaml . }}
{{- end }}
{{- end }}

{{/*
Runner image reference; the scaler also uses it for reap Jobs.
*/}}
{{- define "sg-runner.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag | toString) }}
{{- end }}

{{/*
Scaler image reference (the steps broker's too, unless set apart).
*/}}
{{- define "sg-runner.scalerImage" -}}
{{- printf "%s:%s" .Values.scaler.image.repository (default .Chart.AppVersion .Values.scaler.image.tag | toString) }}
{{- end }}

{{/*
Name of the SG credentials Secret. Fails rendering when neither an existing
Secret nor credentials.create is configured, or both are.
*/}}
{{- define "sg-runner.credentialsSecretName" -}}
{{- $c := .Values.credentials }}
{{- if and $c.existingSecret $c.create }}
{{- fail "credentials: set either credentials.existingSecret or credentials.create=true, not both" }}
{{- else if $c.existingSecret }}
{{- $c.existingSecret }}
{{- else if $c.create }}
{{- printf "%s-credentials" (include "sg-runner.fullname" .) }}
{{- else }}
{{- fail "credentials: set credentials.existingSecret (a Secret with key SG_NODE_TOKEN) or credentials.create=true with credentials.nodeToken" }}
{{- end }}
{{- end }}

{{/*
Name of the ConfigMap with the runner group (SG_ORGANIZATION, SG_RUNNER_GROUP,
SG_BASE_API). Fails rendering without sg.organization and sg.runnerGroup.
*/}}
{{- define "sg-runner.configName" -}}
{{- if not (and .Values.sg.organization .Values.sg.runnerGroup) }}
{{- fail "sg.organization and sg.runnerGroup are required: the runner group to register into" }}
{{- end }}
{{- printf "%s-config" (include "sg-runner.fullname" .) }}
{{- end }}

{{/*
StackGuardian API URL: sg.apiUrl when set, else the one for sg.region.
*/}}
{{- define "sg-runner.apiUrl" -}}
{{- $urls := dict "eu" "https://api.app.stackguardian.io/api/v1" "us" "https://api.us.stackguardian.io/api/v1" "dash" "https://testapi.qa.stackguardian.io/api/v1" }}
{{- .Values.sg.apiUrl | default (get $urls (.Values.sg.region | default "eu")) }}
{{- end }}

{{/*
Hashes of the runner group config and, with credentials.create, the node
token, as pod annotations: runner.sh and the scaler read them once at start,
so a change must roll their pods. The data only, not the rendered objects:
their chart version label would roll (drain) every runner on each chart
upgrade. A token in an existingSecret is invisible to the chart: rotating it
needs a rollout restart.
*/}}
{{- define "sg-runner.configChecksum" -}}
checksum/config: {{ list .Values.sg.organization .Values.sg.runnerGroup (include "sg-runner.apiUrl" .) | join "\n" | sha256sum | quote }}
{{- if .Values.credentials.create }}
checksum/token: {{ .Values.credentials.nodeToken | sha256sum | quote }}
{{- end }}
{{- end }}

{{/*
The runner group settings and node token as files in one directory
(/etc/sg-runner/credentials), as runner.sh and the scaler read them: the
ConfigMap plus only the SG_NODE_TOKEN key of the Secret. Pass the root context
as "ctx" and the file mode as "mode".
*/}}
{{- define "sg-runner.credentialsVolume" -}}
- name: sg-credentials
  projected:
    defaultMode: {{ .mode }}
    sources:
      - secret:
          name: {{ include "sg-runner.credentialsSecretName" .ctx }}
          items: [{ key: SG_NODE_TOKEN, path: SG_NODE_TOKEN }]
      - configMap:
          name: {{ include "sg-runner.configName" .ctx }}
{{- end }}

{{/*
Runner size: what the runner advertises to SG (cpu, memory) and the dockerd
container's resources (only run controllers run there). A preset or, with
size=custom, runner.advertise and runner.controllerResources. Prints YAML.
*/}}
{{- define "sg-runner.size" -}}
{{- $presets := dict
  "small" (dict "cpu" 2 "memory" "4Gi" "resources" (dict "requests" (dict "cpu" "500m" "memory" "1Gi") "limits" (dict "cpu" "2" "memory" "2Gi")))
  "medium" (dict "cpu" 4 "memory" "8Gi" "resources" (dict "requests" (dict "cpu" "1" "memory" "2Gi") "limits" (dict "cpu" "4" "memory" "4Gi")))
  "large" (dict "cpu" 8 "memory" "16Gi" "resources" (dict "requests" (dict "cpu" "2" "memory" "4Gi") "limits" (dict "cpu" "8" "memory" "8Gi")))
}}
{{- $size := .Values.runner.size }}
{{- if eq $size "custom" }}
{{- $a := default dict .Values.runner.advertise }}
{{- $res := default dict .Values.runner.controllerResources }}
{{- if not (and $a.cpu $a.memory) }}
{{- fail "runner.size=custom needs runner.advertise.cpu (whole CPUs) and .memory (Mi or Gi): what the runner advertises to SG for workflows" }}
{{- end }}
{{- $limits := default dict $res.limits }}
{{- if not (and $limits.cpu $limits.memory) }}
{{- fail "runner.size=custom needs runner.controllerResources.limits.cpu and .memory: the run controllers' room" }}
{{- end }}
{{- toYaml (dict "cpu" $a.cpu "memory" $a.memory "resources" $res) }}
{{- else if hasKey $presets $size }}
{{- toYaml (get $presets $size) }}
{{- else }}
{{- fail (printf "runner.size must be small, medium, large or custom, got %q" $size) }}
{{- end }}
{{- end }}

{{/*
Resources of the dockerd container (run controllers only).
*/}}
{{- define "sg-runner.dockerdResources" -}}
{{- toYaml (include "sg-runner.size" . | fromYaml).resources }}
{{- end }}

{{/*
The steps broker image, runner.steps.broker.image when its repository is set,
the scaler image otherwise (it ships /sg-runner-steps).
*/}}
{{- define "sg-runner.brokerImage" -}}
{{- $img := .Values.runner.steps.broker.image }}
{{- if $img.repository }}
{{- printf "%s:%s" $img.repository (default .Chart.AppVersion $img.tag | toString) }}
{{- else }}
{{- include "sg-runner.scalerImage" . }}
{{- end }}
{{- end }}

{{/*
The advertised memory (<n>Mi or <n>Gi) in MiB, what the ECS agent advertises
(SG_TASK_MEMORY_LIMIT_MIB).
*/}}
{{- define "sg-runner.advertiseMemoryMiB" -}}
{{- $m := toString (include "sg-runner.size" . | fromYaml).memory }}
{{- if regexMatch "^[1-9][0-9]*Gi$" $m }}
{{- mul (trimSuffix "Gi" $m | atoi) 1024 }}
{{- else if regexMatch "^[1-9][0-9]*Mi$" $m }}
{{- trimSuffix "Mi" $m | atoi }}
{{- else }}
{{- fail (printf "runner.advertise.memory must be <n>Mi or <n>Gi, got %q" $m) }}
{{- end }}
{{- end }}

{{/*
Runner pod affinity: runner.affinity plus a required pod anti-affinity term
(one runner per node: steps run on the runner's node and mount its RWO
workspace), appended to any terms of the user's own.
*/}}
{{- define "sg-runner.runnerAffinity" -}}
{{- $aff := deepCopy (default dict .Values.runner.affinity) }}
{{- $selector := include "sg-runner.selectorLabels" (dict "ctx" . "component" "runner") | fromYaml }}
{{- $term := dict "topologyKey" "kubernetes.io/hostname" "labelSelector" (dict "matchLabels" $selector) }}
{{- $anti := default dict $aff.podAntiAffinity }}
{{- $required := default list $anti.requiredDuringSchedulingIgnoredDuringExecution }}
{{- $_ := set $anti "requiredDuringSchedulingIgnoredDuringExecution" (append $required $term) }}
{{- $_ := set $aff "podAntiAffinity" $anti }}
{{- toYaml $aff }}
{{- end }}

{{/*
What the ECS agent advertises (runner.sh sizes the agent from it), with
nothing kept back for dockerd: steps run as pods next to the runner. On
ecs-agent and the register init container, which re-registers a runner whose
size changed.
*/}}
{{- define "sg-runner.advertiseEnv" -}}
- { name: SG_TASK_CPU_LIMIT, value: {{ (include "sg-runner.size" . | fromYaml).cpu | quote }} }
- { name: SG_TASK_MEMORY_LIMIT_MIB, value: {{ include "sg-runner.advertiseMemoryMiB" . | quote }} }
- { name: SG_DOCKERD_OVERHEAD_MIB, value: "0" }
{{- end }}

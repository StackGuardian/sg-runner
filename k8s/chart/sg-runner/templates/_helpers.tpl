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
imagePullSecrets names, comma-separated.
*/}}
{{- define "sg-runner.pullSecretNames" -}}
{{- $names := list }}
{{- range .Values.imagePullSecrets }}
{{- $names = append $names (kindIs "string" . | ternary . .name) }}
{{- end }}
{{- join "," $names }}
{{- end }}

{{/*
Runner image reference; the scaler also uses it for reap Jobs.
*/}}
{{- define "sg-runner.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag | toString) }}
{{- end }}

{{/*
Scaler image: its own repository/tag when set, the runner image otherwise.
*/}}
{{- define "sg-runner.scalerImage" -}}
{{- if .Values.scaler.image.repository }}
{{- printf "%s:%s" .Values.scaler.image.repository (default .Chart.AppVersion .Values.scaler.image.tag | toString) }}
{{- else }}
{{- include "sg-runner.image" . }}
{{- end }}
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
{{- fail "credentials: set credentials.existingSecret (a Secret with SG_NODE_TOKEN, SG_ORGANIZATION, SG_RUNNER_GROUP and optionally SG_BASE_API) or credentials.create=true with credentials.nodeToken, credentials.organization and credentials.runnerGroup" }}
{{- end }}
{{- end }}

{{/*
Resources of the dockerd container: a size preset or runner.resources, plus the
workspace's ephemeral-storage request. Workflows run inside dockerd, and the ECS
agent advertises these limits (SG_TASK_* on ecs-agent).
*/}}
{{- define "sg-runner.dockerdResources" -}}
{{- $presets := dict
  "small" (dict "requests" (dict "cpu" "1" "memory" "2Gi") "limits" (dict "cpu" "2" "memory" "4Gi"))
  "medium" (dict "requests" (dict "cpu" "2" "memory" "4Gi") "limits" (dict "cpu" "4" "memory" "8Gi"))
  "large" (dict "requests" (dict "cpu" "4" "memory" "8Gi") "limits" (dict "cpu" "8" "memory" "16Gi"))
}}
{{- $size := .Values.runner.size }}
{{- $res := dict }}
{{- if eq $size "custom" }}
{{- $res = deepCopy (default dict .Values.runner.resources) }}
{{- $limits := default dict $res.limits }}
{{- if not (and $limits.cpu $limits.memory) }}
{{- fail "runner.size=custom needs runner.resources.limits.cpu and .memory: without limits the runner advertises the whole node to SG" }}
{{- end }}
{{- else if hasKey $presets $size }}
{{- $res = deepCopy (get $presets $size) }}
{{- else }}
{{- fail (printf "runner.size must be small, medium, large or custom, got %q" $size) }}
{{- end }}
{{- with .Values.runner.workspace.request }}
{{- $requests := default dict $res.requests }}
{{- $_ := set $requests "ephemeral-storage" . }}
{{- $_ := set $res "requests" $requests }}
{{- end }}
{{- toYaml $res }}
{{- end }}

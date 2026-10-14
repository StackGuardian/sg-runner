#!/usr/bin/env bash
# Lints the sg-runner chart, renders the key value scenarios, validates every
# rendered manifest with kubeconform and checks that the schema and the
# templates reject bad values. Needs helm (v3 or v4) and kubeconform on PATH;
# never talks to a cluster.
#
#   .github/scripts/chart-check.sh [out-dir]
#
# KUBE_VERSION: Kubernetes version the manifests are validated against.
set -euo pipefail

CHART=k8s/chart/sg-runner
OUT=${1:-${RUNNER_TEMP:-/tmp}/chart-check}
KUBE_VERSION=${KUBE_VERSION:-1.37.0}
# Release name = chart name, as the k8s/Makefile installs it.
RELEASE=sg-runner
# Every scenario needs credentials; the Secret doesn't have to exist to render.
CREDS=(--set credentials.existingSecret=sg-runner-credentials
  --set sg.organization=ci-org --set sg.runnerGroup=ci-group)

rm -rf "$OUT" && mkdir -p "$OUT"
failed=0

render() { # <name> <helm template args...>
  local name=$1
  shift
  echo "::group::render $name"
  if helm template "$RELEASE" "$CHART" --namespace sg-runner "$@" >"$OUT/$name.yaml"; then
    echo "rendered $(grep -c '^kind:' "$OUT/$name.yaml") objects"
  else
    echo "::error title=helm template::scenario '$name' failed to render"
    failed=1
  fi
  echo "::endgroup::"
}

# Rendering must fail, and with the expected message (so an unrelated error
# doesn't count as the rejection).
reject() { # <name> <expected stderr regex> <helm template args...>
  local name=$1 want=$2
  shift 2
  if helm template "$RELEASE" "$CHART" "$@" >/dev/null 2>"$OUT/$name.err"; then
    echo "::error title=helm template::scenario '$name' rendered, expected a rejection"
    failed=1
  elif ! grep -Eq "$want" "$OUT/$name.err"; then
    echo "::error title=helm template::scenario '$name' failed for another reason:"
    cat "$OUT/$name.err"
    failed=1
  else
    echo "rejected as expected: $name ($(head -c 200 "$OUT/$name.err" | tr '\n' ' '))"
  fi
}

# Must contain the given kind (guards against a scenario silently rendering
# nothing new).
expect_kind() { # <name> <kind>
  grep -q "^kind: $2\$" "$OUT/$1.yaml" \
    || { echo "::error title=helm template::scenario '$1' has no $2"; failed=1; }
}
expect_no_kind() { # <name> <kind>
  ! grep -q "^kind: $2\$" "$OUT/$1.yaml" \
    || { echo "::error title=helm template::scenario '$1' unexpectedly has a $2"; failed=1; }
}
expect_text() { # <name> <fixed string>
  grep -qF -- "$2" "$OUT/$1.yaml" \
    || { echo "::error title=helm template::scenario '$1' lacks: $2"; failed=1; }
}
expect_count() { # <name> <fixed string> <count>
  local got
  got=$(grep -cF -- "$2" "$OUT/$1.yaml" || true)
  [[ $got == "$3" ]] \
    || { echo "::error title=helm template::scenario '$1' has $got x '$2', want $3"; failed=1; }
}

echo "::group::helm lint --strict"
helm version
helm lint --strict "$CHART" "${CREDS[@]}" || failed=1
echo "::endgroup::"

render defaults "${CREDS[@]}"
expect_kind defaults StatefulSet
expect_kind defaults Deployment
expect_kind defaults Role
# The uninstall hook (pre-delete Job).
expect_kind defaults Job
# The register init container sees what ecs-agent will advertise, to
# re-register a runner whose size changed.
expect_count defaults 'name: SG_TASK_CPU_LIMIT' 2
expect_count defaults 'name: SG_TASK_MEMORY_LIMIT_MIB' 2
expect_text defaults '{ name: SG_REREGISTER_ON_RESIZE, value: "true" }'

render credentials-create \
  --set credentials.create=true \
  --set credentials.nodeToken=ci-dummy-token \
  --set sg.organization=ci-org \
  --set sg.runnerGroup=ci-group \
  --set sg.apiUrl=http://127.0.0.1:9
expect_kind credentials-create Secret
expect_kind credentials-create ConfigMap

render scaler-disabled "${CREDS[@]}" --set scaler.enabled=false --set runner.replicas=2 \
  --set uninstall.deregister=false
expect_no_kind scaler-disabled Deployment
# Only the runner's Role (the steps broker), not the scaler's.
[[ $(grep -c '^kind: Role$' "$OUT/scaler-disabled.yaml") == 1 ]] \
  || { echo "::error title=helm template::scenario 'scaler-disabled' should have only the runner's Role"; failed=1; }
expect_no_kind scaler-disabled Job

# Without the scaler, the uninstall hook still cleans up, with its own Role.
render uninstall-without-scaler "${CREDS[@]}" --set scaler.enabled=false
expect_no_kind uninstall-without-scaler Deployment
expect_kind uninstall-without-scaler Job
expect_kind uninstall-without-scaler Role

render network-policy "${CREDS[@]}" \
  --set networkPolicy.enabled=true \
  --set 'networkPolicy.clusterCIDRs={10.0.0.0/8,172.16.0.0/12}'
expect_kind network-policy NetworkPolicy

# The runner pod's init containers (register, then the steps sidecar).
init_containers() { # <name>
  awk '/^kind: StatefulSet$/ {sts = 1} sts && /^      initContainers:$/ {on = 1; next}
    on && /^      containers:$/ {exit} on' "$OUT/$1.yaml"
}

# Defaults: size small, the broker a native sidecar guarding dockerd, the
# runner's RBAC, a workspace PVC per pod, one runner per node.
expect_kind defaults ServiceAccount
expect_kind defaults RoleBinding
expect_text defaults 'volumeClaimTemplate:'
expect_text defaults 'topologyKey: kubernetes.io/hostname'
expect_count defaults '{ name: SG_TASK_CPU_LIMIT, value: "2" }' 2
expect_count defaults '{ name: SG_TASK_MEMORY_LIMIT_MIB, value: "4096" }' 2
expect_count defaults '{ name: SG_DOCKERD_OVERHEAD_MIB, value: "0" }' 2
expect_text defaults 'verbs: ["create", "get", "list", "watch", "patch", "delete"]'
# Published images by default, tagged with the chart's appVersion ("dev" in
# git; the release workflow sets the version).
expect_text defaults 'image: ghcr.io/stackguardian/sg-runner-k8s:dev'
expect_text defaults 'image: ghcr.io/stackguardian/sg-runner-scaler:dev'
expect_text defaults '{ name: BROKER_IMAGE, value: "ghcr.io/stackguardian/sg-runner-scaler:dev" }'
expect_text defaults '{ name: SCALER_IMAGE, value: "ghcr.io/stackguardian/sg-runner-k8s:dev" }'
expect_text defaults '{ name: BROKER_IMAGE_PULL_POLICY, value: "IfNotPresent" }'
expect_text defaults '{ name: FINISHED_TTL, value: "1h" }'
expect_text defaults '{ name: GUARD_SOCKET, value: /run/sg-guard/sg-steps-guard.sock }'
expect_text defaults '{ name: docker-plugins, mountPath: /run/docker/plugins }'
expect_text defaults '{ name: docker-plugins, mountPath: /run/sg-guard }'
# The sidecar outlives the drain by itself: no drain marker, no preStop.
expect_count defaults 'DRAINED_MARKER' 0
expect_count defaults "command: ['/sg-runner-steps', 'wait-drained']" 0
expect_count defaults 'timeoutSeconds: 6' 2
if ! init_containers defaults | grep -q -- '- name: steps' \
  || ! init_containers defaults | grep -q 'restartPolicy: Always' \
  || ! init_containers defaults | grep -qF "command: ['/sg-runner-steps', 'healthcheck']"; then
  echo "::error title=helm template::scenario 'defaults': the steps broker isn't a native sidecar with a healthcheck"
  failed=1
fi
if grep -q 'workflow-logs' "$OUT/defaults.yaml"; then
  echo "::error title=helm template::scenario 'defaults' still has workflow-logs"
  failed=1
fi
if [[ $(grep -c 'mountPath: /var/run/secrets/kubernetes.io/serviceaccount' "$OUT/defaults.yaml") -ne 1 ]]; then
  echo "::error title=helm template::scenario 'defaults' must mount the API token in exactly one container"
  failed=1
fi

# Presets set what the runner advertises and the controllers' room.
render size-large "${CREDS[@]}" --set runner.size=large
expect_count size-large '{ name: SG_TASK_CPU_LIMIT, value: "8" }' 2
expect_count size-large '{ name: SG_TASK_MEMORY_LIMIT_MIB, value: "16384" }' 2
expect_text size-large 'memory: 8Gi'

render size-custom "${CREDS[@]}" \
  --set runner.size=custom \
  --set runner.advertise.cpu=3 --set runner.advertise.memory=3072Mi \
  --set runner.controllerResources.requests.cpu=250m \
  --set runner.controllerResources.requests.memory=512Mi \
  --set runner.controllerResources.limits.cpu=1 \
  --set runner.controllerResources.limits.memory=1536Mi
expect_count size-custom '{ name: SG_TASK_CPU_LIMIT, value: "3" }' 2
expect_count size-custom '{ name: SG_TASK_MEMORY_LIMIT_MIB, value: "3072" }' 2
expect_text size-custom 'memory: 1536Mi'

# Every knob at once; the NetworkPolicy covers step pods.
render everything "${CREDS[@]}" --set runner.size=medium \
  --set networkPolicy.enabled=true --set 'networkPolicy.clusterCIDRs={10.0.0.0/8}' \
  --set 'runner.ecsAgent.extraEnv[0].name=ECS_IMAGE_PULL_BEHAVIOR' \
  --set 'runner.ecsAgent.extraEnv[0].value=prefer-cached' \
  --set 'runner.dockerd.extraEnv[0].name=SG_PRUNE_INTERVAL_SECONDS' \
  --set-string 'runner.dockerd.extraEnv[0].value=0' \
  --set runner.steps.step.imagePullPolicy=IfNotPresent \
  --set 'imagePullSecrets[0].name=regcred' --set 'imagePullSecrets[1].name=other' \
  --set runner.reregisterOnResize=false \
  --set 'runner.affinity.podAntiAffinity.requiredDuringSchedulingIgnoredDuringExecution[0].topologyKey=zone'
expect_kind everything NetworkPolicy
expect_text everything 'values: [runner, reaper, step]'
expect_count everything '{ name: SG_TASK_CPU_LIMIT, value: "4" }' 2
expect_text everything '{ name: BROKER_IMAGE_PULL_SECRETS, value: "regcred,other" }'
expect_text everything '{ name: STEP_IMAGE_PULL_POLICY, value: IfNotPresent }'
expect_text everything 'name: SG_PRUNE_INTERVAL_SECONDS'
expect_text everything 'name: ECS_IMAGE_PULL_BEHAVIOR'
expect_text everything '{ name: SG_REREGISTER_ON_RESIZE, value: "false" }'
expect_text everything 'topologyKey: zone'
expect_text everything 'topologyKey: kubernetes.io/hostname'

render pdb "${CREDS[@]}" --set podDisruptionBudget.enabled=true --set scaler.min=2
expect_kind pdb PodDisruptionBudget

# --api-versions makes the ServiceMonitor render, as on a cluster with the
# Prometheus Operator CRDs.
render metrics "${CREDS[@]}" \
  --set scaler.metrics.enabled=true \
  --set scaler.metrics.serviceMonitor.enabled=true \
  --api-versions monitoring.coreos.com/v1/ServiceMonitor
expect_kind metrics Service
expect_kind metrics ServiceMonitor

# imagePullSecrets as plain names and {name:} objects, mixed: every pod gets
# {name:} refs, the scaler and the broker the names.
render pull-secrets-mixed "${CREDS[@]}" \
  --set-json 'imagePullSecrets=["plain",{"name":"obj"}]'
expect_count pull-secrets-mixed '- name: plain' 3
expect_count pull-secrets-mixed '- name: obj' 3
expect_text pull-secrets-mixed '{ name: BROKER_IMAGE_PULL_SECRETS, value: "plain,obj" }'
expect_count pull-secrets-mixed 'value: "plain,obj"' 3

echo "::group::kubeconform (Kubernetes $KUBE_VERSION)"
# ServiceMonitor is validated against the community CRDs catalog.
kubeconform -strict -summary -output text \
  -kubernetes-version "$KUBE_VERSION" \
  -schema-location default \
  -schema-location 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json' \
  "$OUT"/*.yaml || failed=1
echo "::endgroup::"

echo "::group::rejections"
reject size-huge 'runner[./]size' "${CREDS[@]}" --set runner.size=huge
reject scaler-min-0 'scaler[./]min' "${CREDS[@]}" --set scaler.min=0
reject no-credentials 'credentials' --set sg.organization=o --set sg.runnerGroup=g
reject both-credentials 'not both' "${CREDS[@]}" --set credentials.create=true
reject no-runner-group 'sg.organization and sg.runnerGroup' \
  --set credentials.existingSecret=x --set sg.organization=o
reject token-only-secret 'additional properties|additionalProperties|organization' \
  --set credentials.existingSecret=x --set credentials.organization=o \
  --set sg.organization=o --set sg.runnerGroup=g
reject network-policy-no-cidrs 'clusterCIDRs' "${CREDS[@]}" --set networkPolicy.enabled=true
reject custom-without-advertise 'advertise' "${CREDS[@]}" --set runner.size=custom \
  --set runner.controllerResources.limits.cpu=1 --set runner.controllerResources.limits.memory=1Gi
reject custom-without-controllers 'controllerResources' "${CREDS[@]}" --set runner.size=custom \
  --set runner.advertise.cpu=2 --set runner.advertise.memory=4Gi
reject fractional-cpu 'advertise[./]cpu' "${CREDS[@]}" --set runner.size=custom \
  --set runner.advertise.cpu=1.5 --set runner.advertise.memory=4Gi \
  --set runner.controllerResources.limits.cpu=1 --set runner.controllerResources.limits.memory=1Gi
reject memory-bytes 'advertise[./]memory' "${CREDS[@]}" --set runner.size=custom \
  --set runner.advertise.cpu=2 --set runner.advertise.memory=6442450944 \
  --set runner.controllerResources.limits.cpu=1 --set runner.controllerResources.limits.memory=1Gi
reject bad-timeout 'startTimeout' "${CREDS[@]}" --set runner.steps.startTimeout=30
reject bad-pull-policy 'imagePullPolicy' "${CREDS[@]}" --set runner.steps.step.imagePullPolicy=Sometimes
reject old-native-steps 'nativeSteps|additional' "${CREDS[@]}" --set runner.nativeSteps.enabled=true
reject pull-secret-empty-name 'imagePullSecrets' "${CREDS[@]}" --set-json 'imagePullSecrets=[{"name":""}]'
reject replicas-without-lease 'leaderElection' "${CREDS[@]}" \
  --set scaler.replicas=2 --set scaler.leaderElection.enabled=false
echo "::endgroup::"

if [[ $failed -ne 0 ]]; then
  echo "chart check failed"
  exit 1
fi
echo "chart check passed"

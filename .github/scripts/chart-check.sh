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
expect_no_kind scaler-disabled Role
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

render size-custom "${CREDS[@]}" \
  --set runner.size=custom \
  --set runner.resources.requests.cpu=3 \
  --set runner.resources.requests.memory=6Gi \
  --set runner.resources.limits.cpu=3 \
  --set runner.resources.limits.memory=6Gi

render workflow-logs "${CREDS[@]}" --set runner.workflowLogs.enabled=true --set runner.workflowLogs.debug=true \
  --set runner.workflowLogs.format=json

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

# Native steps: broker container, runner RBAC, workspace PVC per pod; the
# NetworkPolicy covers step pods.
NATIVE=(--set runner.nativeSteps.enabled=true
  --set runner.nativeSteps.advertise.cpu=4 --set runner.nativeSteps.advertise.memory=6Gi)
render native-steps "${CREDS[@]}" "${NATIVE[@]}" \
  --set networkPolicy.enabled=true --set 'networkPolicy.clusterCIDRs={10.0.0.0/8}' \
  --set 'runner.ecsAgent.extraEnv[0].name=ECS_IMAGE_PULL_BEHAVIOR' \
  --set 'runner.ecsAgent.extraEnv[0].value=prefer-cached' \
  --set 'runner.dockerd.extraEnv[0].name=SG_PRUNE_INTERVAL_SECONDS' \
  --set-string 'runner.dockerd.extraEnv[0].value=0' \
  --set runner.nativeSteps.step.imagePullPolicy=IfNotPresent
expect_kind native-steps ServiceAccount
expect_kind native-steps Role
expect_kind native-steps RoleBinding
expect_kind native-steps NetworkPolicy
expect_text native-steps 'volumeClaimTemplate:'
expect_text native-steps '- name: steps'
expect_text native-steps 'values: [runner, reaper, step]'
expect_text native-steps '{ name: SG_TASK_MEMORY_LIMIT_MIB, value: "6144" }'
expect_text native-steps 'topologyKey: kubernetes.io/hostname'
expect_count native-steps '{ name: SG_TASK_CPU_LIMIT, value: "4" }' 2
expect_count native-steps '{ name: SG_DOCKERD_OVERHEAD_MIB, value: "0" }' 2
expect_text native-steps '{ name: STEP_IMAGE_PULL_POLICY, value: IfNotPresent }'
expect_text native-steps 'name: SG_PRUNE_INTERVAL_SECONDS'
# Only the broker gets a token; workflow-logs is off with native steps.
render native-steps-logs "${CREDS[@]}" "${NATIVE[@]}" --set runner.nativeSteps.advertise.memory=3072Mi \
  --set runner.workflowLogs.enabled=true --set runner.reregisterOnResize=false
expect_text native-steps-logs '{ name: SG_TASK_MEMORY_LIMIT_MIB, value: "3072" }'
expect_text native-steps-logs '{ name: SG_REREGISTER_ON_RESIZE, value: "false" }'
if grep -q 'name: workflow-logs' "$OUT/native-steps-logs.yaml"; then
  echo "::error title=helm template::scenario 'native-steps-logs' has a workflow-logs container"
  failed=1
fi
if [[ $(grep -c 'mountPath: /var/run/secrets/kubernetes.io/serviceaccount' "$OUT/native-steps.yaml") -ne 1 ]]; then
  echo "::error title=helm template::scenario 'native-steps' must mount the API token in exactly one container"
  failed=1
fi

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
reject workflow-logs-format 'workflowLogs[./]format' "${CREDS[@]}" --set runner.workflowLogs.format=xml
reject no-credentials 'credentials' --set sg.organization=o --set sg.runnerGroup=g
reject both-credentials 'not both' "${CREDS[@]}" --set credentials.create=true
reject no-runner-group 'sg.organization and sg.runnerGroup' \
  --set credentials.existingSecret=x --set sg.organization=o
reject token-only-secret 'additional properties|additionalProperties|organization' \
  --set credentials.existingSecret=x --set credentials.organization=o \
  --set sg.organization=o --set sg.runnerGroup=g
reject custom-without-limits 'limits' "${CREDS[@]}" --set runner.size=custom
reject network-policy-no-cidrs 'clusterCIDRs' "${CREDS[@]}" --set networkPolicy.enabled=true
reject native-steps-no-advertise 'advertise' "${CREDS[@]}" --set runner.nativeSteps.enabled=true
reject native-steps-fractional-cpu 'advertise[./]cpu' "${CREDS[@]}" "${NATIVE[@]}" \
  --set runner.nativeSteps.advertise.cpu=1.5
reject native-steps-memory-bytes 'advertise[./]memory' "${CREDS[@]}" "${NATIVE[@]}" \
  --set runner.nativeSteps.advertise.memory=6442450944
reject native-steps-bad-timeout 'startTimeout' "${CREDS[@]}" "${NATIVE[@]}" \
  --set runner.nativeSteps.startTimeout=30
reject native-steps-bad-pull-policy 'imagePullPolicy' "${CREDS[@]}" "${NATIVE[@]}" \
  --set runner.nativeSteps.step.imagePullPolicy=Sometimes
reject replicas-without-lease 'leaderElection' "${CREDS[@]}" \
  --set scaler.replicas=2 --set scaler.leaderElection.enabled=false
echo "::endgroup::"

if [[ $failed -ne 0 ]]; then
  echo "chart check failed"
  exit 1
fi
echo "chart check passed"

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
CREDS=(--set credentials.existingSecret=sg-runner-credentials)

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

echo "::group::helm lint --strict"
helm version
helm lint --strict "$CHART" "${CREDS[@]}" || failed=1
echo "::endgroup::"

render defaults "${CREDS[@]}"
expect_kind defaults StatefulSet
expect_kind defaults Deployment
expect_kind defaults Role

render credentials-create \
  --set credentials.create=true \
  --set credentials.nodeToken=ci-dummy-token \
  --set credentials.organization=ci-org \
  --set credentials.runnerGroup=ci-group \
  --set credentials.apiUrl=http://127.0.0.1:9
expect_kind credentials-create Secret

render scaler-disabled "${CREDS[@]}" --set scaler.enabled=false --set runner.replicas=2
expect_no_kind scaler-disabled Deployment
expect_no_kind scaler-disabled Role

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
reject no-credentials 'credentials'
reject both-credentials 'not both' "${CREDS[@]}" --set credentials.create=true
reject custom-without-limits 'limits' "${CREDS[@]}" --set runner.size=custom
reject network-policy-no-cidrs 'clusterCIDRs' "${CREDS[@]}" --set networkPolicy.enabled=true
reject replicas-without-lease 'leaderElection' "${CREDS[@]}" \
  --set scaler.replicas=2 --set scaler.leaderElection.enabled=false
echo "::endgroup::"

if [[ $failed -ne 0 ]]; then
  echo "chart check failed"
  exit 1
fi
echo "chart check passed"

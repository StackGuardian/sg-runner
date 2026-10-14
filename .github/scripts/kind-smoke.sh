#!/usr/bin/env bash
# Smoke-installs the sg-runner chart on a throwaway kind cluster with locally
# built images and checks what can be checked without StackGuardian: the
# scaler starts and is ready, finds SG unreachable and leaks no credentials,
# the runner's register init container fails as expected, the scaler's
# RBAC is as narrow as intended, and `helm uninstall` leaves no PVCs behind.
#
# sg.apiUrl is http://127.0.0.1:9 (discard port on the pod's own loopback):
# nothing ever reaches StackGuardian, and registration fails before any AWS
# call.
#
#   .github/scripts/kind-smoke.sh run        # load images, install, assert
#   .github/scripts/kind-smoke.sh diag DIR   # dump cluster state into DIR
#
# The images must exist locally (RUNNER_IMAGE, SCALER_IMAGE); the cluster
# must exist already (kind create cluster --name "$CLUSTER").
set -euo pipefail

CLUSTER=${CLUSTER:-sg-runner-ci}
CONTEXT=${KUBE_CONTEXT:-kind-$CLUSTER}
RUNNER_IMAGE=${RUNNER_IMAGE:-sg-runner-k8s:ci}
SCALER_IMAGE=${SCALER_IMAGE:-sg-runner-scaler:ci}
NS=sg-runner
RELEASE=sg-runner
STS=sg-runner
SCALER=sg-runner-scaler
SECRET=sg-runner-credentials
CHART=k8s/chart/sg-runner
TIMEOUT=${TIMEOUT:-240}
# Failed SG API calls one register run may make (see the register step).
MAX_API_ATTEMPTS=3
# Distinctive, so finding it in any log means a credential leaked.
TOKEN=ci-dummy-node-token-6f1d3c9a
SA=system:serviceaccount:$NS:$SCALER

# Only ever a kind cluster: never a real or shared context.
[[ $CONTEXT == kind-* ]] || { echo "refusing to use context '$CONTEXT' (not kind-*)"; exit 2; }

k() { kubectl --context "$CONTEXT" -n "$NS" "$@"; }

step() { echo "::group::$*"; }
endstep() { echo "::endgroup::"; }
fail() { echo "::error title=kind smoke::$*"; exit 1; }

# Polls a command until it succeeds or TIMEOUT seconds pass.
until_ok() { # <description> <command...>
  local what=$1 deadline=$((SECONDS + TIMEOUT))
  shift
  until "$@"; do
    ((SECONDS < deadline)) || fail "timed out after ${TIMEOUT}s waiting for: $what"
    sleep 5
  done
}

split_image() { # <repo:tag> -> "repo tag"
  echo "${1%:*} ${1##*:}"
}

cmd_run() {
  step "load images into kind/$CLUSTER"
  kind load docker-image --name "$CLUSTER" "$RUNNER_IMAGE" "$SCALER_IMAGE"
  endstep

  step "namespace and dummy credentials"
  kubectl --context "$CONTEXT" create namespace "$NS" --dry-run=client -o yaml \
    | kubectl --context "$CONTEXT" apply -f -
  kubectl --context "$CONTEXT" label namespace "$NS" --overwrite \
    pod-security.kubernetes.io/enforce=privileged
  # Only the token is secret; the runner group goes in as chart values.
  k create secret generic "$SECRET" \
    --from-literal=SG_NODE_TOKEN="$TOKEN" \
    --dry-run=client -o yaml | k apply -f -
  endstep

  step "helm install"
  local runner_repo runner_tag scaler_repo scaler_tag
  read -r runner_repo runner_tag <<<"$(split_image "$RUNNER_IMAGE")"
  read -r scaler_repo scaler_tag <<<"$(split_image "$SCALER_IMAGE")"
  # Small volumes: kind's local-path provisioner ignores sizes anyway.
  helm --kube-context "$CONTEXT" -n "$NS" upgrade --install "$RELEASE" "$CHART" \
    --set credentials.existingSecret="$SECRET" \
    --set sg.organization=ci-org --set sg.runnerGroup=ci-group \
    --set sg.apiUrl=http://127.0.0.1:9 \
    --set image.repository="$runner_repo" --set image.tag="$runner_tag" \
    --set image.pullPolicy=Never \
    --set scaler.image.repository="$scaler_repo" --set scaler.image.tag="$scaler_tag" \
    --set scaler.image.pullPolicy=Never \
    --set scaler.interval=5 \
    --set runner.storage.state.size=64Mi --set runner.storage.docker.size=256Mi \
    --set runner.terminationGracePeriodSeconds=5
  endstep

  step "scaler Deployment becomes Available"
  k wait --for=condition=Available "deployment/$SCALER" --timeout="${TIMEOUT}s"
  endstep

  step "scaler started and finds SG unreachable"
  # The scaler logs JSON; a failed loop against the unreachable API carries
  # reason SGUnreachable.
  until_ok "scaler log: loop failed with SGUnreachable" scaler_saw_sg_unreachable
  k logs "deployment/$SCALER" --tail=20
  endstep

  step "runner StatefulSet exists, register init container fails"
  k get "statefulset/$STS"
  until_ok "a finished run of the register init container of $STS-0" register_finished
  local logs=$REGISTER_LOG code=$REGISTER_CODE attempts
  echo "$logs" | tail -n 20
  # Exactly 1: die() on the failed SG call. 0 would mean it registered
  # against nothing; >=128 means it crashed (e.g. error reporting recursing
  # into itself while the API is down).
  [[ $code == 1 ]] || fail "register exited $code, want 1"
  grep -q "API call failed" <<<"$logs" \
    || fail "register exited 1, but not on the SG API call"
  grep -qF "$TOKEN" <<<"$logs" && fail "register printed the dummy SG_NODE_TOKEN"
  # Each failed API call logs one "API call failed": the registration call
  # plus at most one best-effort error report. More means it is retrying.
  attempts=$(grep -c "API call failed" <<<"$logs")
  ((attempts <= MAX_API_ATTEMPTS)) \
    || fail "register made $attempts failed API calls in one run, want <= $MAX_API_ATTEMPTS"
  echo "register exited 1 after $attempts failed API calls, as expected"
  endstep

  step "no credentials in logs or events"
  local all
  all=$(
    k logs "deployment/$SCALER" --all-containers 2>&1
    k logs "$STS-0" -c register --previous 2>&1 || true
    k logs "$STS-0" -c register 2>&1 || true
    k get events -o yaml 2>&1
  )
  if grep -qF "$TOKEN" <<<"$all"; then
    fail "the dummy SG_NODE_TOKEN shows up in logs or events"
  fi
  echo "dummy token not found in scaler logs, register logs or events"
  endstep

  step "scaler RBAC"
  can "patch statefulsets.apps/$STS --subresource=scale" yes
  can "get statefulsets.apps/$STS --subresource=scale" yes
  can "patch statefulsets.apps/$STS" yes
  can "create jobs.batch" yes
  # scaler.nudge: read-only on runner pods and autoscaler events.
  can "list pods" yes
  can "list events" yes
  can "patch statefulsets.apps/other --subresource=scale" no
  can "delete statefulsets.apps/$STS" no
  can "delete pods" no
  can "create pods" no
  can "get secrets" no
  can "create pods/exec" no
  endstep

  step "helm uninstall deregisters and deletes every runner's PVCs"
  # The pre-delete hook parks the runner, runs a reap Job against its state
  # PVC (never registered here: nothing to deregister), then deletes the PVCs.
  k get pvc
  helm --kube-context "$CONTEXT" -n "$NS" uninstall "$RELEASE" --timeout "${TIMEOUT}s"
  local left
  left=$(k get pvc,statefulset,deployment,job -o name 2>&1)
  [[ -z $left ]] || fail "left behind after helm uninstall: $left"
  echo "nothing left after helm uninstall"
  endstep

  echo "kind smoke passed"
}

scaler_saw_sg_unreachable() {
  k logs "deployment/$SCALER" 2>/dev/null \
    | grep '"loop failed, skipping decisions"' | grep -q '"reason":"SGUnreachable"'
}

# Sets REGISTER_CODE and REGISTER_LOG from the register init container's last
# finished run: the current container once it has terminated, else the
# previous one (it restarts in a loop). Fails until a run has finished and its
# log is retrievable.
register_finished() {
  local status prev=()
  status=$(k get pod "$STS-0" -o jsonpath='{.status.initContainerStatuses[?(@.name=="register")]}' 2>/dev/null) \
    || return 1
  REGISTER_CODE=$(jq -r '.state.terminated.exitCode // empty' <<<"$status")
  if [[ -z $REGISTER_CODE ]]; then
    REGISTER_CODE=$(jq -r '.lastState.terminated.exitCode // empty' <<<"$status")
    prev=(--previous)
  fi
  [[ -n $REGISTER_CODE ]] || return 1
  REGISTER_LOG=$(k logs "$STS-0" -c register "${prev[@]}" 2>/dev/null) || return 1
  # Gone between the two calls (restarted again): try the next round.
  [[ -n $REGISTER_LOG && $REGISTER_LOG != "unable to retrieve container logs"* ]]
}

can() { # <verb resource [flags]> <yes|no>
  local got
  # shellcheck disable=SC2086 # $1 is a verb plus resource plus flags
  got=$(k auth can-i $1 --as="$SA" 2>/dev/null || true)
  if [[ $got != "$2" ]]; then
    fail "scaler can-i '$1': got '$got', want '$2'"
  fi
  echo "can-i $1: $got"
}

cmd_diag() {
  local dir=${1:?usage: kind-smoke.sh diag DIR}
  mkdir -p "$dir"
  k get all,pvc,secret,lease,role,rolebinding,serviceaccount -o wide >"$dir/get.txt" 2>&1 || true
  k describe statefulset,deployment,pods,pvc >"$dir/describe.txt" 2>&1 || true
  k get events --sort-by=.lastTimestamp >"$dir/events.txt" 2>&1 || true
  k logs "deployment/$SCALER" --all-containers --prefix >"$dir/scaler.log" 2>&1 || true
  k logs "$STS-0" --all-containers --prefix >"$dir/runner-0.log" 2>&1 || true
  k logs "$STS-0" -c register --previous >"$dir/runner-0-register-previous.log" 2>&1 || true
  helm --kube-context "$CONTEXT" -n "$NS" get all "$RELEASE" >"$dir/helm-release.txt" 2>&1 || true
  kubectl --context "$CONTEXT" get nodes -o wide >"$dir/nodes.txt" 2>&1 || true
  # Only dummy values in this cluster, but keep secret data out regardless.
  sed -i.bak "s/$TOKEN/<redacted>/g" "$dir"/*.txt "$dir"/*.log && rm -f "$dir"/*.bak
}

case ${1:-} in
  run) cmd_run ;;
  diag) cmd_diag "${2:-}" ;;
  *)
    echo "usage: $0 run | diag DIR"
    exit 2
    ;;
esac

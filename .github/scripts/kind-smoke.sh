#!/usr/bin/env bash
# Smoke-installs the sg-runner chart on a throwaway kind cluster with locally
# built images and checks what can be checked without StackGuardian: the
# scaler starts and is ready, finds SG unreachable and leaks no credentials,
# the runner's register init container fails as expected, the scaler's
# RBAC is as narrow as intended, the native steps broker runs steps as pods
# with the chart's runner RBAC, and `helm uninstall` leaves no PVCs behind.
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
#
# CONTROLLER_REPO (optional, local runs): an sg-run-controller checkout whose
# unit/test_step_broker_live.py then runs against the broker too.
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
# Native steps: the chart's runner ServiceAccount, the broker's test pod.
RUNNER_SA=system:serviceaccount:$NS:$STS
STEPS_POD=steps-smoke
STEPS_SOCK=/var/tmp/workspace/.sg-runner/steps.sock
# A run's workspace as a run controller would lay it out.
STEPS_RUN=/var/tmp/workspace/orgs/ci/wfruns/r1
STEP_IMAGE=alpine:3.20
# Finished step pods are kept this long in the test pod (the broker's GC
# sweeps every minute).
STEPS_FINISHED_TTL=90s
# A registry host only the node's containerd knows (a hosts.toml mirror to
# Docker Hub): the node pulls it, the broker can't read its config, so the
# step runs unwrapped. (An image only `kind load`ed doesn't do: the kubelet
# re-pulls images it has no pull record for.)
MIRROR_HOST=ci-local.invalid
UNWRAPPED_STEP_IMAGE=$MIRROR_HOST/library/$STEP_IMAGE
OUTCOME_LABEL=sg-runner.stackguardian.io/outcome
WRAPPED_ANNOTATION=sg-runner.stackguardian.io/wrapped
CONTROLLER_REPO=${CONTROLLER_REPO:-}

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

  native_steps

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

can() { # <verb resource [flags]> <yes|no> [service account]
  local got as=${3:-$SA}
  # shellcheck disable=SC2086 # $1 is a verb plus resource plus flags
  got=$(k auth can-i $1 --as="$as" 2>/dev/null || true)
  if [[ $got != "$2" ]]; then
    fail "${as##*:} can-i '$1': got '$got', want '$2'"
  fi
  echo "can-i $1: $got"
}

# Native steps. The runner pod never gets past register without SG, so the
# broker runs in a test pod of its own with the chart's runner ServiceAccount
# (which also checks the chart's RBAC), next to a client container laid out
# like the runner's dockerd: the workspace PVC at /var/tmp/workspace, the
# broker's socket below it.
native_steps() {
  step "native steps: chart upgrade, broker test pod"
  helm --kube-context "$CONTEXT" -n "$NS" upgrade "$RELEASE" "$CHART" --reuse-values \
    --set runner.nativeSteps.enabled=true \
    --set runner.nativeSteps.advertise.cpu=1 --set runner.nativeSteps.advertise.memory=1Gi
  local node
  for node in $(kind get nodes --name "$CLUSTER"); do
    docker exec -i "$node" sh -c "mkdir -p /etc/containerd/certs.d/$MIRROR_HOST \
      && cat >/etc/containerd/certs.d/$MIRROR_HOST/hosts.toml" <<EOF
server = "https://registry-1.docker.io"

[host."https://registry-1.docker.io"]
  capabilities = ["pull", "resolve"]
EOF
  done
  steps_pod_manifest | k apply -f -
  k wait --for=condition=Ready "pod/$STEPS_POD" --timeout="${TIMEOUT}s"
  kc mkdir -p "$STEPS_RUN/shared-workspace"
  endstep

  step "native steps: runner RBAC"
  can "create pods" yes "$RUNNER_SA"
  can "delete pods" yes "$RUNNER_SA"
  can "get pods --subresource=log" yes "$RUNNER_SA"
  can "create secrets" yes "$RUNNER_SA"
  can "get secrets" no "$RUNNER_SA"
  can "list secrets" no "$RUNNER_SA"
  can "create pods --subresource=exec" no "$RUNNER_SA"
  can "patch statefulsets.apps/$STS" no "$RUNNER_SA"
  endstep

  step "native steps: API"
  local out id
  out=$(api GET /healthz)
  [[ $(jq -r .api <<<"$out") == v1 ]] || fail "healthz: $out"
  echo "healthz: $out"

  # 11 (approval required) and 12 (completed early) are outcomes: the
  # wrapper makes those pods end Completed. Finished pods stay, labelled.
  local code first=""
  for code in 0 1 11 12; do
    id=$(create_step "[\"sh\",\"-c\",\"exit $code\"]")
    expect_state "$id" exited "$code"
    : "${first:=$id}"
    case $code in
      0) expect_pod "$id" Succeeded Completed succeeded true ;;
      1) expect_pod "$id" Failed Error failed true ;;
      11) expect_pod "$id" Succeeded Completed approval-required true ;;
      12) expect_pod "$id" Succeeded Completed completed-early true ;;
    esac
  done
  until_ok "Secret $id-env deleted" secret_gone "$id"
  [[ -n $(k get "pod/$id" -o name --ignore-not-found) ]] || fail "step pod $id is gone already"
  echo "step $id: Secret deleted, pod kept"

  # No image config to read (the broker can't reach that registry): runs
  # unwrapped, so exit 11 stays a failed container.
  id=$(STEP_IMAGE=$UNWRAPPED_STEP_IMAGE create_step '["sh","-c","exit 11"]')
  expect_state "$id" exited 11
  expect_pod "$id" Failed Error approval-required false
  out=$(k get "pod/$id" -o json | jq -r '.metadata.annotations["sg-runner.stackguardian.io/not-wrapped-reason"] // empty')
  [[ -n $out ]] || fail "unwrapped step pod $id has no not-wrapped-reason"
  echo "not wrapped: ${out:0:120}"

  # Args reach the container as is: the kubelet would expand $(FOO). Logs
  # are read while the step still exists.
  # shellcheck disable=SC2016 # literal $(FOO) on purpose
  id=$(create_step '["echo","[$(FOO)]"]')
  out=$(api GET "/v1/steps/$id/logs?follow=1" | cut -d' ' -f2-)
  # shellcheck disable=SC2016
  [[ $out == '[$(FOO)]' ]] || fail "args: want [\$(FOO)] in the logs, got: $out"
  echo "args kept literal: $out"
  expect_state "$id" exited 0

  # Env from the step's Secret, a workspace write, log lines in order.
  # shellcheck disable=SC2016 # $FOO for the step's shell
  id=$(create_step '["sh","-c","echo env=$FOO; echo hi >/mnt/sg_workspace/out.txt; echo done"]')
  out=$(api GET "/v1/steps/$id/logs?follow=1" | cut -d' ' -f2-)
  [[ $out == $'env=bar\ndone' ]] || fail "step logs: $out"
  echo "logs: $(tr '\n' ' ' <<<"$out")"
  expect_state "$id" exited 0
  [[ $(kc cat "$STEPS_RUN/shared-workspace/out.txt") == hi ]] \
    || fail "the step's workspace write isn't visible to the client"
  echo "workspace write visible to the client"

  expect_error InvalidMount POST /v1/steps "$(step_json '["true"]' '"mounts":[{"source":"/var/tmp/workspace","target":"/w"}]')"
  expect_error InvalidMount POST /v1/steps "$(step_json '["true"]' "\"mounts\":[{\"source\":\"$STEPS_RUN/../r2/x\",\"target\":\"/w\"}]")"
  expect_error InvalidMount POST /v1/steps "$(step_json '["true"]' '"mounts":[{"source":"/var/tmp/workspace/orgs/ci/wfruns/r2/x","target":"/w"}]')"
  expect_error InvalidEnv POST /v1/steps "$(step_json '["true"]' '"env":{"BAD KEY":"x"}')"
  expect_error NotFound GET "/v1/steps/kube-apiserver-$CLUSTER-control-plane"

  id=$(STEP_IMAGE=nonexistent.invalid/nope:1 create_step '["true"]')
  expect_state "$id" failed "" 'ErrImagePull|ImagePullBackOff'
  id=$(create_step '["true"]' '"memoryMiB":9999999')
  expect_state "$id" failed "" Unschedulable

  # TERM trapped: the step exits 143 itself within the grace.
  id=$(create_step '["sh","-c","trap \"echo got TERM; exit 143\" TERM; while true; do sleep 1; done"]')
  until_ok "step $id running" step_running "$id"
  api POST "/v1/steps/$id/stop" '{"graceSeconds":30}' >/dev/null
  expect_state "$id" exited 143

  # Kept for FINISHED_TTL, then deleted by the GC; the state stays.
  until_ok "step pod $first deleted after FINISHED_TTL" step_gone "$first"
  [[ $(api GET "/v1/steps/$first" | jq -r .exitCode) == 0 ]] || fail "deleted step $first lost its exit code"
  echo "step $first deleted after FINISHED_TTL, exit code still served"
  endstep

  if [[ -n $CONTROLLER_REPO ]]; then
    controller_live_test
  fi

  step "native steps: cleanup"
  # The drain marker releases the broker (it ignores SIGTERM until then).
  kc touch /run/sg-runner/sg-runner-drained
  k delete pod "$STEPS_POD" --timeout=60s
  k delete pvc "$STEPS_POD-workspace" --timeout=60s
  # Step pods and Secrets are owned by the test pod.
  until_ok "step pods gone" steps_all_gone
  helm --kube-context "$CONTEXT" -n "$NS" upgrade "$RELEASE" "$CHART" --reuse-values \
    --set runner.nativeSteps.enabled=false
  # The runner's own workspace PVC (generic ephemeral) goes with its pod.
  until_ok "PVC $STS-0-workspace gone" runner_workspace_gone
  echo "native steps cleaned up"
  endstep
}

steps_pod_manifest() {
  cat <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: $STEPS_POD-workspace
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 64Mi
---
apiVersion: v1
kind: Pod
metadata:
  name: $STEPS_POD
spec:
  serviceAccountName: $STS
  automountServiceAccountToken: false
  terminationGracePeriodSeconds: 120
  containers:
    - name: steps
      image: $SCALER_IMAGE
      imagePullPolicy: Never
      command: [/sg-runner-steps]
      args: [serve]
      env:
        - name: RUNNER_POD_NAME
          valueFrom: { fieldRef: { fieldPath: metadata.name } }
        - name: RUNNER_POD_UID
          valueFrom: { fieldRef: { fieldPath: metadata.uid } }
        - name: NODE_NAME
          valueFrom: { fieldRef: { fieldPath: spec.nodeName } }
        - name: NAMESPACE
          valueFrom: { fieldRef: { fieldPath: metadata.namespace } }
        - { name: SOCKET_PATH, value: /run/sg-steps/steps.sock }
        - { name: WORKSPACES_DIR, value: /var/tmp/workspace }
        - { name: WORKSPACE_CLAIM, value: $STEPS_POD-workspace }
        - name: STEP_LABELS
          value: '{"app.kubernetes.io/name":"sg-runner","app.kubernetes.io/instance":"$RELEASE","app.kubernetes.io/component":"step"}'
        - { name: SCHEDULING_TIMEOUT, value: 20s }
        - { name: START_TIMEOUT, value: 60s }
        - { name: FINISHED_TTL, value: $STEPS_FINISHED_TTL }
        # Its own image, for the step pods' wrapper init container.
        - { name: BROKER_IMAGE, value: $SCALER_IMAGE }
        - { name: BROKER_IMAGE_PULL_POLICY, value: Never }
        - { name: DRAINED_MARKER, value: /run/sg-runner/sg-runner-drained }
      lifecycle:
        preStop:
          exec:
            command: [/sg-runner-steps, wait-drained]
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: { drop: [ALL] }
        seccompProfile: { type: RuntimeDefault }
      volumeMounts:
        - { name: socket, mountPath: /run/sg-steps }
        - { name: drained, mountPath: /run/sg-runner, readOnly: true }
        - { name: api-access, mountPath: /var/run/secrets/kubernetes.io/serviceaccount, readOnly: true }
    - name: client
      image: python:3.11-alpine
      # PID 1 ignores SIGTERM without a handler: trap it, or deleting the pod
      # waits out the grace period.
      command: [sh, -c, 'trap "exit 0" TERM; apk add --no-cache curl >/dev/null && touch /tmp/ready; sleep infinity & wait']
      readinessProbe:
        exec: { command: [test, -e, /tmp/ready] }
        periodSeconds: 2
      volumeMounts:
        - { name: workspace, mountPath: /var/tmp/workspace }
        - { name: socket, mountPath: /var/tmp/workspace/.sg-runner }
        - { name: drained, mountPath: /run/sg-runner }
  volumes:
    - name: workspace
      persistentVolumeClaim: { claimName: $STEPS_POD-workspace }
    - name: socket
      emptyDir: {}
    - name: drained
      emptyDir: {}
    # As the chart's steps container gets it.
    - name: api-access
      projected:
        defaultMode: 0444
        sources:
          - serviceAccountToken: { path: token, expirationSeconds: 3607 }
          - configMap:
              name: kube-root-ca.crt
              items: [{ key: ca.crt, path: ca.crt }]
          - downwardAPI:
              items:
                - path: namespace
                  fieldRef: { apiVersion: v1, fieldPath: metadata.namespace }
EOF
}

# In the client container.
kc() { k exec "$STEPS_POD" -c client -- "$@"; }

# Calls the broker; prints the body, fails on a curl error (not on a 4xx).
api() { # <method> <path> [json body]
  local args=(curl -sS --unix-socket "$STEPS_SOCK" -X "$1" "http://broker$2")
  [[ -n ${3:-} ]] && args+=(-H 'Content-Type: application/json' -d "$3")
  kc "${args[@]}"
}

step_json() { # <args json> [extra fields]
  echo "{\"name\":\"ci-r1-step\",\"org\":\"/orgs/ci\",\"run\":\"/wfruns/r1\",\"stepIdx\":0,
    \"image\":\"$STEP_IMAGE\",\"args\":$1,\"env\":{\"FOO\":\"bar\"},
    \"mounts\":[{\"source\":\"$STEPS_RUN/shared-workspace\",\"target\":\"/mnt/sg_workspace\",\"readOnly\":false}],
    \"cpuShares\":64,\"memoryMiB\":64,\"timeoutSeconds\":300${2:+,$2}}"
}

create_step() { # <args json> [extra fields] -> id
  local out id
  out=$(api POST /v1/steps "$(step_json "$@")")
  id=$(jq -r '.id // empty' <<<"$out")
  [[ -n $id ]] || fail "create step: $out"
  echo "$id"
}

# Waits for a terminal state and checks it.
expect_state() { # <id> <exited|failed> <exit code or ""> [reason regex]
  local id=$1 want=$2 code=$3 reason=${4:-} st
  until_ok "step $id terminal" step_terminal "$id"
  st=$STEP_STATE
  [[ $(jq -r .state <<<"$st") == "$want" ]] || fail "step $id: want $want, got $st"
  if [[ -n $code ]]; then
    [[ $(jq -r .exitCode <<<"$st") == "$code" ]] || fail "step $id: want exit code $code, got $st"
  fi
  if [[ -n $reason ]]; then
    [[ $(jq -r .reason <<<"$st") =~ ^($reason)$ ]] || fail "step $id: want reason $reason, got $st"
  fi
  echo "step $id: $(jq -c '{state, exitCode, reason}' <<<"$st")"
}

step_terminal() {
  STEP_STATE=$(api GET "/v1/steps/$1") || return 1
  [[ $(jq -r .state <<<"$STEP_STATE") =~ ^(exited|failed)$ ]]
}

step_running() {
  [[ $(api GET "/v1/steps/$1" | jq -r .state) == running ]]
}

step_gone() {
  [[ -z $(k get "pod/$1" "secret/$1-env" -o name --ignore-not-found 2>/dev/null) ]]
}

secret_gone() {
  [[ -z $(k get "secret/$1-env" -o name --ignore-not-found 2>/dev/null) ]]
}

# A finished step pod as the broker leaves it.
expect_pod() { # <id> <phase> <container reason> <outcome> <wrapped>
  local got want="$2 $3 $4 $5"
  until_ok "step pod $1 labelled" step_labelled "$1"
  got=$(k get "pod/$1" -o json | jq -r --arg l "$OUTCOME_LABEL" --arg a "$WRAPPED_ANNOTATION" '
    [.status.phase,
     (.status.containerStatuses[] | select(.name == "step") | .state.terminated.reason),
     .metadata.labels[$l], .metadata.annotations[$a]] | join(" ")')
  [[ $got == "$want" ]] || fail "step pod $1: want '$want' (phase reason outcome wrapped), got '$got'"
  echo "step pod $1: $got"
}

step_labelled() {
  k get "pod/$1" -o json 2>/dev/null | jq -e --arg l "$OUTCOME_LABEL" '.metadata.labels[$l] // empty' >/dev/null
}

steps_all_gone() {
  [[ -z $(k get pods,secrets -l app.kubernetes.io/component=step -o name 2>/dev/null) ]]
}

runner_workspace_gone() {
  [[ -z $(k get pvc "$STS-0-workspace" -o name --ignore-not-found 2>/dev/null) ]]
}

expect_error() { # <reason> <method> <path> [json body]
  local want=$1 out
  shift
  out=$(api "$@")
  [[ $(jq -r .reason <<<"$out" 2>/dev/null) == "$want" ]] || fail "$1 $2: want $want, got $out"
  echo "$1 $2: $want"
}

# The run controller's live broker test (unit/test_step_broker_live.py) from a
# local sg-run-controller checkout, in the client container.
controller_live_test() {
  step "native steps: run controller live test"
  local test=$CONTROLLER_REPO/unit/test_step_broker_live.py
  [[ -f $test ]] || fail "CONTROLLER_REPO is set, but $test doesn't exist"
  kc mkdir -p /tmp/controller/unit
  tar -C "$CONTROLLER_REPO" -cf - src/run_controller unit/test_step_broker_live.py \
    | k exec -i "$STEPS_POD" -c client -- tar -C /tmp/controller -xf -
  kc pip install -q --root-user-action=ignore --disable-pip-version-check docker==6.0.1 requests==2.31.0 'urllib3<2' pytest
  kc sh -c "cd /tmp/controller && STEP_BROKER_SOCKET=$STEPS_SOCK STEP_BROKER_WORKSPACES_DIR=/var/tmp/workspace \
    STEP_BROKER_IMAGE=$STEP_IMAGE \
    PYTHONPATH=src:src/run_controller python -m pytest -q unit/test_step_broker_live.py"
  endstep
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
  # Native steps: the broker test pod and its step pods.
  k logs "$STEPS_POD" --all-containers --prefix >"$dir/steps-smoke.log" 2>&1 || true
  k get pods,secrets -l app.kubernetes.io/component=step -o wide >"$dir/step-pods.txt" 2>&1 || true
  k describe pods -l app.kubernetes.io/component=step >"$dir/step-pods-describe.txt" 2>&1 || true
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

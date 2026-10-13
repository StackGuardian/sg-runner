#!/bin/bash
#
# sg-runner scaler (prototype): sizes the runner StatefulSet from the runner
# group's state in SG, and deregisters runners parked for too long.
#
# Every SCALER_INTERVAL seconds:
#   out   workflows queued and no awake runner fully idle → one more runner
#         (wakes a parked one if its PVC is there, registers a new one
#         otherwise). With a runner fully idle, SG's next retry places queued
#         work there if it fits; another runner of the same size can't help.
#         Optional headroom: with SCALER_HEADROOM_PCT > 0, also scale out when
#         less than that share of the awake runners' CPU or memory is free,
#         so the next workflow finds a warm runner instead of queueing.
#   in    nothing queued and the highest awake runner idle for
#         SCALER_IDLE_SECONDS, and the rest keeps the headroom → park it (StatefulSets always remove the
#         highest ordinal, so that's the only one worth checking)
#   reap  runner parked longer than SCALER_PARK_TTL → deregister it from its
#         PVC (a Job running `runner.sh reap`), then delete its PVCs
#   stuck workflows queued while an awake runner sat fully idle for
#         SCALER_STUCK_SECONDS → what's queued fits no runner (bigger than a
#         runner pod), so more runners of the same size won't help: ignore
#         the queue (no scale out for it, park as if empty) and warn
#
# Replicas stay within [SCALER_MIN, max], where max is the lower of SCALER_MAX
# and the runner group's MaxNumberOfRunners. SCALER_MIN >= 1: SG pauses
# workflows when no runner is ACTIVE and connected.
#
# All SG calls use the runner group's node token.

set -o pipefail

# shellcheck source-path=SCRIPTDIR source=runner.sh
source /opt/sg-runner/runner.sh

SCALER_INTERVAL="${SCALER_INTERVAL:-15}"
SCALER_MIN="${SCALER_MIN:-1}"
SCALER_MAX="${SCALER_MAX:-10}"
# Share of awake capacity to keep free; 0 = off (scale out on the queue only).
SCALER_HEADROOM_PCT="${SCALER_HEADROOM_PCT:-0}"
SCALER_IDLE_SECONDS="${SCALER_IDLE_SECONDS:-60}"
SCALER_PARK_TTL="${SCALER_PARK_TTL:-43200}"
# Longer than SG's retry delay for queued workflows.
SCALER_STUCK_SECONDS="${SCALER_STUCK_SECONDS:-180}"
# How long to wait for an awake runner to connect before deciding without it.
SCALER_SETTLE_TIMEOUT="${SCALER_SETTLE_TIMEOUT:-300}"
SCALER_STATEFULSET="${SCALER_STATEFULSET:-sg-runner}"
SCALER_IMAGE="${SCALER_IMAGE:-sg-runner-k8s:dev}"
# The runner group's SG credentials, mounted by reap Jobs.
SCALER_CREDENTIALS_SECRET="${SCALER_CREDENTIALS_SECRET:-sg-runner-credentials}"

readonly SA_DIR="/var/run/secrets/kubernetes.io/serviceaccount"
readonly PARKED_AT_ANNOTATION="sg-runner.stackguardian.io/parked-at"

# Ordinal of the highest awake runner -> epoch it was first seen idle.
declare -A IDLE_SINCE=()
# Since when workflows have been queued while an awake runner was fully idle.
STUCK_SINCE=""
# Ordinal of an awake runner not connected to SG -> epoch first seen so.
declare -A UNCONNECTED_SINCE=()

log() {
  printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"
}

kube() { #{{{
  # Usage: kube <method> <path> [body]
  # Kubernetes API call with the scaler's service account. PATCH bodies are
  # merge patches, POST bodies plain JSON.
  local method="$1" path="$2" body="${3:-}" content_type="application/json"
  [[ "$method" == PATCH ]] && content_type="application/merge-patch+json"
  local args=(-fsS --max-time 10 -X "$method"
    --cacert "$SA_DIR/ca.crt"
    -H "Authorization: Bearer $(<"$SA_DIR/token")")
  [[ -n "$body" ]] && args+=(-H "Content-Type: $content_type" -d "$body")
  curl "${args[@]}" "https://kubernetes.default.svc/${path#/}"
}
#}}}: kube

sg_runner_group() { #{{{
  # Prints the runner group as SG reports it, with active workflow counts.
  # It holds secrets (the group's runner token): only extract fields from it.
  # Subshell: api_call exits on an empty response, the loop must not.
  (
    api_call GET \
      "${SG_BASE_API}/orgs/${SG_ORGANIZATION}/runnergroups/${SG_RUNNER_GROUP}/?getActiveWorkflows=true" \
      >/dev/null 2>&1 &&
      printf '%s' "$response"
  )
}
#}}}: sg_runner_group

summarize_group() { #{{{
  # stdin: runner group JSON. Prints what scaling needs, with each SG runner
  # mapped to its StatefulSet ordinal through its hostname (the pod's FQDN).
  jq -c --arg sts "$SCALER_STATEFULSET" '
    def res($list; $name): [($list // [])[] | select(.name == $name) | .integerValue][0] // 0;
    .msg | {
      queued: (.QueuedWorkflowsCount // 0),
      max_runners: .MaxNumberOfRunners,
      runners: [(.ContainerInstances // [])[] | {
        ordinal: (try (.instanceDetails[0].ComputerName
          | capture("^" + $sts + "-(?<n>[0-9]+)\\.").n | tonumber) catch null),
        status,
        connected: (.agentConnected == true),
        busy: ((.runningTasksCount // 0) + (.pendingTasksCount // 0)),
        cpu: res(.registeredResources; "CPU"),
        cpu_free: res(.remainingResources; "CPU"),
        mem: res(.registeredResources; "MEMORY"),
        mem_free: res(.remainingResources; "MEMORY")
      } | select(.ordinal != null)]
    }'
}
#}}}: summarize_group

reserved_pct() { #{{{
  # Usage: reserved_pct <summary> <below-ordinal>
  # Percent of CPU or memory (whichever is higher) reserved on runners with an
  # ordinal below the given one that are ACTIVE and connected. 100 if none.
  jq -r --argjson below "$2" '
    [.runners[] | select(.ordinal < $below and .status == "ACTIVE" and .connected)] as $r
    | if ($r | length) == 0 then 100 else
        ([$r[].cpu] | add) as $cpu | ([$r[].mem] | add) as $mem
        | [(($cpu - ([$r[].cpu_free] | add)) * 100 / ([$cpu, 1] | max)),
           (($mem - ([$r[].mem_free] | add)) * 100 / ([$mem, 1] | max))]
        | max | floor
      end' <<<"$1"
}
#}}}: reserved_pct

set_replicas() { #{{{
  kube PATCH "apis/apps/v1/namespaces/${NS}/statefulsets/${SCALER_STATEFULSET}/scale" \
    "{\"spec\":{\"replicas\":$1}}" >/dev/null
}
#}}}: set_replicas

annotate_pvc() { #{{{
  # Usage: annotate_pvc <name> <value|null>
  local value="null"
  [[ "$2" != null ]] && value="\"$2\""
  kube PATCH "api/v1/namespaces/${NS}/persistentvolumeclaims/$1" \
    "{\"metadata\":{\"annotations\":{\"${PARKED_AT_ANNOTATION}\":${value}}}}" >/dev/null
}
#}}}: annotate_pvc

reap_job() { #{{{
  # Usage: reap_job <ordinal>; prints the Job manifest.
  local n="$1"
  jq -n --arg n "$n" --arg sts "$SCALER_STATEFULSET" --arg image "$SCALER_IMAGE" \
    --arg secret "$SCALER_CREDENTIALS_SECRET" '{
    apiVersion: "batch/v1", kind: "Job",
    metadata: {name: "\($sts)-reap-\($n)", labels: {app: "\($sts)-reaper"}},
    spec: {backoffLimit: 0, template: {spec: {
      restartPolicy: "Never",
      automountServiceAccountToken: false,
      containers: [{
        name: "reap", image: $image, imagePullPolicy: "IfNotPresent", args: ["reap"],
        volumeMounts: [
          {name: "state", mountPath: "/etc/ecs", subPath: "ecs-config"},
          {name: "state", mountPath: "/var/lib/ecs/data", subPath: "ecs-data"},
          {name: "state", mountPath: "/var/lib/amazon/ssm", subPath: "ssm"},
          {name: "sg-credentials", mountPath: "/etc/sg-runner/credentials", readOnly: true}
        ]
      }],
      volumes: [
        {name: "state", persistentVolumeClaim: {claimName: "state-\($sts)-\($n)"}},
        {name: "sg-credentials", secret: {secretName: $secret, defaultMode: 256}}
      ]
    }}}
  }'
}
#}}}: reap_job

reap_parked() { #{{{
  # Usage: reap_parked <replicas>
  # Stamps newly parked runners and deregisters those parked past the TTL.
  local replicas="$1" now pvcs pvc n parked_at job job_state
  now="$(date +%s)"
  pvcs="$(kube GET "api/v1/namespaces/${NS}/persistentvolumeclaims")" || return

  while IFS=$'\t' read -r pvc parked_at; do
    n="${pvc##*-}"
    [[ "$n" =~ ^[0-9]+$ ]] || continue

    if ((n < replicas)); then
      # Awake again: clear a stale stamp.
      [[ -n "$parked_at" ]] && annotate_pvc "$pvc" null
      continue
    fi
    if [[ -z "$parked_at" ]]; then
      annotate_pvc "$pvc" "$now"
      log "runner $n parked"
      continue
    fi
    ((now - parked_at >= SCALER_PARK_TTL)) || continue

    job="${SCALER_STATEFULSET}-reap-${n}"
    job_state="$(kube GET "apis/batch/v1/namespaces/${NS}/jobs/${job}" 2>/dev/null |
      jq -r 'if .status.succeeded then "done" elif .status.failed then "failed" else "running" end')"
    case "$job_state" in
    "")
      log "runner $n parked for $((now - parked_at))s: deregistering"
      kube POST "apis/batch/v1/namespaces/${NS}/jobs" "$(reap_job "$n")" >/dev/null
      ;;
    done)
      log "runner $n deregistered: deleting its PVCs"
      kube DELETE "api/v1/namespaces/${NS}/persistentvolumeclaims/${pvc}" >/dev/null
      kube DELETE "api/v1/namespaces/${NS}/persistentvolumeclaims/docker-${SCALER_STATEFULSET}-${n}" >/dev/null
      kube DELETE "apis/batch/v1/namespaces/${NS}/jobs/${job}?propagationPolicy=Background" >/dev/null
      ;;
    failed)
      # Keep the identity; retry on a later loop.
      log "runner $n: deregistration failed, retrying (see job/${job})"
      kube DELETE "apis/batch/v1/namespaces/${NS}/jobs/${job}?propagationPolicy=Background" >/dev/null
      ;;
    esac
  done < <(jq -r --arg prefix "state-${SCALER_STATEFULSET}-" --arg a "$PARKED_AT_ANNOTATION" '
    .items[] | select(.metadata.name | startswith($prefix))
    | [.metadata.name, (.metadata.annotations[$a] // "")] | @tsv' <<<"$pvcs")
}
#}}}: reap_parked

reaping() { #{{{
  # Usage: reaping <ordinal>; true while a reap Job holds that runner's PVC.
  kube GET "apis/batch/v1/namespaces/${NS}/jobs/${SCALER_STATEFULSET}-reap-$1" >/dev/null 2>&1
}
#}}}: reaping

scale() { #{{{
  local group summary replicas queued max top top_runner pct free free_without_top now settling
  group="$(sg_runner_group)" || {
    log "can't read the runner group from SG"
    return
  }
  summary="$(summarize_group <<<"$group")" || return
  replicas="$(kube GET "apis/apps/v1/namespaces/${NS}/statefulsets/${SCALER_STATEFULSET}" |
    jq -r '.spec.replicas')" || return

  queued="$(jq -r '.queued' <<<"$summary")"
  max="$(jq -r --argjson max "$SCALER_MAX" '[.max_runners // $max, $max] | min' <<<"$summary")"
  pct="$(reserved_pct "$summary" "$replicas")"
  free=$((100 - pct))
  # A runner that is awake but not yet connected: let it settle before
  # deciding again, or one queued workflow wakes several runners. One that
  # never connects (failed registration, crash loop) mustn't freeze scaling:
  # past SCALER_SETTLE_TIMEOUT it's left out and reported.
  local unconnected n
  unconnected="$(jq -r --argjson r "$replicas" '
    [range(0; $r)] - [.runners[] | select(.connected) | .ordinal] | .[]' <<<"$summary")"
  now="$(date +%s)"
  for n in "${!UNCONNECTED_SINCE[@]}"; do
    grep -qx "$n" <<<"$unconnected" || unset "UNCONNECTED_SINCE[$n]"
  done
  settling=0
  for n in $unconnected; do
    : "${UNCONNECTED_SINCE[$n]:=$now}"
    if ((now - UNCONNECTED_SINCE[$n] < SCALER_SETTLE_TIMEOUT)); then
      settling=$((settling + 1))
    else
      log "WARNING: runner $n awake but not connected to SG for $((now - UNCONNECTED_SINCE[$n]))s;" \
        "scaling without it (check pod/${SCALER_STATEFULSET}-$n)"
    fi
  done

  # Queued while a runner sits fully idle: once that lasts past SG's retry
  # delay, the queued workflows don't fit on a runner of this size.
  local stuck=false idle_runner
  idle_runner="$(jq -r --argjson r "$replicas" '[.runners[] | select(.ordinal < $r
      and .status == "ACTIVE" and .connected and .busy == 0 and .cpu_free == .cpu
      and .mem_free == .mem)] | first | if . then "\(.cpu)/\(.mem)" else "" end' <<<"$summary")"
  if ((queued > 0)) && [[ -n "$idle_runner" ]]; then
    : "${STUCK_SINCE:=$now}"
    if ((now - STUCK_SINCE >= SCALER_STUCK_SECONDS)); then
      stuck=true
      log "WARNING: $queued workflow(s) queued for $((now - STUCK_SINCE))s while a runner" \
        "(CPU/MiB $idle_runner) sits idle: they need more than one runner pod offers." \
        "Ignoring them; raise the dockerd container's limits to run them."
    fi
  else
    STUCK_SINCE=""
  fi

  log "replicas=$replicas max=$max queued=$queued reserved=${pct}% free=${free}% settling=$settling stuck=$stuck"

  if ((settling > 0)); then
    :
  elif ((replicas < max)) && { { ((queued > 0)) && [[ -z "$idle_runner" ]]; } ||
    ((free < SCALER_HEADROOM_PCT)); }; then
    if reaping "$replicas"; then
      log "scale out waits: runner $replicas is being deregistered"
    else
      log "scale out: $replicas -> $((replicas + 1))"
      set_replicas $((replicas + 1))
      IDLE_SINCE=()
      # The new runner starts idle: don't mistake it for a stuck queue.
      STUCK_SINCE=""
    fi
  elif ((replicas > SCALER_MIN)) && { ((queued == 0)) || [[ "$stuck" == true ]]; }; then
    top=$((replicas - 1))
    top_runner="$(jq -c --argjson n "$top" '.runners[] | select(.ordinal == $n)' <<<"$summary")"
    if [[ "$(jq -r '.busy' <<<"$top_runner")" != 0 ]]; then
      unset "IDLE_SINCE[$top]"
    else
      : "${IDLE_SINCE[$top]:=$now}"
      # Don't park into a scale out: the rest must keep the headroom.
      free_without_top=$((100 - $(reserved_pct "$summary" "$top")))
      if ((now - IDLE_SINCE[$top] >= SCALER_IDLE_SECONDS && free_without_top >= SCALER_HEADROOM_PCT)); then
        log "scale in: runner $top idle for $((now - IDLE_SINCE[$top]))s, parking ($replicas -> $top)"
        set_replicas "$top"
        unset "IDLE_SINCE[$top]"
      fi
    fi
  fi

  reap_parked "$(kube GET "apis/apps/v1/namespaces/${NS}/statefulsets/${SCALER_STATEFULSET}" |
    jq -r '.spec.replicas')"
}
#}}}: scale

main() {
  if ((SCALER_MIN < 1)); then
    log "SCALER_MIN=$SCALER_MIN raised to 1: SG pauses workflows without an ACTIVE runner"
    SCALER_MIN=1
  fi
  NS="$(<"$SA_DIR/namespace")"
  load_sg_credentials_from_dir
  log "scaling statefulset/${SCALER_STATEFULSET}: min=$SCALER_MIN max=$SCALER_MAX" \
    "headroom=${SCALER_HEADROOM_PCT}% idle=${SCALER_IDLE_SECONDS}s park-ttl=${SCALER_PARK_TTL}s" \
    "stuck-after=${SCALER_STUCK_SECONDS}s settle-timeout=${SCALER_SETTLE_TIMEOUT}s"
  while :; do
    scale
    sleep "$SCALER_INTERVAL"
  done
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main
fi

#!/bin/bash
#
# Kubernetes entrypoint for the sg-runner pod (prototype).
#
# One pod plays the part of one registered runner host. Each subcommand backs
# one container of the StatefulSet, standing in for what systemd and
# ecs-anywhere-install.sh do on a VM:
#
#   register    init container: SG API registration + SSM hybrid activation
#   dockerd     privileged: nested Docker daemon + main.sh network setup
#   ssm-agent   amazon-ssm-agent; shares rotating creds via /root/.aws
#   ecs-agent   ECS agent binary, configured from ecs.config (replaces ecs-init)
#   drain       ecs-agent preStop: DRAINING, wait for workflows, park (keep registration)
#   wait-drained  dockerd/ssm-agent preStop: outlive the drain
#   deregister  run via `kubectl exec -i`; reads SG credentials from stdin
#   reap        scaler Job: deregister a runner parked too long, from its PVC
#
# main.sh is sourced for the API, config and network helpers; its
# BASH_SOURCE guard keeps main() from running.

set -o pipefail

# Next to this script in the image (/opt/sg-runner), one level up in the repo
# (k8s/runner.sh, main.sh), where the tests source it from.
RUNNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -r "$RUNNER_DIR/main.sh" ]]; then
  # shellcheck source-path=SCRIPTDIR/.. source=main.sh
  source "$RUNNER_DIR/main.sh"
else
  # shellcheck source-path=SCRIPTDIR/.. source=main.sh
  source "$RUNNER_DIR/../main.sh"
fi

readonly SSM_DIR="/var/lib/amazon/ssm"
readonly SSM_REGISTRATION_FILE="${SSM_DIR}/Vault/Store/RegistrationKey"
readonly AGENT_CREDS_FILE="/rotatingcreds/credentials"
readonly SG_CRED_KEYS="SG_NODE_TOKEN SG_ORGANIZATION SG_RUNNER_GROUP SG_BASE_API"
readonly SG_CREDS_DIR="/etc/sg-runner/credentials"
# On the emptyDir shared by every container: tells the others the drain is over.
readonly DRAINED_MARKER="/var/run/sg-runner-drained"
# On the state PVC: this pod drained the runner when it parked, so the next
# start may set it ACTIVE again. Absent when someone else drained it on purpose.
readonly SELF_DRAIN_MARKER="$ECS_CONFIG_DIR/.parked"
readonly AGENT_API="http://localhost:51678/v1"

# Memory kept back for dockerd/containerd themselves, out of the dockerd
# container's limit, when sizing what the agent advertises.
SG_DOCKERD_OVERHEAD_MIB="${SG_DOCKERD_OVERHEAD_MIB:-256}"

# Nested Docker cleanup (prune_loop), in place of the VM's `main.sh prune`
# cron. Every interval (0 = off), remove stopped containers, dangling images
# and build cache older than SG_PRUNE_UNTIL, and unused volumes. Unused images
# are the wake-up cache, so they only go once the Docker volume is
# SG_PRUNE_IMAGES_ABOVE_PCT full (0 = every run).
SG_PRUNE_INTERVAL_SECONDS="${SG_PRUNE_INTERVAL_SECONDS:-14400}"
SG_PRUNE_UNTIL="${SG_PRUNE_UNTIL:-24h}"
SG_PRUNE_IMAGES_ABOVE_PCT="${SG_PRUNE_IMAGES_ABOVE_PCT:-70}"
DOCKER_DATA_ROOT="${DOCKER_DATA_ROOT:-/var/lib/docker}"

# What the agent sizing reads; overridable so tests can feed fake files.
PROC_STATUS_FILE="${PROC_STATUS_FILE:-/proc/self/status}"
MEMINFO_FILE="${MEMINFO_FILE:-/proc/meminfo}"

CONTAINER_ORCHESTRATOR="docker"

wait_for() { #{{{
  # Usage: wait_for <description> <command...>
  local what="$1"
  shift
  until "$@" >&/dev/null; do
    info "Waiting for" "$what"
    sleep 3
  done
}
#}}}: wait_for

load_sg_credentials() { #{{{
  # Map the k8s-friendly names onto the globals main.sh expects.
  SG_NODE_TOKEN="${SG_NODE_TOKEN:-}"
  ORGANIZATION_ID="${SG_ORGANIZATION:-}"
  RUNNER_GROUP_ID="${SG_RUNNER_GROUP:-}"
  check_sg_args
}
#}}}: load_sg_credentials

is_registered() {
  [[ -s "$ECS_CONFIG_DIR/ecs.config" && -s "$SSM_REGISTRATION_FILE" ]]
}

cmd_register() { #{{{
  if is_registered; then
    info "Already registered, reusing state from" "$ECS_CONFIG_DIR/ecs.config"
    return 0
  fi
  if [[ -s "$ECS_CONFIG_DIR/ecs.config" || -s "$SSM_REGISTRATION_FILE" ]]; then
    die "Partial registration state found." "Deregister and wipe the PVC before retrying."
  fi

  load_sg_credentials
  fetch_organization_info

  info "Registering SSM agent in" "$LOCAL_AWS_DEFAULT_REGION"
  if ! amazon-ssm-agent -register -y \
    -code "$SSM_ACTIVATION_CODE" \
    -id "$SSM_ACTIVATION_ID" \
    -region "$LOCAL_AWS_DEFAULT_REGION" >>"$LOG_FILE" 2>&1; then
    log_err
    die "SSM registration failed." "See $LOG_FILE"
  fi
  info "SSM managed instance" "$(jq -r '.instanceID' "$SSM_REGISTRATION_FILE")"

  # Written last: its presence marks a complete registration.
  configure_local_data
  save_registration_details
}
#}}}: cmd_register

cmd_dockerd() { #{{{
  # cgroup v2 nesting, as in moby's hack/dind: move our processes out of the
  # root cgroup so controllers can be delegated to the inner containers.
  if [[ -f /sys/fs/cgroup/cgroup.controllers ]]; then
    mkdir -p /sys/fs/cgroup/init
    xargs -rn1 </sys/fs/cgroup/cgroup.procs >/sys/fs/cgroup/init/cgroup.procs 2>/dev/null || :
    sed -e 's/ / +/g' -e 's/^/+/' </sys/fs/cgroup/cgroup.controllers \
      >/sys/fs/cgroup/cgroup.subtree_control
  fi

  dockerd --host=unix:///var/run/docker.sock &
  local dockerd_pid=$! prune_pid=""
  trap 'kill -TERM $prune_pid "$dockerd_pid" 2>/dev/null; wait "$dockerd_pid"' TERM INT

  wait_for "dockerd" docker info
  # Same bridge, IMDS block and task-credential DNAT as on a VM. Rules land in
  # the pod's network namespace, not the node's.
  configure_local_network
  info "Docker ready, network" "$SG_DOCKER_NETWORK"

  if prune_enabled; then
    prune_loop &
    prune_pid=$!
  else
    info "Docker prune disabled:" "SG_PRUNE_INTERVAL_SECONDS=$SG_PRUNE_INTERVAL_SECONDS"
  fi

  wait "$dockerd_pid"
}
#}}}: cmd_dockerd

prune_enabled() {
  [[ "$SG_PRUNE_INTERVAL_SECONDS" =~ ^[0-9]+$ ]] && ((SG_PRUNE_INTERVAL_SECONDS > 0))
}

docker_disk_used_pct() { #{{{
  # Prints how full the filesystem holding Docker's data is, as a bare number.
  df -P "$DOCKER_DATA_ROOT" 2>/dev/null | awk 'NR == 2 {sub(/%/, "", $5); print $5}'
}
#}}}: docker_disk_used_pct

should_prune_images() { #{{{
  # Usage: should_prune_images <used_pct>
  # Unused images are kept as the wake-up cache until the disk is filling up.
  # An unknown usage counts as full: better a cold cache than a full PVC.
  local used="$1" threshold="$SG_PRUNE_IMAGES_ABOVE_PCT"
  [[ "$threshold" =~ ^[0-9]+$ ]] || threshold=70
  [[ "$used" =~ ^[0-9]+$ ]] || return 0
  ((threshold == 0 || used >= threshold))
}
#}}}: should_prune_images

docker_prune() { #{{{
  # Usage: docker_prune <docker args...>
  # Runs one prune and prints the space it reclaimed (0B when docker reports
  # none: `builder prune` prints "Total:", the others "Total reclaimed space:").
  local out space
  if ! out="$(docker "$@" 2>&1)"; then
    info "docker $* failed:" "$(tail -n1 <<<"$out")" >&2
    printf 'failed'
    return 1
  fi
  space="$(sed -nE 's/^Total( reclaimed space)?:[[:space:]]*//p' <<<"$out" | tail -n1)"
  printf '%s' "${space:-0B}"
}
#}}}: docker_prune

prune_docker() { #{{{
  # One cleanup pass over the nested Docker. Never a bare `system prune`: it
  # removes every non-running container regardless of age, including ones the
  # ECS agent has created but not started yet (see main.sh prune()). Every
  # container-touching sweep carries the until= age guard.
  local filter="until=$SG_PRUNE_UNTIL" used all=() containers images build volumes
  containers="$(docker_prune container prune -f --filter "$filter")"

  used="$(docker_disk_used_pct)"
  # -a: unused images too, not just dangling ones. `until` is the image's
  # creation time, not when it was pulled or last used, so it's no LRU: under
  # pressure, every unused image older than that goes.
  should_prune_images "$used" && all=(-a)
  images="$(docker_prune image prune -f "${all[@]}" --filter "$filter")"

  build="$(docker_prune builder prune -f --filter "$filter")"
  # Anonymous volumes no container (in any state) refers to. Separate from the
  # container sweep on purpose: this one can't remove a container.
  volumes="$(docker_prune volume prune -f)"

  info "Docker prune ($filter, disk ${used:-?}% used${all[*]:+, unused images too}) reclaimed:" \
    "containers $containers, images $images, build cache $build, volumes $volumes"
}
#}}}: prune_docker

prune_loop() { #{{{
  # Runs once right away, then every interval: a pod may park within minutes
  # of waking and never see a full interval, so its first pass can't wait for
  # one. Each pass runs in a subshell so a failing docker call or a stray exit
  # can't end the loop.
  local sleep_pid=""
  trap 'kill $sleep_pid 2>/dev/null; exit 0' TERM INT
  info "Docker prune every" "${SG_PRUNE_INTERVAL_SECONDS}s, keeping anything newer than $SG_PRUNE_UNTIL"
  while :; do
    (prune_docker) || info "Docker prune failed;" "retrying in ${SG_PRUNE_INTERVAL_SECONDS}s"
    sleep "$SG_PRUNE_INTERVAL_SECONDS" &
    sleep_pid=$!
    wait "$sleep_pid"
  done
}
#}}}: prune_loop

cmd_ssm_agent() { #{{{
  wait_for "SSM registration" test -s "$SSM_REGISTRATION_FILE"
  exec amazon-ssm-agent
}
#}}}: cmd_ssm_agent

load_ecs_config() { #{{{
  # ecs-init normally turns ecs.config into the agent's environment. Read it
  # line by line: ECS_INSTANCE_ATTRIBUTES holds JSON that `source` would mangle.
  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    export "${line%%=*}=${line#*=}"
  done <"$ECS_CONFIG_DIR/ecs.config"
}
#}}}: load_ecs_config

size_agent_memory() { #{{{
  # The agent advertises MemTotal from /proc/meminfo, which is the whole node.
  # Tasks run inside the dockerd container, so advertise its limit (downward
  # API) minus dockerd's own overhead, by reserving the difference.
  local limit="${SG_TASK_MEMORY_LIMIT_MIB:-}" total available reserved
  [[ "$limit" =~ ^[0-9]+$ ]] || return 0

  total=$(($(awk '/^MemTotal:/ {print $2}' "$MEMINFO_FILE") / 1024))
  available=$((limit - SG_DOCKERD_OVERHEAD_MIB))
  reserved=$((total > available ? total - available : 0))
  # The agent parses this as uint16: anything larger silently becomes 0, which
  # would advertise the whole node again.
  if ((reserved > 65535)); then
    die "Can't size agent memory:" "reservation of ${reserved}MiB exceeds 65535MiB"
  fi
  export ECS_RESERVED_MEMORY="$reserved"
  info "Advertising memory (MiB):" "$((total - reserved)) of $total"
}
#}}}: size_agent_memory

cpu_affinity_list() { #{{{
  # Usage: cpu_affinity_list <n>
  # Prints the first n CPUs this process may run on as a taskset list, or
  # nothing if n already covers all of them.
  local n="$1" range first last cpu allowed=0 cpus=() ranges=()
  IFS=, read -ra ranges <<<"$(awk '/^Cpus_allowed_list:/ {print $2}' "$PROC_STATUS_FILE")"
  for range in "${ranges[@]}"; do
    first="${range%-*}"
    last="${range#*-}"
    for ((cpu = first; cpu <= last; cpu++)); do
      allowed=$((allowed + 1))
      ((${#cpus[@]} < n)) && cpus+=("$cpu")
    done
  done
  ((n >= allowed)) && return 0
  (
    IFS=,
    echo "${cpus[*]}"
  )
}
#}}}: cpu_affinity_list

cmd_ecs_agent() { #{{{
  wait_for "ecs.config" test -s "$ECS_CONFIG_DIR/ecs.config"
  wait_for "dockerd" docker info
  wait_for "SSM rotating credentials" test -s "$AGENT_CREDS_FILE"

  load_ecs_config

  # Defaults ecs-init would set (see ecs-init/docker/docker.go).
  export ECS_AVAILABLE_LOGGING_DRIVERS='["json-file","syslog","awslogs","fluentd","none"]'
  export ECS_UPDATES_ENABLED=false
  # Where dockerd sees the agent's data dir, for bind-mounting task metadata.
  export ECS_HOST_DATA_DIR=/var/lib/ecs
  # The agent can't create task cgroups from an unprivileged container.
  export ECS_ENABLE_TASK_CPU_MEM_LIMIT=false

  size_agent_memory

  # The agent advertises runtime.NumCPU() x 1024 units. NumCPU follows CPU
  # affinity, not the cgroup quota, so pin the agent to as many CPUs as the
  # dockerd container's limit allows.
  local cpu_list=""
  if [[ "${SG_TASK_CPU_LIMIT:-}" =~ ^[0-9]+$ ]]; then
    cpu_list="$(cpu_affinity_list "$SG_TASK_CPU_LIMIT")"
  fi
  reactivate_when_registered &

  if [[ -n "$cpu_list" ]]; then
    info "Advertising CPUs:" "$SG_TASK_CPU_LIMIT (agent pinned to $cpu_list)"
    exec taskset -c "$cpu_list" ecs-agent
  fi
  exec ecs-agent
}
#}}}: cmd_ecs_agent

read_sg_credentials_from_stdin() { #{{{
  # KEY=VALUE lines (the k8s/.env format); only known keys are taken, so the
  # token never has to live in the pod spec or on a command line.
  local key value
  while IFS='=' read -r key value || [[ -n "$key" ]]; do
    [[ " $SG_CRED_KEYS " == *" $key "* ]] || continue
    value="${value%\"}"
    value="${value#\"}"
    printf -v "$key" '%s' "$value"
  done
}
#}}}: read_sg_credentials_from_stdin

load_sg_credentials_from_dir() { #{{{
  # The credentials Secret, mounted as one file per key.
  local key
  for key in $SG_CRED_KEYS; do
    [[ -r "$SG_CREDS_DIR/$key" ]] && printf -v "$key" '%s' "$(<"$SG_CREDS_DIR/$key")"
  done
}
#}}}: load_sg_credentials_from_dir

configured_runner_id() { #{{{
  # Prints the SG runner ID recorded in ecs.config at registration.
  [[ -s "$ECS_CONFIG_DIR/ecs.config" ]] || die "Not registered:" "$ECS_CONFIG_DIR/ecs.config missing"
  grep ECS_INSTANCE_ATTRIBUTES "$ECS_CONFIG_DIR/ecs.config" | cut -d "=" -f2- |
    jq -r '.sg_runner_id'
}
#}}}: configured_runner_id

deregister_runner() { #{{{
  local url
  load_sg_credentials

  RUNNER_ID="$(configured_runner_id)"
  validate_runner_id "$RUNNER_ID"

  url="${SG_BASE_API}/orgs/${ORGANIZATION_ID}/runnergroups/${RUNNER_GROUP_ID}/deregister/"
  if ! api_call "POST" "$url" "{ \"RunnerId\": \"${RUNNER_ID}\" }"; then
    die "Could not deregister runner." "$status_code" "$message"
  fi
  info "Deregistered runner" "$RUNNER_ID"

  # Wipe the identity so a restarted pod can't come back as a ghost runner.
  find "$ECS_CONFIG_DIR" "$ECS_DATA_DIR" "$SSM_DIR" -mindepth 1 -delete
  info "Local state wiped."
}
#}}}: deregister_runner

cmd_deregister() { #{{{
  [[ -t 0 ]] && die "Pipe SG credentials on stdin:" "kubectl exec -i ... deregister < k8s/.env"
  read_sg_credentials_from_stdin
  deregister_runner
}
#}}}: cmd_deregister

cmd_reap() { #{{{
  # One-off Job the scaler starts for a runner parked longer than its TTL: the
  # pod is gone, so deregister using the identity on the mounted state PVC.
  load_sg_credentials_from_dir
  deregister_runner
}
#}}}: cmd_reap



sg_api() { #{{{
  # Usage: sg_api <method> <path> [payload]
  # Calls the runner group's SG API with the node token and prints the
  # response. Subshell: api_call exits on an empty response.
  local method="$1" path="$2" payload="${3:-}"
  (
    if ! api_call "$method" \
      "${SG_BASE_API}/orgs/${SG_ORGANIZATION}/runnergroups/${SG_RUNNER_GROUP}/${path}" \
      "$payload"; then
      info "SG API $method $path failed ($status_code):" "$message" >&2
      exit 1
    fi
    printf '%s' "$response"
  )
}
#}}}: sg_api

set_sg_runner_status() { #{{{
  # Usage: set_sg_runner_status DRAINING|ACTIVE
  # SG's runner_status API, as used by sg-runner-autoscaler: SG changes the
  # ECS container instance state on its side, with its own permissions.
  local runner_id
  runner_id="$(configured_runner_id)"
  validate_runner_id "$runner_id"
  sg_api POST runner_status/ \
    "$(jq -nc --arg s "$1" --arg r "$runner_id" '{Status: $s, RunnerId: $r}')" >/dev/null
}
#}}}: set_sg_runner_status

set_runner_status() { #{{{
  # Usage: set_runner_status DRAINING|ACTIVE
  # Only through SG: a customer's runner has no ECS permissions of its own.
  load_sg_credentials_from_dir
  set_sg_runner_status "$1"
}
#}}}: set_runner_status

current_runner_status() { #{{{
  # Prints this runner's status as SG reports it (ACTIVE, DRAINING, ...).
  # The response holds secrets; only the status leaves this function.
  local runner_id
  load_sg_credentials_from_dir
  runner_id="$(configured_runner_id)"
  sg_api GET "" | jq -r --arg r "$runner_id" \
    '.msg.ContainerInstances[]? | select(.runnerId == $r) | .status'
}
#}}}: current_runner_status

reactivate_when_registered() { #{{{
  # Wake a parked runner: undo the drain this pod did on its way down
  # (cmd_drain); it comes back with the same container instance. A drain anyone else
  # started (SG UI, an autoscaler) leaves no marker and is kept.
  [[ -e "$SELF_DRAIN_MARKER" ]] || return 0
  local attempt
  for ((attempt = 0; attempt < 120; attempt++)); do
    if curl -fsS --max-time 5 "$AGENT_API/metadata" 2>/dev/null |
      jq -e '.ContainerInstanceArn // empty' >/dev/null; then
      if set_runner_status ACTIVE; then
        rm -f "$SELF_DRAIN_MARKER"
        info "Runner" "ACTIVE"
      else
        info "Could not set ACTIVE;" "a restarted runner may stay DRAINING"
      fi
      return
    fi
    sleep 5
  done
}
#}}}: reactivate_when_registered

cmd_drain() { #{{{
  # preStop hook of the ecs-agent container: park the runner. Every shutdown
  # (scale-down, restart, rollout, eviction) sets it DRAINING so no new
  # workflows land, waits for the running ones (bounded by
  # terminationGracePeriodSeconds), and keeps the registration on the state
  # PVC. Scaling back up wakes the same runner in seconds
  # (reactivate_when_registered); deregistering parked runners is left to
  # `make deregister` / the scaler.
  # Hook output isn't logged by the kubelet, so write to the container's.
  exec >/proc/1/fd/1 2>&1
  # Release the other containers whatever happens below.
  trap 'touch "$DRAINED_MARKER"' EXIT

  info "Parking runner.."
  # Already gone after a manual deregister (make nuke).
  if [[ -s "$ECS_CONFIG_DIR/ecs.config" ]]; then
    load_ecs_config
    if [[ "$(current_runner_status)" == "DRAINING" ]]; then
      # Drained on purpose by someone else: keep it that way on wake.
      info "Runner already" "DRAINING"
    elif set_runner_status DRAINING; then
      info "Runner" "DRAINING"
      touch "$SELF_DRAIN_MARKER"
    else
      info "Could not set DRAINING;" "new tasks may still land"
    fi
  fi

  until [[ -z "$(docker ps -q 2>/dev/null)" ]]; do
    info "Waiting for running workflow containers.."
    sleep 10
  done
  info "Parked:" "no workflow containers running"
}
#}}}: cmd_drain

cmd_wait_drained() { #{{{
  until [[ -e "$DRAINED_MARKER" ]]; do
    sleep 5
  done
}
#}}}: cmd_wait_drained

# Only dispatch when executed directly; sourcing exposes the functions (tests).
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  case "${1:-}" in
  register) cmd_register ;;
  dockerd) cmd_dockerd ;;
  ssm-agent) cmd_ssm_agent ;;
  ecs-agent) cmd_ecs_agent ;;
  drain) cmd_drain ;;
  wait-drained) cmd_wait_drained ;;
  deregister) cmd_deregister ;;
  reap) cmd_reap ;;
  *)
    echo "Usage: $(basename "$0") register|dockerd|ssm-agent|ecs-agent|drain|wait-drained|deregister|reap" >&2
    exit 2
    ;;
  esac
fi

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
#
# main.sh is sourced for the API, config and network helpers; its
# BASH_SOURCE guard keeps main() from running.

set -o pipefail

# shellcheck source-path=SCRIPTDIR/.. source=main.sh
source /opt/sg-runner/main.sh

readonly SSM_DIR="/var/lib/amazon/ssm"
readonly SSM_REGISTRATION_FILE="${SSM_DIR}/Vault/Store/RegistrationKey"
readonly AGENT_CREDS_FILE="/rotatingcreds/credentials"
readonly SG_CRED_KEYS="SG_NODE_TOKEN SG_ORGANIZATION SG_RUNNER_GROUP SG_BASE_API SG_API_KEY"
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
  local dockerd_pid=$!
  trap 'kill -TERM "$dockerd_pid"; wait "$dockerd_pid"' TERM INT

  wait_for "dockerd" docker info
  # Same bridge, IMDS block and task-credential DNAT as on a VM. Rules land in
  # the pod's network namespace, not the node's.
  configure_local_network
  info "Docker ready, network" "$SG_DOCKER_NETWORK"

  wait "$dockerd_pid"
}
#}}}: cmd_dockerd

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

  total=$(($(awk '/^MemTotal:/ {print $2}' /proc/meminfo) / 1024))
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
  IFS=, read -ra ranges <<<"$(awk '/^Cpus_allowed_list:/ {print $2}' /proc/self/status)"
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



sg_api() { #{{{
  # Usage: sg_api <method> <path> [payload]
  # Calls the runner group's SG API with SG_API_KEY and prints the response.
  # api_call authenticates with SG_NODE_TOKEN: swap in the key, in a subshell
  # so the node token stays untouched for deregistration.
  local method="$1" path="$2" payload="${3:-}"
  (
    SG_NODE_TOKEN="$SG_API_KEY"
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
  # Without SG_API_KEY, shutdowns still wait for running workflows but can't
  # stop new ones from being placed meanwhile.
  load_sg_credentials_from_dir
  if [[ -z "${SG_API_KEY:-}" ]]; then
    info "SG_API_KEY not set:" "skipping $1"
    return 1
  fi
  set_sg_runner_status "$1"
}
#}}}: set_runner_status

current_runner_status() { #{{{
  # Prints this runner's status as SG reports it (ACTIVE, DRAINING, ...).
  # The response holds secrets; only the status leaves this function.
  local runner_id
  load_sg_credentials_from_dir
  [[ -n "${SG_API_KEY:-}" ]] || return 1
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
  *)
    echo "Usage: $(basename "$0") register|dockerd|ssm-agent|ecs-agent|drain|wait-drained|deregister" >&2
    exit 2
    ;;
  esac
fi

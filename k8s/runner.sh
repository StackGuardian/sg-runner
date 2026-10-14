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
#   workflow-logs  opt-in sidecar: workflow step output, tagged with its run
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

# workflow-logs sidecar: "text" lines or "json" objects, one per output line;
# [SG_DEBUG] lines only with SG_WORKFLOW_LOGS_DEBUG=true.
SG_WORKFLOW_LOGS_FORMAT="${SG_WORKFLOW_LOGS_FORMAT:-text}"
SG_WORKFLOW_LOGS_DEBUG="${SG_WORKFLOW_LOGS_DEBUG:-false}"
# Containers being followed (one directory each), so a container listed at
# start and also seen starting is followed once.
FOLLOWED_DIR="${FOLLOWED_DIR:-/tmp/sg-workflow-logs}"

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

registered_resources() { #{{{
  # Prints "<cpu units> <memory MiB> <running + pending tasks>" of this
  # runner's ECS container instance as SG reports it. The response holds
  # secrets (the group's runner token): only these numbers leave here.
  local runner_id
  runner_id="$(configured_runner_id)"
  validate_runner_id "$runner_id" >/dev/null 2>&1 || return 1
  sg_api GET "" | jq -er --arg r "$runner_id" '
    first(.msg.ContainerInstances[]? | select(.runnerId == $r))
    | [(.registeredResources[]? | select(.name == "CPU") | .integerValue),
       (.registeredResources[]? | select(.name == "MEMORY") | .integerValue),
       ((.runningTasksCount // 0) + (.pendingTasksCount // 0))]
    | select(length == 3 and all(type == "number"))
    | map(tostring) | join(" ")' 2>/dev/null
}
#}}}: registered_resources

resized_while_idle() { #{{{
  # ECS keeps a container instance's resources from its first registration:
  # an agent restarted with a new size still offers the old one. True when
  # this runner's registration has another size than the agent will advertise
  # and nothing runs on it, so it can register again. Never fails the
  # registration: anything unknown keeps the existing one.
  [[ "${SG_REREGISTER_ON_RESIZE:-true}" == "true" ]] || return 1
  local want got cpu mem tasks
  if ! want="$(advertised_resources)"; then
    info "Can't tell the advertised size;" "keeping the registration"
    return 1
  fi
  if ! got="$(registered_resources)" || [[ -z "$got" ]]; then
    info "Can't read the registered size from SG;" "keeping the registration"
    return 1
  fi
  read -r cpu mem tasks <<<"$got"
  [[ "$cpu $mem" == "$want" ]] && return 1
  if ((tasks > 0)); then
    info "Registered CPU/memory $cpu/$mem, now ${want/ //}:" "$tasks task(s) running or pending, keeping the old size"
    return 1
  fi
  info "Registered CPU/memory $cpu/$mem, now ${want/ //}:" "re-registering"
}
#}}}: resized_while_idle

cmd_register() { #{{{
  if is_registered; then
    if ! resized_while_idle; then
      info "Already registered, reusing state from" "$ECS_CONFIG_DIR/ecs.config"
      return 0
    fi
    # As cmd_reap: deregister through SG and wipe the identity. If that
    # fails, keep the registration rather than block the runner.
    if ! (deregister_runner); then
      info "Could not deregister;" "keeping the old registration"
      return 0
    fi
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

mem_total_mib() {
  echo $(($(awk '/^MemTotal:/ {print $2}' "$MEMINFO_FILE") / 1024))
}

reserved_memory_mib() { #{{{
  # The agent advertises MemTotal from /proc/meminfo, which is the whole node.
  # Tasks run inside the dockerd container, so advertise its limit (downward
  # API) minus dockerd's own overhead, by reserving the difference. With native
  # steps the limit is the chart's nativeSteps.advertise and the overhead 0.
  # More than the node advertises the node.
  # Prints the reservation; fails without a numeric limit (1, nothing printed)
  # or when the agent can't take it (2).
  local limit="${SG_TASK_MEMORY_LIMIT_MIB:-}" total available reserved
  [[ "$limit" =~ ^[0-9]+$ ]] || return 1

  total=$(mem_total_mib)
  available=$((limit - SG_DOCKERD_OVERHEAD_MIB))
  reserved=$((total > available ? total - available : 0))
  echo "$reserved"
  # The agent parses this as uint16: anything larger silently becomes 0, which
  # would advertise the whole node again.
  ((reserved <= 65535)) || return 2
}
#}}}: reserved_memory_mib

size_agent_memory() { #{{{
  local reserved rc=0 total
  reserved=$(reserved_memory_mib) || rc=$?
  ((rc == 1)) && return 0
  if ((rc == 2)); then
    die "Can't size agent memory:" "reservation of ${reserved}MiB exceeds 65535MiB (advertise more memory or use a smaller node)"
  fi
  total=$(mem_total_mib)
  export ECS_RESERVED_MEMORY="$reserved"
  info "Advertising memory (MiB):" "$((total - reserved)) of $total"
}
#}}}: size_agent_memory

allowed_cpus() { #{{{
  # Prints the CPUs this process may run on, space-separated.
  local range first last cpu cpus=() ranges=()
  IFS=, read -ra ranges <<<"$(awk '/^Cpus_allowed_list:/ {print $2}' "$PROC_STATUS_FILE")"
  for range in "${ranges[@]}"; do
    first="${range%-*}"
    last="${range#*-}"
    for ((cpu = first; cpu <= last; cpu++)); do
      cpus+=("$cpu")
    done
  done
  echo "${cpus[*]}"
}
#}}}: allowed_cpus

cpu_affinity_list() { #{{{
  # Usage: cpu_affinity_list <n>
  # Prints the first n CPUs this process may run on as a taskset list, or
  # nothing if n already covers all of them.
  local n="$1" cpus=()
  read -ra cpus <<<"$(allowed_cpus)"
  ((n >= ${#cpus[@]})) && return 0
  (
    IFS=,
    echo "${cpus[*]:0:n}"
  )
}
#}}}: cpu_affinity_list

agent_cpu_list() { #{{{
  # The CPUs cmd_ecs_agent pins the agent to (SG_TASK_CPU_LIMIT of them), or
  # nothing to leave it on all of them.
  [[ "${SG_TASK_CPU_LIMIT:-}" =~ ^[0-9]+$ ]] || return 0
  cpu_affinity_list "$SG_TASK_CPU_LIMIT"
}
#}}}: agent_cpu_list

advertised_resources() { #{{{
  # Prints "<cpu units> <memory MiB>" as the ECS agent started by
  # cmd_ecs_agent registers them: NumCPU of its CPU set x 1024, and MemTotal
  # minus ECS_RESERVED_MEMORY. Fails when the agent wouldn't start (memory
  # reservation too large).
  local cpu_list cpus=() reserved=0 rc=0
  cpu_list="$(agent_cpu_list)"
  if [[ -n "$cpu_list" ]]; then
    IFS=, read -ra cpus <<<"$cpu_list"
  else
    read -ra cpus <<<"$(allowed_cpus)"
  fi
  reserved=$(reserved_memory_mib) || rc=$?
  ((rc == 2)) && return 1
  ((rc == 1)) && reserved=0
  echo "$((${#cpus[@]} * 1024)) $(($(mem_total_mib) - reserved))"
}
#}}}: advertised_resources

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
  local cpu_list
  cpu_list="$(agent_cpu_list)"
  reactivate_when_registered &

  if [[ -n "$cpu_list" ]]; then
    info "Advertising CPUs:" "$SG_TASK_CPU_LIMIT (agent pinned to $cpu_list)"
    exec taskset -c "$cpu_list" ecs-agent
  elif [[ -n "${SG_TASK_CPU_LIMIT:-}" ]]; then
    info "Advertising CPUs:" "all this node allows (limit $SG_TASK_CPU_LIMIT)"
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
  # One-off Job the scaler (parked longer than its TTL) or the uninstall hook
  # starts: the pod is gone, so deregister using the identity on the mounted
  # state PVC.
  load_sg_credentials_from_dir
  # Never registered (registration failed, or already deregistered and
  # wiped): nothing in SG to remove, and the PVC can go.
  if [[ ! -s "$ECS_CONFIG_DIR/ecs.config" ]]; then
    info "Not registered:" "nothing to deregister"
    return 0
  fi
  deregister_runner
}
#}}}: cmd_reap



sg_api() { #{{{
  # Usage: sg_api <method> <path> [payload]
  # Calls the runner group's SG API with the node token and prints the
  # response. Subshell: api_call exits on an empty response. A failure logs
  # only a string message: the runner group's body holds secrets.
  local method="$1" path="$2" payload="${3:-}"
  (
    if ! api_call "$method" \
      "${SG_BASE_API}/orgs/${SG_ORGANIZATION}/runnergroups/${SG_RUNNER_GROUP}/${path}" \
      "$payload"; then
      info "SG API $method $path failed ($status_code):" \
        "$(jq -r '[.msg, .message] | map(strings) | first // "no message"' <<<"$response" 2>/dev/null)" >&2
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

container_log_tags() { #{{{
  # Usage: container_log_tags <task-arn|mount sources>
  # Prints "run workflow" for a step (user) container, "-" where unknown, or
  # fails for a run controller (admin) container, an ECS task: it relays its
  # steps' output, so following it too would print every step line twice.
  # Steps mount their run's workspace, .../wfs/<workflow>/wfruns/<run>/...
  # No env is read: it holds the run's credentials.
  local task_arn sources run="-" wf="-"
  IFS='|' read -r task_arn sources <<<"$1"
  [[ -z "$task_arn" ]] || return 1
  [[ "$sources" =~ /wfruns/([^/[:space:]]+) ]] && run="${BASH_REMATCH[1]}"
  [[ "$sources" =~ /wfs/([^/[:space:]]+)/wfruns/ ]] && wf="${BASH_REMATCH[1]}"
  echo "$run $wf"
}
#}}}: container_log_tags

format_log_lines() { #{{{
  # Usage: format_log_lines <run> <workflow>
  # Reads `docker logs -t` lines ("<time> <message>") on stdin and writes each
  # as one tagged line or JSON object: one write per line, so concurrent
  # containers interleave by line, never mid-line. [SG_DEBUG] lines only with
  # SG_WORKFLOW_LOGS_DEBUG=true.
  local run="$1" wf="$2" debug=false line time msg
  [[ "${SG_WORKFLOW_LOGS_DEBUG:-}" == "true" ]] && debug=true
  if [[ "$SG_WORKFLOW_LOGS_FORMAT" == "json" ]]; then
    jq -Rc --unbuffered --arg run "$run" --arg wf "$wf" --argjson debug "$debug" '
      index(" ") as $i
      | (if $i then {time: .[:$i], msg: .[$i + 1:]} else {time: null, msg: .} end)
      | select($debug or (.msg | startswith("[SG_DEBUG]") | not))
      | . + {role: "user", run: $run, workflow: $wf}'
    return
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    time="${line%% *}"
    msg="${line#* }"
    [[ "$line" == *" "* ]] || { time="-" msg="$line"; }
    [[ "$debug" == "true" || "$msg" != "[SG_DEBUG]"* ]] || continue
    printf '%s role=user run=%s workflow=%s | %s\n' "$time" "$run" "$wf" "$msg"
  done
}
#}}}: format_log_lines

follow_container() { #{{{
  # Usage: follow_container <id> [since]
  # Streams one step container's output until it exits.
  local id="$1" since="${2:-}" inspect tags
  mkdir -p "$FOLLOWED_DIR"
  mkdir "$FOLLOWED_DIR/$id" 2>/dev/null || return 0
  # Gone already, or a run controller: nothing to follow.
  if ! inspect="$(docker inspect --format \
    '{{index .Config.Labels "com.amazonaws.ecs.task-arn"}}|{{range .Mounts}}{{.Source}} {{end}}' \
    "$id" 2>/dev/null)" || ! tags="$(container_log_tags "$inspect")"; then
    rmdir "$FOLLOWED_DIR/$id"
    return 0
  fi
  # The CLI's own error for a container removed before it attached (--rm
  # and done within moments) isn't workflow output.
  # shellcheck disable=SC2086 # tags is "run workflow"
  docker logs --follow --timestamps ${since:+--since "$since"} "$id" 2>&1 |
    grep --line-buffered -v '^Error response from daemon: No such container' |
    format_log_lines $tags
  rmdir "$FOLLOWED_DIR/$id" 2>/dev/null
}
#}}}: follow_container

cmd_workflow_logs() { #{{{
  # Opt-in sidecar: every workflow step's output on this container's stdout,
  # so `kubectl logs -c workflow-logs` and the cluster's log pipeline see it.
  # Run controllers are skipped (they relay their steps' output). Containers
  # already running when it starts (a sidecar restart) are followed from now,
  # not replayed.
  local since id time events_pid
  wait_for "dockerd" docker info
  since="$(date +%s)"
  info "Streaming workflow step logs, format" "$SG_WORKFLOW_LOGS_FORMAT, debug $SG_WORKFLOW_LOGS_DEBUG"

  docker events --since "$since" --filter type=container --filter event=start \
    --format '{{.ID}} {{.Time}}' |
    while read -r id time; do
      follow_container "$id" "$time" &
    done &
  events_pid=$!
  for id in $(docker ps -q --no-trunc); do
    follow_container "$id" "$since" &
  done

  # In the background and waited on, so SIGTERM ends it at once (after the
  # preStop wait-drained). If dockerd goes away, events ends: exit and let
  # the kubelet restart the sidecar.
  trap 'exit 0' TERM INT
  wait "$events_pid"
}
#}}}: cmd_workflow_logs


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
  workflow-logs) cmd_workflow_logs ;;
  *)
    echo "Usage: $(basename "$0") register|dockerd|ssm-agent|ecs-agent|drain|wait-drained|deregister|reap|workflow-logs" >&2
    exit 2
    ;;
  esac
fi

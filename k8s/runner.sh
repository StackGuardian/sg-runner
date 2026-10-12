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
#   drain       ecs-agent preStop: DRAINING, wait for workflows; deregister on scale-down
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
readonly SG_CRED_KEYS="SG_NODE_TOKEN SG_ORGANIZATION SG_RUNNER_GROUP SG_BASE_API"
readonly SG_CREDS_DIR="/etc/sg-runner/credentials"
readonly K8S_TOKEN_DIR="/etc/sg-runner/kube"
# On the emptyDir shared by every container: tells the others the drain is over.
readonly DRAINED_MARKER="/var/run/sg-runner-drained"
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

deregister_runner() { #{{{
  local instance_attrs url
  load_sg_credentials

  [[ -s "$ECS_CONFIG_DIR/ecs.config" ]] || die "Not registered:" "$ECS_CONFIG_DIR/ecs.config missing"
  instance_attrs="$(grep ECS_INSTANCE_ATTRIBUTES "$ECS_CONFIG_DIR/ecs.config" | cut -d "=" -f2-)"
  RUNNER_ID="$(echo "$instance_attrs" | jq -r '.sg_runner_id')"
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

k8s_api() { #{{{
  # Usage: k8s_api <path>; GET with the pod's projected service account token.
  curl -fsS --max-time 10 \
    --cacert "$K8S_TOKEN_DIR/ca.crt" \
    -H "Authorization: Bearer $(<"$K8S_TOKEN_DIR/token")" \
    "https://kubernetes.default.svc$1"
}
#}}}: k8s_api

is_scaling_down() { #{{{
  # A StatefulSet scale-down removes the highest ordinals, so this pod is going
  # away for good only if its ordinal no longer fits under spec.replicas.
  # Rollouts, evictions and deleting the StatefulSet keep the identity.
  local ns replicas ordinal="${HOSTNAME##*-}"
  ns="$(<"$K8S_TOKEN_DIR/namespace")"
  replicas="$(k8s_api "/apis/apps/v1/namespaces/${ns}/statefulsets/${SG_STATEFULSET}" |
    jq -r '.spec.replicas')" || return 1
  [[ "$replicas" =~ ^[0-9]+$ ]] && ((ordinal >= replicas))
}
#}}}: is_scaling_down

ecs_api() { #{{{
  # Usage: ecs_api <action> <json>
  # Signed with the instance credentials the SSM agent rotates for the ECS
  # agent; the key pair goes through a curl config file, not the command line.
  local action="$1" payload="$2" curl_config response code rc
  curl_config=$(mktemp)
  chmod 600 "$curl_config"
  awk -F' *= *' '
    $1 == "aws_access_key_id"     { key = $2 }
    $1 == "aws_secret_access_key" { secret = $2 }
    $1 == "aws_session_token"     { token = $2 }
    END {
      printf "user = \"%s:%s\"\n", key, secret
      printf "header = \"x-amz-security-token: %s\"\n", token
    }' "$AGENT_CREDS_FILE" >"$curl_config"

  response="$(curl -sS --max-time 15 -K "$curl_config" \
    --aws-sigv4 "aws:amz:${AWS_DEFAULT_REGION}:ecs" \
    -H "Content-Type: application/x-amz-json-1.1" \
    -H "X-Amz-Target: AmazonEC2ContainerServiceV20141113.${action}" \
    -w '\n%{http_code}' \
    -d "$payload" \
    "https://ecs.${AWS_DEFAULT_REGION}.amazonaws.com/")"
  rc=$?
  rm -f "$curl_config"
  ((rc == 0)) || return $rc

  code="${response##*$'\n'}"
  response="${response%$'\n'*}"
  if [[ "$code" != 2* ]]; then
    # e.g. AccessDeniedException: ... not authorized to perform ...
    # stderr: callers capture stdout for the response.
    info "ECS $action failed ($code):" \
      "$(echo "$response" | jq -r '"\(.__type // "") \(.message // .Message // "")"' 2>/dev/null)" >&2
    return 1
  fi
  echo "$response"
}
#}}}: ecs_api

set_container_instance_state() { #{{{
  # Usage: set_container_instance_state DRAINING|ACTIVE
  # DRAINING stops ECS from placing new tasks on this runner; running ones
  # carry on.
  local metadata payload response
  metadata="$(curl -fsS --max-time 5 "$AGENT_API/metadata")" || return 1
  payload="$(echo "$metadata" | jq -c --arg status "$1" \
    '{cluster: .Cluster, containerInstances: [.ContainerInstanceArn], status: $status}')"
  response="$(ecs_api UpdateContainerInstancesState "$payload")" || return 1
  if [[ "$(echo "$response" | jq '.failures | length')" != 0 ]]; then
    info "ECS UpdateContainerInstancesState failures:" "$(echo "$response" | jq -c '.failures')" >&2
    return 1
  fi
}
#}}}: set_container_instance_state

reactivate_when_registered() { #{{{
  # Every shutdown drains the runner (cmd_drain). After a restart it comes back
  # with the same container instance, still DRAINING, so set it ACTIVE again as
  # soon as the agent has registered. Harmless if it already is.
  local attempt
  for ((attempt = 0; attempt < 120; attempt++)); do
    if curl -fsS --max-time 5 "$AGENT_API/metadata" 2>/dev/null |
      jq -e '.ContainerInstanceArn // empty' >/dev/null; then
      if set_container_instance_state ACTIVE; then
        info "Container instance" "ACTIVE"
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
  # preStop hook of the ecs-agent container. Every shutdown first sets the
  # runner DRAINING, so it waits only for workflows already running (bounded
  # by terminationGracePeriodSeconds) instead of picking up new ones. A
  # scale-down also deregisters at the end; any other shutdown keeps the
  # identity and reactivates on start (reactivate_when_registered).
  # Hook output isn't logged by the kubelet, so write to the container's.
  exec >/proc/1/fd/1 2>&1
  # Release the other containers whatever happens below.
  trap 'touch "$DRAINED_MARKER"' EXIT

  local scale_down=false
  if is_scaling_down; then
    scale_down=true
  fi
  info "Shutting down:" "$([[ "$scale_down" == true ]] && echo scale-down || echo restart)"

  # Already gone after a manual deregister (make nuke).
  if [[ -s "$ECS_CONFIG_DIR/ecs.config" ]]; then
    load_ecs_config
    if set_container_instance_state DRAINING; then
      info "Container instance" "DRAINING"
    else
      info "Could not set DRAINING;" "new tasks may still land"
    fi
  fi

  until [[ -z "$(docker ps -q 2>/dev/null)" ]]; do
    info "Waiting for running workflow containers.."
    sleep 10
  done
  info "No workflow containers running."

  if [[ "$scale_down" == true ]]; then
    load_sg_credentials_from_dir
    deregister_runner
  fi
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

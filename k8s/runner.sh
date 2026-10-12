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

cmd_ecs_agent() { #{{{
  wait_for "ecs.config" test -s "$ECS_CONFIG_DIR/ecs.config"
  wait_for "dockerd" docker info
  wait_for "SSM rotating credentials" test -s "$AGENT_CREDS_FILE"

  # ecs-init normally turns ecs.config into the agent's environment. Read it
  # line by line: ECS_INSTANCE_ATTRIBUTES holds JSON that `source` would mangle.
  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" || "$line" == \#* ]] && continue
    export "${line%%=*}=${line#*=}"
  done <"$ECS_CONFIG_DIR/ecs.config"

  # Defaults ecs-init would set (see ecs-init/docker/docker.go).
  export ECS_AVAILABLE_LOGGING_DRIVERS='["json-file","syslog","awslogs","fluentd","none"]'
  export ECS_UPDATES_ENABLED=false
  # Where dockerd sees the agent's data dir, for bind-mounting task metadata.
  export ECS_HOST_DATA_DIR=/var/lib/ecs
  # The agent can't create task cgroups from an unprivileged container.
  export ECS_ENABLE_TASK_CPU_MEM_LIMIT=false

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

cmd_deregister() { #{{{
  [[ -t 0 ]] && die "Pipe SG credentials on stdin:" "kubectl exec -i ... deregister < k8s/.env"
  read_sg_credentials_from_stdin
  load_sg_credentials

  local instance_attrs url
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
  info "Local state wiped." "Delete the StatefulSet and PVCs next."
}
#}}}: cmd_deregister

case "${1:-}" in
register) cmd_register ;;
dockerd) cmd_dockerd ;;
ssm-agent) cmd_ssm_agent ;;
ecs-agent) cmd_ecs_agent ;;
deregister) cmd_deregister ;;
*)
  echo "Usage: $(basename "$0") register|dockerd|ssm-agent|ecs-agent|deregister" >&2
  exit 2
  ;;
esac

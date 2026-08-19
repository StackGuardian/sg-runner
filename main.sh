#!/bin/bash
#
# Register external instance to Stackguardian platform.

set -o pipefail

#{{{ Environment variables

## main
CONTAINER_ORCHESTRATOR=
LOG_DEBUG=${LOG_DEBUG:=false}
CGROUPSV2_PREVIEW=${CGROUPSV2_PREVIEW:=false}
SG_BASE_API=${SG_BASE_API:="https://api.app.stackguardian.io/api/v1"}
# NO_PROXY bypasses proxy for AWS ECS/SSM addresses; user-supplied values are appended.
NO_PROXY="169.254.169.254,169.254.170.2,/var/run/docker.sock"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
LOG_FILE="${LOG_FILE:=/var/log/sg_runner.log}"
readonly LOG_FILE

# static
# readonly COMMANDS=("jq" "crontab")
readonly COMMANDS=("jq")
readonly CONTAINER_ORCHESTRATORS=("docker")
readonly SG_DOCKER_NETWORK="sg-net"

# Filesystem locations (overridable for testing; default to production paths)
ECS_CONFIG_DIR="${ECS_CONFIG_DIR:=/etc/ecs}"
ECS_LOG_DIR="${ECS_LOG_DIR:=/var/log/ecs}"
ECS_DATA_DIR="${ECS_DATA_DIR:=/var/lib/ecs/data}"
ECS_EXEC_DEPS_DIR="${ECS_EXEC_DEPS_DIR:=/var/lib/ecs/deps/execute-command}"
REGISTRATION_DIR="${REGISTRATION_DIR:=/var/log/registration}"
readonly ECS_CONFIG_DIR ECS_LOG_DIR ECS_DATA_DIR ECS_EXEC_DEPS_DIR REGISTRATION_DIR

# diagnostics
SG_DIAGNOSTIC_DIR="${SG_DIAGNOSTIC_DIR:=/var/lib/sg-runner}"
readonly SG_DIAGNOSTIC_DIR
readonly SG_DIAGNOSTIC_FILE="${SG_DIAGNOSTIC_DIR}/diagnostic.json"
readonly SG_DIAGNOSTIC_TMP_FILE="${SG_DIAGNOSTIC_DIR}/diagnostic.json.tmp"

# Environment variables can be overridden via command line:
# LOG_DEBUG=true ./main.sh register ...

## colors
readonly C_RED_BOLD="\033[1;31m"
readonly C_RED="\033[0;31m"
readonly C_GREEN_BOLD="\033[1;32m"
readonly C_GREEN="\033[0;32m"
readonly C_MAGENTA_BOLD="\033[1;35m"
readonly C_RESET="\033[0m"
readonly C_BOLD="\033[1m"

init_diagnostic_dir() { #{{{
  if [[ ! -d "$SG_DIAGNOSTIC_DIR" ]]; then
    mkdir -p "$SG_DIAGNOSTIC_DIR"
    chmod 700 "$SG_DIAGNOSTIC_DIR"
  fi

  if [[ ! -e "$SG_DIAGNOSTIC_FILE" ]]; then
    touch "$SG_DIAGNOSTIC_FILE"
    chmod 600 "$SG_DIAGNOSTIC_FILE"
    echo "{}" >"$SG_DIAGNOSTIC_FILE"
  fi
}
#}}}: init_diagnostic_dir

#}}}: Environment variables

#{{{ Printing

is_debug() { [[ "${LOG_DEBUG,,}" == "true" ]]; }

show_help() { #{{{
  cat <<EOF

sg-runner is a script for registration of Private Runner Nodes on Stackguardian.

  More information available at: https://docs.stackguardian.io/docs/organisation_settings/private-runner-groups/

Examples:
  # Register new runner
  ./$(basename "$0") register --sg-node-token "some-token" --organization "demo-org" --runner-group "private-runner-group"

  # De-Register new runner
  ./$(basename "$0") deregister --sg-node-token "some-token" --organization "demo-org" --runner-group "private-runner-group"

Available commands:
  register [options]            Register new Private Runner
  deregister [options]          Deregister existing Private Runner
  status                        Show health status of used services/containers
  info                          Show information about instance/registration
  prune                         Prune container system older than 10 days
  clean [options]               Clean local setup (no API calls)
  cgroupsv2 [enable|disable]    Manage cgroups versions (deprecated)

Options:
  --sg-node-token '': (required)
    The runner node token acquired from Stackguardian platform.

  --organization '': (required)
    The organization name on Stackguardian platform.

  --runner-group '': (required)
    The runner group where new runner will be registered.

  --http-proxy [hostname or IP address]:[port]
    The hostname (or IP address) and port of an HTTP and HTTPS proxy

  --no-proxy
    Comma separated hostname (or IP address)

  --no-clean-on-fail
    Do not clean up local setup in case of errors during registration.

  --debug
    Print more verbose output during command execution.

  --force, -f
    Execute some commands with force. Skip some sections in case of errors.

Usage:
  ./$(basename "$0") <command> [options]
EOF
}
#}}}: show_help

err() { #{{{
  printf "${C_RED_BOLD}ERROR:${C_RESET} %s${C_BOLD} %s${C_RESET} %s\n" "${1}" "${2:-}" "${@:3}" >&2
  if [[ -n "${ORGANIZATION_ID:-}" && -n "${RUNNER_GROUP_ID:-}" && -n "${SG_NODE_TOKEN:-}" ]]; then
    update_runner_group "${1} ${2:-} ${*:3}"
  fi
}
#}}}: err

die() {
  err "$@"
  exit 1
}

log_err() { #{{{
  local line err_part msg_part
  if [[ -r "$LOG_FILE" ]]; then
    line="$(tail -n1 "$LOG_FILE")"
    err_part="$(printf '%s' "$line" | cut -d':' -f1)"
    msg_part="$(printf '%s' "$line" | cut -d':' -f2-)"
  else
    err_part="Unknown error"
    msg_part=""
  fi
  printf "${C_RED_BOLD}ERROR:${C_RESET} %s${C_BOLD} %s${C_RESET}\n" "$err_part" "$msg_part" >&2
  if [[ -n "${ORGANIZATION_ID:-}" && -n "${RUNNER_GROUP_ID:-}" && -n "${SG_NODE_TOKEN:-}" ]]; then
    update_runner_group "${err_part} ${msg_part}"
  fi
}
#}}}: log_err

info() { #{{{
  printf "%s${C_BOLD} %s${C_RESET} %s\n" "${1}" "${2:-}" "${@:3}"
}
#}}}: info

spinner_wait() { #{{{
  printf "%s${C_BOLD} %s${C_RESET}\r" "${1}" "${2:-}"
}
#}}}: spinner_wait

spinner_msg() { #{{{
  local status="${2:-}"
  local msg="${3:-}"
  if [[ -z "$status" ]]; then
    printf "%s.. ${C_BOLD}%s${C_RESET}" "${1}" "${msg}"
    is_debug && printf "\n"
  elif ((status == 0)); then
    printf "%s.. ${C_GREEN_BOLD}%s${C_RESET}\n" "${1}" "${msg:="Done"}"
  else
    printf "%s.. ${C_RED_BOLD}%s${C_RESET}\n" "${1}" "${msg:="Failed"}"
  fi
}
#}}}: spinner_msg

debug() { #{{{
  is_debug &&
    printf "${C_MAGENTA_BOLD}DEBUG:${C_RESET} %s${C_BOLD} %s${C_RESET} %s\n" "${1}" "${2:-}" "${@:3}"
}
#}}}: debug

debug_variable() { #{{{
  is_debug &&
    [[ -n "${!1}" ]] && [[ "${!1}" != "null" ]] &&
    printf "${C_MAGENTA_BOLD}DEBUG:${C_RESET} %s${C_BOLD} %s${C_RESET}\n" "${1}" "${!1}"
}
#}}}: debug_variable

debug_secret() { #{{{
  is_debug &&
    [[ -n "${!1}" ]] && [[ "${!1}" != "null" ]] &&
    printf "${C_MAGENTA_BOLD}DEBUG:${C_RESET} %s${C_BOLD} %s${C_RESET}\n" "${1}" "${!1:0:5}*****"
}
#}}}: debug_secret

cmd_example() { #{{{
  echo
  printf "${C_BOLD}%s${C_RESET} %s %s\n" "${1}" "${2}" "${@:3}"
}
#}}}: cmd_example

exit_help() { #{{{
  exit_code=$?
  ((exit_code != 0)) &&
    printf "\n(Try ${C_BOLD}%s --help${C_RESET} for more information. Use --debug for verbose logs.)\n" "$(basename "${0}")"
}
#}}}: exit_help

doctor_frame() { #{{{
  printf " + %s " "${1}"
  printf "\n |"
  printf "%s" "$2"
  printf "\n"
}
#}}}: doctor_frame

details_frame() { #{{{
  printf " + ${C_BOLD}%s${C_RESET} " "${1}"
  printf "\n |\n"
}
#}}}: details_frame

details_item() { #{{{
  printf " | * %s: ${C_GREEN_BOLD}%s${C_RESET}\n" "$1" "$2"
}
#}}}: details_item

print_details() { #{{{
  echo
  details_frame "Registration Details"
  details_item "Organization" "${ORGANIZATION_ID}"
  details_item "Runner Group" "${RUNNER_GROUP_ID}"
  echo
  details_frame "Host Information"
  details_item "Hostname" "$HOSTNAME"
  details_item "Private IP Address" "$(ip route | grep default | cut -d" " -f9)"
  details_item "Public IP Address" "$(curl -fSs ifconfig.me)"
  details_item "HTTP PROXY" "$HTTP_PROXY"
  echo
  details_frame "System Information"
  details_item "OS Release" "$(cat /etc/*release | grep -oP '(?<=PRETTY_NAME=").*?(?=")')"
  details_item "Uptime" "$(uptime | awk '{gsub(",", "", $3); print $1, $2, $3}')"
  details_item "Load Average" "$(uptime | awk -F 'load average:' '{print $2}')"
  echo
  details_frame "Hardware Information"
  details_item "CPU Cores" "$(nproc) Core [Used: $(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}' | awk '{printf "%.0f%%", $1}')]"
  details_item "Memory" "$(free -h | awk '/^Mem:/ {printf "%s [Used: %s]\n", $2, $3}')"
  details_item "Size /var" "$(df -h --total /var | awk '/^total/ {if ($2 ~ /G/ && $2 + 0 < 100) printf "\033[31m%s [Used: %s]\033[0m\n", $2, $(NF-1); else printf "%s [Used: %s]\n", $2, $(NF-1)}')"
  echo
}
#}}}: print_details

save_registration_details() { #{{{
  mkdir -p "$REGISTRATION_DIR"
  print_details
  print_details | sed 's/\x1B\[[0-9;]*[JKmsu]//g' \
    >>"$REGISTRATION_DIR/registration_details_$(date +'%Y-%m-%dT%H-%M-%S%z').txt"
}
#}}}: save_registration_details

#}}}: Printing

#{{{ HTTP / API

api_call() { #{{{
  # Usage: api_call <method> <url> [payload]
  # Side effects: sets globals `response`, `status_code`, `message`, `data`
  local method="$1" call_url="$2" payload="${3:-}"
  local curl_config full_response

  curl_config=$(mktemp)
  chmod 600 "$curl_config"
  cat >"$curl_config" <<EOF
header = "Authorization: apikey ${SG_NODE_TOKEN}"
header = "Content-Type: application/json"
EOF

  if [[ -n "$payload" ]]; then
    response=$(curl --max-time 10 -i -s \
      -X "$method" \
      -K "$curl_config" \
      -d "$payload" \
      "${call_url}")
  else
    response=$(curl --max-time 10 -i -s \
      -X "$method" \
      -K "$curl_config" \
      "${call_url}")
  fi
  rm -f "$curl_config"

  if [[ -z "$response" ]]; then
    err "API call failed" "Empty response received"
    exit 1
  fi
  full_response="$response"

  debug "Response:" &&
    echo "-----" &&
    echo "${response}" &&
    echo "-----"

  # Last status code wins (a proxy may add its own 200 before the real one)
  status_code=$(echo "$response" | awk '/^HTTP\/[12]/ {code=$2} END {print code}')

  response="$(echo "$response" | awk '/^Response/ {print $2}')"
  [[ -z "$response" ]] &&
    response="$(echo "$full_response" | sed -n '/^{.*/,$p' | tr '\n' ' ')"

  message="$(echo "$response" | jq -r '.msg // .message //  "Unknown error"')"
  data="$(echo "$response" | jq -r '.data //  "Unknown error"')"

  if [[ -z "$status_code" ]]; then
    err "Unknown status code."
    exit 1
  elif [[ "$status_code" != "200" && "$status_code" != "201" && "$status_code" != "100" ]]; then
    return 1
  else
    return 0
  fi
}
#}}}: api_call

update_runner_group() { #{{{
  local err_msg ip_addr payload url
  url="${SG_BASE_API}/orgs/${ORGANIZATION_ID}/runnergroups/${RUNNER_GROUP_ID}/"

  err_msg=$(printf '%s' "$1" | tr -cd "[:print:]")
  debug "Error message ${err_msg}"

  ip_addr=$(ip route | grep default | cut -d" " -f9)

  payload=$(jq -n \
    --arg ip "$ip_addr" \
    --arg runner_id "${RUNNER_ID:-}" \
    --arg error "${err_msg}" \
    --arg timestamp "$(date -u -Iseconds)" \
    --arg command "${0} $*" \
    '{RunnerRegistrationErrors: {($ip): {RunnerId: $runner_id, error: $error, timestamp: $timestamp, command: $command}}}')

  if api_call "PATCH" "$url" "$payload"; then
    debug "updated runner group with error msg"
  else
    debug "failed to update runner group with error msg"
  fi
}
#}}}: update_runner_group

patch_json() { #{{{
  local file="$1"
  local patch="$2"
  local org_json
  debug "editing $file"
  [[ -f "${file}" && -s "${file}" ]] && org_json=$(cat "$file") || org_json='{}'
  jq -s '.[0] * .[1]' <(echo "$org_json") <(echo "$patch") >"$file"
}
#}}}: patch_json

#}}}: HTTP / API

#{{{ Services

check_systemctl_status() { #{{{
  if ! systemctl is-active "$1" >&/dev/null; then
    debug "Reloading/Restarting necessary services.."
    if ! systemctl reload-or-restart "$1" 2>/dev/null; then
      return 2
    fi
    return 0
  else
    return 0
  fi
}
#}}}: check_systemctl_status

check_systemctl_ecs_status() { #{{{
  systemctl status ecs --no-pager >&/dev/null
  if [[ "$?" =~ 4|0 ]]; then
    return 0
  else
    check_systemctl_status "ecs"
  fi
}
#}}}: check_systemctl_ecs_status

check_container_orchestrator() { #{{{
  if type "$1" >&/dev/null; then
    check_systemctl_status "$1"
    return $?
  else
    return 1
  fi
}
#}}}: check_container_orchestrator

detect_ssm_service() { #{{{
  # Sets SSM_SERVICE_NAME and SSM_BIN_NAME globals.
  if systemctl is-enabled snap.amazon-ssm-agent.amazon-ssm-agent.service &>/dev/null; then
    SSM_SERVICE_NAME="snap.amazon-ssm-agent.amazon-ssm-agent.service"
    SSM_BIN_NAME="/snap/amazon-ssm-agent/current/amazon-ssm-agent"
  else
    SSM_SERVICE_NAME="amazon-ssm-agent"
    SSM_BIN_NAME="amazon-ssm-agent"
  fi
}
#}}}: detect_ssm_service

cgroupsv2() { #{{{
  local cgroup_toggle
  [[ "$1" == "enable" ]] &&
    cgroup_toggle=1 || cgroup_toggle=0

  if ((cgroup_toggle == 0)); then
    info "Switching to" "cgroupsv1"
  else
    info "Switching to" "cgroupsv2"
  fi

  info "Reboot required!"
  while :; do
    read -r -p "Continue.. [Y/n]: " choice
    if [[ "${choice:="Y"}" =~ y|Y ]]; then
      break
    elif [[ "$choice" =~ n|N ]]; then
      exit 0
    else
      info "Unsupported option:" "$choice"
    fi
  done

  if type grubby >&/dev/null; then
    grubby --update-kernel=ALL --args="systemd.unified_cgroup_hierarchy=$cgroup_toggle"
  else
    grub_cmdline="$(grep "GRUB_CMDLINE_LINUX=.*" /etc/default/grub | grep -o '".*"' | tr -d '"')"
    debug "GRUB_CMDLINE_LINUX" "$grub_cmdline"
    if [[ -n "$grub_cmdline" ]]; then
      pattern="(systemd.unified_cgroup_hierarchy)=(.*)"
      if [[ $grub_cmdline =~ $pattern ]]; then
        pattern=${pattern//(/\\(}
        grub_cmdline="$(echo "$grub_cmdline" |
          sed "s/${pattern//)/\\)}/\1=$cgroup_toggle/")"
        debug "GRUB_CMDLINE_LINUX switched" "$grub_cmdline"
      else
        grub_cmdline="$grub_cmdline systemd.unified_cgroup_hierarchy=$cgroup_toggle"
        debug "GRUB_CMDLINE_LINUX appended" "$grub_cmdline"
      fi
    else
      grub_cmdline="systemd.unified_cgroup_hierarchy=$cgroup_toggle"
      debug "GRUB_CMDLINE_LINUX new" "$grub_cmdline"
    fi
    sed -i "s/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX=\"$grub_cmdline\"/" /etc/default/grub
  fi

  reboot
  exit 0
}
#}}}: cgroupsv2

setup_cron() { #{{{
  local temp_file
  temp_file=$(mktemp)
  crontab -l >"$temp_file" 2>/dev/null || echo "" >"$temp_file"

  if grep -qE "main\.sh (status|prune)" "$temp_file"; then
    clean_cron
    crontab -l >"$temp_file" 2>/dev/null || echo "" >"$temp_file"
  fi
  {
    echo "* * * * * /bin/bash $SCRIPT_DIR/main.sh status"
    echo "0 */4 * * * /bin/bash $SCRIPT_DIR/main.sh prune"
  } >>"$temp_file"
  /usr/bin/crontab "$temp_file"
}
#}}}: setup_cron

clean_cron() { #{{{
  local temp_file
  temp_file=$(mktemp)
  crontab -l >"$temp_file" 2>/dev/null

  if [[ -s "$temp_file" ]]; then
    # Match by command tail so old crontab entries with $PWD paths are also cleaned up.
    sed -i '\|main\.sh status$|d' "$temp_file"
    sed -i '\|main\.sh prune$|d' "$temp_file"
    /usr/bin/crontab "$temp_file"
  fi
}
#}}}: clean_cron

#}}}: Services

#{{{ Other

cleanup() { #{{{
  printf "\nGraceful shutdown..\n"
  [[ -n ${spinner_pid} ]] && kill "${spinner_pid}" >&/dev/null
  exit 0
}
#}}}: cleanup

force_exec() { #{{{
  [[ "$FORCE_PASS" == true ]] && return 0
  return 1
}
#}}}: force_exec

no_clean_on_fail() { #{{{
  [[ "$NO_CLEAN_ON_FAIL" == true ]] && return 0
  return 1
}
#}}}: no_clean_on_fail

spinner() { #{{{
  local spinner_pid=$1
  local msg="$2"
  local status="$3"
  local log_file="$LOG_FILE"
  local delay=0.15
  local spinstr='|/-\'
  spinner_msg "$msg"
  if ! is_debug; then
    while ps a | awk '{print $1}' | grep "${spinner_pid}" >&/dev/null; do
      local temp=${spinstr#?}
      printf "${C_BOLD}[%c]${C_RESET}" "$spinstr"
      local spinstr=$temp${spinstr%"$temp"}
      sleep $delay
      printf "\b\b\b"
    done
  else
    tail -n0 -f "${log_file}" --pid "${spinner_pid}"
  fi
  wait "${spinner_pid}"
  local exit_code
  exit_code=$?
  printf "      \b\b\b\b\b\r"
  debug "$msg (exit code):" "$exit_code"
  if is_debug; then :; else
    spinner_msg "$msg" "$exit_code"
  fi
  ((exit_code != 0)) && log_err && exit $exit_code
  return $exit_code
}
#}}}: spinner

clean_local_setup() { #{{{
  debug "Stopping services.."
  systemctl stop ecs 2>/dev/null
  debug "Stopping $CONTAINER_ORCHESTRATOR containers.."
  $CONTAINER_ORCHESTRATOR stop ecs-agent >&/dev/null
  debug "Removing $CONTAINER_ORCHESTRATOR containers.."
  $CONTAINER_ORCHESTRATOR rm ecs-agent >&/dev/null
  debug "Removing $CONTAINER_ORCHESTRATOR network: ${SG_DOCKER_NETWORK}.."
  $CONTAINER_ORCHESTRATOR network rm "${SG_DOCKER_NETWORK}" >&/dev/null
  debug "Removing local configuration.."

  files_and_dir_to_remove=(
    "/var/log/ecs"
    "/etc/ecs"
    "/var/lib/ecs"
    "volumes/"
    "./aws-credentials"
    "./db-state"
    "/var/log/registration"
    "./ssm-binaries"
    "/var/lib/amazon/ssm"
    "/root/.aws/credentials"
    "/etc/systemd/system/ecs.service.d/http-proxy.conf"
    "/etc/systemd/system/amazon-ssm-agent.service.d/http-proxy.conf"
    "/etc/systemd/system/snap.amazon-ssm-agent.amazon-ssm-agent.service.d/http-proxy.conf"
  )

  for item in "${files_and_dir_to_remove[@]}"; do
    if [[ -e "${item}" ]]; then
      rm -rf "$item" && debug "$item removed successfully." || debug "Failed to remove $item."
    fi
  done

  # revert config to as it was earlier
  [[ -e "${HOME}/original_docker_config.json" ]] && cp "${HOME}/original_docker_config.json" "${HOME}/.docker/config.json"
  [[ -e "${HOME}/original_docker_daemon.json" ]] && cp "${HOME}/original_docker_daemon.json" "/etc/docker/daemon.json"

  # clean_cron

  # Wait for AWS SSM Managed Instance to deregister on AWS side
  sleep 10s

  return 0
}
#}}}: clean_local_setup

check_variable_value() { #{{{
  local variable_name=$1
  [[ -z "${!variable_name}" ]] &&
    die "Variable can't be empty" "$variable_name"
  return 0
}
#}}}: check_variable_value

#}}}: Other

#{{{ Local configuration

iptables_ensure() { #{{{
  # Idempotent iptables rule insert/append.
  # Usage: iptables_ensure -A|-I [-t TABLE] CHAIN args...
  local op="$1"
  shift
  local table_args=()
  if [[ "$1" == "-t" ]]; then
    table_args=(-t "$2")
    shift 2
  fi
  if ! iptables "${table_args[@]}" -C "$@" 2>/dev/null; then
    iptables "${table_args[@]}" "$op" "$@"
  fi
}
#}}}: iptables_ensure

configure_local_data() { #{{{
  mkdir -p "$ECS_LOG_DIR" "$ECS_CONFIG_DIR" "$ECS_DATA_DIR" "$REGISTRATION_DIR"
  rm -rf "$ECS_CONFIG_DIR/ecs.config" >/dev/null

  spinner_wait "Configuring local data.."

  # See https://github.com/aws/amazon-ecs-agent/blob/master/README.md for the full set of agent env vars.

  if [[ $RUNNER_GROUP_DOC_VERSION == "V4" ]]; then
    ECS_INSTANCE_ATTRIBUTES="{\"sg_organization\": \"${ORGANIZATION_NAME}\",\"sg_runner_id\": \"${RUNNER_ID}\", \"sg_runner_group_id\": \"${RUNNER_GROUP_ID}\", \"sg_runner_group_signature\": \"${SG_RUNNER_GROUP_SIGNATURE}\"}"
  else
    ECS_INSTANCE_ATTRIBUTES="{\"sg_organization\": \"${ORGANIZATION_NAME}\",\"sg_runner_id\": \"${RUNNER_ID}\", \"sg_runner_group_id\": \"${RUNNER_GROUP_ID}\"}"
  fi

  cat >"$ECS_CONFIG_DIR/ecs.config" <<EOF
ECS_CLUSTER=${ECS_CLUSTER}
AWS_DEFAULT_REGION=${LOCAL_AWS_DEFAULT_REGION}
ECS_INSTANCE_ATTRIBUTES=${ECS_INSTANCE_ATTRIBUTES}
ECS_LOGLEVEL=info
ECS_DISABLE_PRIVILEGED=false
ECS_ENABLE_UNTRACKED_IMAGE_CLEANUP=true
ECS_ENGINE_TASK_CLEANUP_WAIT_DURATION=24h
ECS_IMAGE_CLEANUP_INTERVAL=24h
ECS_IMAGE_MINIMUM_CLEANUP_AGE=1h
NON_ECS_IMAGE_MINIMUM_CLEANUP_AGE=1h
ECS_TASK_METADATA_RPS_LIMIT=300,400
AWS_EC2_METADATA_DISABLED=true
ECS_LOGFILE=/log/ecs-agent.log
ECS_DATADIR=/data/
ECS_ENABLE_TASK_IAM_ROLE=true
ECS_ENABLE_TASK_IAM_ROLE_NETWORK_HOST=true
ECS_EXTERNAL=true
EOF

  if [[ -n "${HTTP_PROXY}" ]]; then
    cat >>"$ECS_CONFIG_DIR/ecs.config" <<EOF
HTTP_PROXY=${HTTP_PROXY}
HTTPS_PROXY=${HTTP_PROXY}
NO_PROXY=${NO_PROXY}
EOF
  fi

  spinner_msg "Configuring local data" 0
}
#}}}: configure_local_data

configure_local_network() { #{{{
  spinner_wait "Configuring local network.."

  $CONTAINER_ORCHESTRATOR network create --driver bridge "${SG_DOCKER_NETWORK}" >&/dev/null
  bridge_id="br-$($CONTAINER_ORCHESTRATOR network ls -q --filter "name=${SG_DOCKER_NETWORK}")"
  iptables_ensure -I DOCKER-USER -i "${bridge_id}" -d 169.254.169.254,10.0.0.0/24 -j DROP

  debug "$CONTAINER_ORCHESTRATOR network ${SG_DOCKER_NETWORK} created."

  # Enable IAM roles for tasks
  sysctl -w net.ipv4.conf.all.route_localnet=1 >/dev/null
  sysctl -w net.ipv4.ip_forward=1 >/dev/null

  iptables_ensure -A -t nat PREROUTING -p tcp -d 169.254.170.2 --dport 80 -j DNAT --to-destination 127.0.0.1:51679
  iptables_ensure -A -t nat OUTPUT -d 169.254.170.2 -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 51679

  spinner_msg "Configuring local network" 0
}
#}}}: configure_local_network

export_proxy_env() { #{{{
  if [[ -n "${HTTP_PROXY}" ]]; then
    export HTTP_PROXY=${HTTP_PROXY}
    export HTTPS_PROXY=${HTTP_PROXY}
    export http_proxy="http://${HTTP_PROXY}"
    export https_proxy="http://${HTTP_PROXY}"
  fi
}
#}}}: export_proxy_env

configure_http_proxy() { #{{{
  [[ -z "${HTTP_PROXY}" ]] && return 0

  info "Setting up Proxy configuration for the registration process."
  info "Docker should be setup to use the same proxy. For more info see: https://docs.docker.com/engine/cli/proxy/"
  debug "Setting up HTTP PROXY to ${HTTP_PROXY} for the ECS agent."

  detect_ssm_service
  mkdir -p "/etc/systemd/system/${SSM_SERVICE_NAME}.d"
  cat <<EOF >"/etc/systemd/system/${SSM_SERVICE_NAME}.d/http-proxy.conf"
[Service]
Environment="http_proxy=http://${HTTP_PROXY}"
Environment="https_proxy=http://${HTTP_PROXY}"
Environment="no_proxy=${NO_PROXY}"
EOF
  debug "Generated http configuration for service ${SSM_SERVICE_NAME}"

  # Docker client config — used for fetching images / interacting with the internet
  mkdir -p "${HOME}/.docker"
  local http_proxy_docker_config
  http_proxy_docker_config="{ \"proxies\": { \"default\": { \"httpProxy\": \"http://${HTTP_PROXY}\", \"httpsProxy\": \"http://${HTTP_PROXY}\", \"noProxy\": \"${NO_PROXY}\" } } }"
  [[ -e "$HOME/.docker/config.json" ]] && cp "$HOME/.docker/config.json" "$HOME/original_docker_config.json"
  patch_json "$HOME/.docker/config.json" "$http_proxy_docker_config"

  # Docker daemon config — used for authenticating to the registry
  local http_proxy_docker_daemon_config
  http_proxy_docker_daemon_config="{ \"proxies\": { \"http-proxy\": \"http://${HTTP_PROXY}\", \"https-proxy\": \"http://${HTTP_PROXY}\", \"no-proxy\": \"${NO_PROXY}\" } }"
  [[ -e "/etc/docker/daemon.json" ]] && cp "/etc/docker/daemon.json" "$HOME/original_docker_daemon.json"
  patch_json "/etc/docker/daemon.json" "$http_proxy_docker_daemon_config"

  systemctl daemon-reload
  systemctl restart docker

  export_proxy_env
}
#}}}: configure_http_proxy

# StackGuardian never launches ECS tasks with enableExecuteCommand, so ECS Exec
# is unused on runners. AWS's ecs-anywhere-install.sh stages the SSM session
# binaries under ECS_EXEC_DEPS_DIR regardless: its exec-setup call is
# unconditional and the script exposes no flag to skip it. That leaves unused
# binaries on disk which trip vulnerability scanners, e.g. CVE-2026-71556 in the
# go-git version vendored by amazon-ssm-agent 3.3.4624.0.
#
# The ECS agent treats these dependencies as optional: when the directory is
# absent it starts normally and simply stops advertising the
# ecs.capability.execute-command attribute (see appendExecCapabilities in
# amazon-ecs-agent), which we never rely on.

disable_ecs_exec_setup() { #{{{
  # Best effort: neuter the installer's `exec-setup` call so the SSM binaries
  # are never downloaded. remove_ecs_exec_deps is the backstop if this misses.
  local script="$1"

  if ! grep -qx 'exec-setup' "$script"; then
    debug "No exec-setup call found in" "$(basename "$script")" "- skipping patch."
    return 0
  fi

  # Write-and-move rather than `sed -i`: the in-place flag is not portable.
  if sed 's/^exec-setup$/: # exec-setup disabled: ECS Exec is unused/' \
    "$script" >"${script}.patched" && mv "${script}.patched" "$script"; then
    debug "Disabled ECS Exec dependency staging in" "$(basename "$script")"
  else
    rm -f "${script}.patched"
    debug "Could not patch" "$(basename "$script")" "- relying on cleanup."
  fi

  # debug() is a no-op returning non-zero unless --debug is set; never let that
  # become this function's exit status.
  return 0
}
#}}}: disable_ecs_exec_setup

is_ecs_exec_deps_path() { #{{{
  # Guard for the root-run `rm -rf` in remove_ecs_exec_deps. ECS_EXEC_DEPS_DIR
  # is overridable for testing, which makes it the one place in this script
  # where an env var supplies a whole deletion path rather than a fixed literal.
  # Accept only an absolute path that actually names a deps directory, so a
  # stray "/" or "/etc" in the environment can never reach rm.
  #
  # Kept as a pure predicate so the dangerous inputs are unit-testable without
  # any test ever pointing rm at them. A trailing slash is rejected too: the
  # refusal is logged and harmless, unlike the alternative.
  case "${1:-}" in
  /*/execute-command) return 0 ;;
  *) return 1 ;;
  esac
}
#}}}: is_ecs_exec_deps_path

remove_ecs_exec_deps() { #{{{
  # Authoritative cleanup: drop whatever exec-setup managed to stage.
  if ! is_ecs_exec_deps_path "$ECS_EXEC_DEPS_DIR"; then
    debug "Refusing to remove unexpected ECS_EXEC_DEPS_DIR:" "$ECS_EXEC_DEPS_DIR"
    return 0
  fi

  [[ -d "$ECS_EXEC_DEPS_DIR" ]] || return 0

  if rm -rf "$ECS_EXEC_DEPS_DIR"; then
    debug "Removed unused ECS Exec dependencies:" "$ECS_EXEC_DEPS_DIR"
  else
    debug "Failed to remove ECS Exec dependencies:" "$ECS_EXEC_DEPS_DIR"
  fi

  # Hardening only: a failure here must not fail an otherwise good registration.
  return 0
}
#}}}: remove_ecs_exec_deps

#}}}: Local configuration

#{{{ Registration / deregistration

fetch_organization_info() { #{{{
  local url metadata

  spinner_wait "Trying to fetch registration data.."
  url="${SG_BASE_API}/orgs/${ORGANIZATION_ID}/runnergroups/${RUNNER_GROUP_ID}/register/"

  debug "Calling URL:" "${url}"

  if api_call "POST" "$url"; then
    spinner_msg "Trying to fetch registration data" 0
    spinner_wait "Preparing environment.."
    metadata="$(echo "${response}" | jq -r '.data.RegistrationMetadata[0]')"
    if [[ "$metadata" == "null" || -z "$metadata" ]]; then
      spinner_msg "Preparing environment.." 1
      die "API data missing registration metadata."
    fi
  else
    spinner_msg "Trying to fetch registration data" 1
    die "Could not fetch data from API." "$status_code" "$message"
  fi
  spinner_msg "Preparing environment" 0

  ECS_CLUSTER="$(echo "${metadata}" | jq -r '.ECSCluster')"
  LOCAL_AWS_DEFAULT_REGION="$(echo "${metadata}" | jq -r '.AWSDefaultRegion')"
  SSM_ACTIVATION_ID="$(echo "${metadata}" | jq -r '.SSMActivationId')"
  SSM_ACTIVATION_CODE="$(echo "${metadata}" | jq -r '.SSMActivationCode')"

  for var in ECS_CLUSTER LOCAL_AWS_DEFAULT_REGION SSM_ACTIVATION_ID SSM_ACTIVATION_CODE; do
    check_variable_value "$var"
  done

  debug_variable "ECS_CLUSTER"
  debug_variable "LOCAL_AWS_DEFAULT_REGION"
  debug_secret "SSM_ACTIVATION_ID"
  debug_secret "SSM_ACTIVATION_CODE"

  ORGANIZATION_NAME="$(echo "${response}" | jq -r '.data.OrgName')"
  ORGANIZATION_ID="$(echo "${response}" | jq -r '.data.OrgId')"
  RUNNER_ID="$(echo "${response}" | jq -r '.data.RunnerId')"
  RUNNER_GROUP_ID="$(echo "${response}" | jq -r '.data.RunnerGroupId')"
  RUNNER_GROUP_ID="${RUNNER_GROUP_ID##*/}"
  RUNNER_GROUP_DOC_VERSION="$(echo "${response}" | jq -r '.data.RunnerGroup.DocVersion // empty')"
  SG_RUNNER_GROUP_SIGNATURE="$(echo "${response}" | jq -r '.data.RunnerGroup.RunnerGroupSignature // empty')"

  for var in ORGANIZATION_NAME ORGANIZATION_ID RUNNER_ID RUNNER_GROUP_ID; do
    check_variable_value "$var"
  done

  debug_variable "ORGANIZATION_NAME"
  debug_variable "ORGANIZATION_ID"
  debug_variable "RUNNER_ID"
  debug_variable "RUNNER_GROUP_ID"
  debug_variable "HTTP_PROXY"
}
#}}}: fetch_organization_info

register_instance() { #{{{
  local container_id container_health

  container_id=$($CONTAINER_ORCHESTRATOR ps -q -f "name=ecs-agent")
  container_health=$($CONTAINER_ORCHESTRATOR inspect ecs-agent --type container --format '{{.State.Health.Status}}' 2>/dev/null)

  if [[ -n "${container_id}" && "$container_health" == "healthy" ]]; then
    debug "Instance ecs-agent health:" "${container_health}"
    info "Instance agent already registered and running."
    NO_CLEAN_ON_FAIL=true
    configure_local_network
    save_registration_details
    exit 0
  fi

  fetch_organization_info
  configure_local_data
  configure_local_network

  spinner_wait "Downloading support files.."
  local ecs_install_script="/tmp/ecs-anywhere-install.sh"
  if ! curl --max-time 30 -fSsL \
    --proto "https" \
    -o "$ecs_install_script" \
    "https://amazon-ecs-agent.s3.amazonaws.com/ecs-anywhere-install-latest.sh" \
    >>"$LOG_FILE" 2>&1; then
    debug "Response:" "$(cat $LOG_FILE)"
    spinner_msg "Downloading support files" 1
    die "Unable to download" "ecs-anywhere-install.sh" "script"
  fi

  # Sanity check: must be a bash script
  if ! head -1 "$ecs_install_script" | grep -q '^#!/bin/bash'; then
    rm -f "$ecs_install_script"
    die "Downloaded script appears invalid" "missing bash shebang"
  fi

  disable_ecs_exec_setup "$ecs_install_script"

  spinner_msg "Downloading support files" 0

  check_systemctl_ecs_status

  detect_ssm_service

  # Restart SSM agent so creds are refreshed before installation starts
  echo "Restarting SSM agent.." >>"$LOG_FILE" 2>&1
  systemctl restart "$SSM_SERVICE_NAME" >>"$LOG_FILE" 2>&1
  systemctl status "$SSM_SERVICE_NAME" >>"$LOG_FILE" 2>&1

  /bin/bash /tmp/ecs-anywhere-install.sh \
    --region "${LOCAL_AWS_DEFAULT_REGION}" \
    --cluster "${ECS_CLUSTER}" \
    --activation-id "${SSM_ACTIVATION_ID}" \
    --activation-code "${SSM_ACTIVATION_CODE}" \
    --docker-install-source none \
    >>"$LOG_FILE" 2>&1 &

  local ecs_anywhere_pid="$!"
  until [[ "$($CONTAINER_ORCHESTRATOR inspect ecs-agent --type container --format '{{.State.Health.Status}}' 2>/dev/null)" == "healthy" ]]; do
    log_path="$($CONTAINER_ORCHESTRATOR inspect ecs-agent --type container --format '{{.LogPath}}' 2>/dev/null)"
    if [[ ! -e $log_path ]]; then
      continue
    fi
    sleep 5
    full_err_msg=$(grep -ioa -m1 -P '(?<=\[error\] logger=structured ).*?(?=status code)' "$log_path" 2>/dev/null)
    if [[ -n "$full_err_msg" ]]; then
      debug "Full Error:" "$full_err_msg"
      err=$(echo "$full_err_msg" | grep -io -P '(?<=msg=\\\").*?(?=\\\")')
      msg=$(echo "$full_err_msg" | grep -io -P '(?<=error=\\\").*?(?=\\)')
      kill "$ecs_anywhere_pid" >&/dev/null
      sleep 2
      echo "${err}:${msg}" >>"$LOG_FILE"
      exit 1
    fi
  done &
  spinner "$!" "Verifying registration of this runner"

  remove_ecs_exec_deps

  # setup_cron
  save_registration_details
}
#}}}: register_instance

deregister_instance() { #{{{
  local url

  if [[ -e "$ECS_CONFIG_DIR/ecs.config" ]]; then
    local instance_attrs runner_group_id_cfg org_name_cfg
    instance_attrs="$(grep ECS_INSTANCE_ATTRIBUTES "$ECS_CONFIG_DIR/ecs.config" | cut -d "=" -f2-)"
    runner_group_id_cfg="$(echo "$instance_attrs" | jq -r '.sg_runner_group_id')"
    org_name_cfg="$(echo "$instance_attrs" | jq -r '.sg_organization')"

    if [[ "$runner_group_id_cfg" != "$RUNNER_GROUP_ID" ]]; then
      die "Different configured and provided --runner-group. Configured: $runner_group_id_cfg, Provided: $RUNNER_GROUP_ID"
    fi
    if [[ -n "$org_name_cfg" && "$org_name_cfg" != "null" && "$org_name_cfg" != "$ORGANIZATION_ID" ]]; then
      die "Different configured and provided --organization. Configured: $org_name_cfg, Provided: $ORGANIZATION_ID"
    fi
    RUNNER_ID="$(echo "$instance_attrs" | jq -r '.sg_runner_id')"
    validate_runner_id "$RUNNER_ID"
  else
    if ! force_exec; then
      err "Instance probably deregistered"
      cmd_example "Try rerunning with" "-f/--force" "to force local cleanup"
      exit 1
    fi
  fi

  url="${SG_BASE_API}/orgs/${ORGANIZATION_ID}/runnergroups/${RUNNER_GROUP_ID}/deregister/"

  debug "Calling URL:" "${url}"
  payload="{ \"RunnerId\": \"${RUNNER_ID}\" }"
  debug "Payload:" "${payload}"

  spinner_wait "Trying to deregister instance.."
  if is_debug; then printf "\n"; fi
  if api_call "POST" "$url" "$payload"; then
    spinner_msg "Trying to deregister instance" 0
    clean_local_setup &
    spinner "$!" "Starting cleanup"
  else
    spinner_msg "Trying to deregister instance" 1
    err "Could not fetch data from API." "$status_code" "$message"
    if force_exec; then
      clean_local_setup &
      spinner "$!" "Starting cleanup"
    else
      info "Deregister with -f/--force to force local cleanup. Needed if you are registering this machine again."
    fi
    exit 1
  fi
}
#}}}: deregister_instance

#}}}: Registration / deregistration

#{{{ Diagnostics

update_diagnostic() { #{{{
  local key="$1" value="$2"
  jq --arg v "$value" ".$key = \$v" "$SG_DIAGNOSTIC_FILE" >"$SG_DIAGNOSTIC_TMP_FILE"
  mv "$SG_DIAGNOSTIC_TMP_FILE" "$SG_DIAGNOSTIC_FILE"
}
#}}}: update_diagnostic

doctor() { #{{{
  echo

  update_diagnostic "system.last_check" "$(date)"

  local status_list=""
  local service_status
  local service_list=("ecs" "docker")

  for service in "${service_list[@]}"; do
    service_status="$(systemctl is-active "${service}")"
    update_diagnostic "health.service.${service}" "$service_status"
    if [[ -n ${service_status} && ${service_status} == "active" ]]; then
      status_list="$(printf "%s\n%s" \
        "${status_list}" \
        "$(printf " | * ${C_BOLD}%s${C_RESET} service: ${C_GREEN}%s${C_RESET}\n" "${service}" "${service_status}")")"
    else
      status_list="$(printf "%s\n%s" \
        "${status_list}" \
        "$(printf " | * ${C_BOLD}%s${C_RESET} service: ${C_RED}%s${C_RESET}\n" "${service}" "${service_status}")")"
    fi
  done

  doctor_frame "System Service" "${status_list}"
  echo
  service_status="$(systemctl is-active "$CONTAINER_ORCHESTRATOR")"
  if [[ "${service_status}" != "active" ]]; then
    update_diagnostic "health.service.$CONTAINER_ORCHESTRATOR" "$service_status"
    printf " + Container Status (${C_BOLD}$CONTAINER_ORCHESTRATOR ${C_RESET}service: ${C_RED}%s${C_RESET})\n\n" "${service_status}"
    return
  fi

  status_list=""
  local containers=("ecs")

  for container in "${containers[@]}"; do
    local container_status
    container_status="$(
      $CONTAINER_ORCHESTRATOR ps \
        --filter "name=${container}-agent" \
        --format '{{.Status}}'
    )"
    if [[ -z ${container_status} ]]; then
      update_diagnostic "health.container.$container" "Not Running"
      status_list="$(printf "%s\n%s" \
        "${status_list}" \
        "$(printf " | * ${C_BOLD}%s${C_RESET} agent: ${C_RED}Not Running${C_RESET}\n" "${container}")")"
    else
      update_diagnostic "health.container.$container" "$container_status"
      status_list="$(printf "%s\n%s" \
        "${status_list}" \
        "$(printf " | * ${C_BOLD}%s${C_RESET} agent: ${C_GREEN}%s${C_RESET}\n" "${container}" "${container_status}")")"
    fi
  done
  doctor_frame "Container Status" "${status_list}"
  echo
}
#}}}: doctor

prune() { #{{{
  local prune_filter="until=4h"
  local curr_time
  curr_time=$(date)

  spinner_wait "Cleaning up system.."
  local reclaimed_containers_images
  reclaimed_containers_images=$($CONTAINER_ORCHESTRATOR system prune -f \
    --filter "$prune_filter" |
    cut -d: -f2 | tr -d ' ')

  update_diagnostic "system.docker.last_prune" "$curr_time"
  update_diagnostic "system.docker.reclaimed_containers_images" "$reclaimed_containers_images"
  update_diagnostic "system.docker.prune_filter" "$prune_filter"

  local reclaimed_volumes
  reclaimed_volumes=$($CONTAINER_ORCHESTRATOR system prune --volumes -f |
    cut -d: -f2 | tr -d ' ')
  update_diagnostic "system.docker.reclaimed_volumes" "$reclaimed_volumes"

  spinner_msg "Cleaning up system" 0
  info "Reclaimed at:" "$curr_time"
  info "Reclaimed from containers and images:" "$reclaimed_containers_images"
  info "Reclaimed from volumes:" "$reclaimed_volumes"
}
#}}}: prune

#}}}: Diagnostics

#{{{ Argument/init checks

check_arg_value() { #{{{
  if [[ "${2:0:2}" == "--" ]]; then
    die "Argument" "${1}" "has invalid value: $2"
  elif [[ -z "${2}" ]]; then
    die "Argument" "${1}" "can't be empty"
  fi
  return 0
}
#}}}: check_arg_value

validate_proxy_format() { #{{{
  local proxy="$1"
  # Allow hostname:port or IP:port format only (prevents command injection)
  if [[ ! "$proxy" =~ ^[a-zA-Z0-9._-]+:[0-9]+$ ]]; then
    die "Invalid proxy format" "$proxy" "(expected: hostname:port)"
  fi
}
#}}}: validate_proxy_format

validate_runner_id() { #{{{
  local runner_id="$1"
  # Only allow alphanumeric, hyphens, underscores (prevents injection)
  if [[ ! "$runner_id" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    die "Invalid RUNNER_ID format" "$runner_id"
  fi
}
#}}}: validate_runner_id

is_root() { #{{{
  # SG_SKIP_ROOT_CHECK bypasses the root requirement (for testing only).
  [[ "${SG_SKIP_ROOT_CHECK:-}" == "true" ]] && return 0
  if (($(id -u) != 0)); then
    die "This script must be run as" "root"
  fi
  return 0
}
#}}}: is_root

init_args_are_valid() { #{{{
  if [[ ! "$1" =~ ^register$|^deregister$|^status$|^info$|^prune$|^cgroupsv2$|^clean$ ]]; then
    die "Provided option" "${1}" "is invalid"
  elif [[ "$1" == "cgroupsv2" && ! "$2" =~ ^enable$|^disable$ ]]; then
    die "Arguments:" "enable, disable" "are required."
  elif [[ "$1" =~ register|deregister &&
    (! "$*" =~ --sg-node-token ||
    ! "$*" =~ --organization ||
    ! "$*" =~ --runner-group) ]]; then
    die "Arguments:" "--sg-node-token, --organization, --runner-group" "are required"
  fi
  return 0
}
#}}}: init_args_are_valid

check_sg_args() { #{{{
  if [[ -z "${SG_NODE_TOKEN}" ||
    -z "${ORGANIZATION_ID}" ||
    -z "${RUNNER_GROUP_ID}" ]]; then
    die "Arguments: " "--sg-node-token, --organization, --runner-group" "are required"
  fi
  return 0
}
#}}}: check_sg_args

parse_arguments() { #{{{
  while :; do
    case "${1}" in
    --sg-node-token)
      check_arg_value "${1}" "${2}"
      SG_NODE_TOKEN="${2}"
      shift 2
      ;;
    --organization)
      check_arg_value "${1}" "${2}"
      ORGANIZATION_ID="${2}"
      shift 2
      ;;
    --runner-group)
      check_arg_value "${1}" "${2}"
      RUNNER_GROUP_ID="${2}"
      shift 2
      ;;
    --http-proxy)
      check_arg_value "${1}" "${2}"
      validate_proxy_format "${2}"
      HTTP_PROXY="${2}"
      shift 2
      ;;
    --no-proxy)
      check_arg_value "${1}" "${2}"
      NO_PROXY="${NO_PROXY},${2}"
      shift 2
      ;;
    -f | --force)
      FORCE_PASS=true
      shift
      ;;
    --no-clean-on-fail)
      NO_CLEAN_ON_FAIL=true
      shift
      ;;
    --debug)
      LOG_DEBUG=true
      shift
      ;;
    *)
      [[ -z "${1}" ]] && break
      die "Invalid argument:" "${1}"
      ;;
    esac
  done
}
#}}}: parse_arguments

#}}}: Argument/init checks

#{{{ Preflight + main

preflight() { #{{{
  if [[ ! -d /run/systemd/system ]]; then
    die "Private runner is only available for" "systemd-based" "systems"
  fi

  info "Running on" "$(cat /etc/*release | grep -oP '(?<=PRETTY_NAME=").*?(?=")')"

  if [[ -e /sys/fs/cgroup/cgroup.controllers ]]; then
    if [[ "$(grep "^GRUB_CMDLINE_LINUX=\".*systemd.unified_cgroup_hierarchy=0\"" /etc/default/grub)" == "" ]]; then
      info "Private runner is running on" "cgroupsv2"
    fi
  fi

  local missing=()
  for cmd in "${COMMANDS[@]}"; do
    type "$cmd" >&/dev/null || missing+=("$cmd")
  done
  ((${#missing[@]} > 0)) && die "Commands" "${missing[*]}" "not installed"

  for orchestrator in "${CONTAINER_ORCHESTRATORS[@]}"; do
    if check_container_orchestrator "$orchestrator"; then
      info "Default container orchestrator" "$orchestrator"
      if [[ "$orchestrator" == "podman" ]]; then
        info "Container orchestrator not supported. Aborting.."
        exit 0
      fi
      CONTAINER_ORCHESTRATOR="$orchestrator"
      break
    else
      info "Container orchestrator" "$orchestrator" "not found. Trying next.."
    fi
  done

  if [[ -z $CONTAINER_ORCHESTRATOR ]]; then
    die "One of following container orchestrators required:" "${CONTAINER_ORCHESTRATORS[*]}"
  fi

  # Probe IMDSv2 (AWS); silently no-ops elsewhere.
  local imdsv2_token attached_iam_role
  imdsv2_token=$(curl --max-time 5 -fSsLkX PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 120" 2>/dev/null)
  if [[ -n "$imdsv2_token" ]]; then
    attached_iam_role=$(curl --max-time 10 -fSsLk --proto "https" -H "X-aws-ec2-metadata-token: $imdsv2_token" "http://169.254.169.254/latest/meta-data/iam/security-credentials/" 2>/dev/null)
  else
    attached_iam_role=$(curl --max-time 10 -fSsLk "http://169.254.169.254/latest/meta-data/iam/security-credentials/" 2>/dev/null)
  fi
  if [[ -n "$attached_iam_role" ]]; then
    debug "Response:" "$attached_iam_role"
    info "Found an IAM role attached to the instance" "$attached_iam_role"
  fi
}
#}}}: preflight

main() { #{{{
  [[ "${*}" =~ --help || $# -lt 1 ]] && show_help && exit 0

  is_root && init_args_are_valid "$@"

  init_diagnostic_dir

  if [[ ! -e "$LOG_FILE" ]]; then
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"
  fi

  preflight

  case "${1}" in
  register)
    shift
    parse_arguments "$@"
    check_sg_args
    configure_http_proxy
    register_instance
    ;;
  deregister)
    shift
    parse_arguments "$@"
    check_sg_args
    # Proxy env vars are needed for the deregister API call, but the docker /
    # SSM proxy config is wiped seconds later by clean_local_setup, so we skip it.
    export_proxy_env
    deregister_instance
    ;;
  prune)
    prune
    exit 0
    ;;
  status)
    doctor
    exit 0
    ;;
  info)
    print_details
    exit 0
    ;;
  cgroupsv2)
    if [[ "$CGROUPSV2_PREVIEW" == true ]]; then
      parse_arguments "${@:3}"
      cgroupsv2 "$2"
    else
      info "cgroupsv2 toggle is gated behind" "CGROUPSV2_PREVIEW=true"
      exit 0
    fi
    ;;
  clean)
    shift
    parse_arguments "$@"
    clean_local_setup &
    spinner "$!" "Starting cleanup"
    ;;
  esac
}
#}}}: main

#}}}: Preflight + main

# Only wire traps and run main when executed directly. When sourced (e.g. by a
# test harness), expose the functions without side effects.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  trap cleanup SIGINT
  trap exit_help EXIT

  main "$@"
fi

#!/bin/bash
#
# Register external instance to AWS ECS with ecs-anywhere script.

set -o pipefail

## colors for printf
readonly C_RED_BOLD="\033[1;31m"
readonly C_RED="\033[0;31m"
readonly C_GREEN_BOLD="\033[1;32m"
readonly C_GREEN="\033[0;32m"
readonly C_YELLOW_BOLD="\033[1;33m"
readonly C_YELLOW="\033[0;33m"
readonly C_BLUE_BOLD="\033[1;34m"
readonly C_BLUE="\033[0;34m"
readonly C_MAGENTA_BOLD="\033[1;35m"
readonly C_MAGENTA="\033[0;35m"
readonly C_CYAN_BOLD="\033[1;36m"
readonly C_CYAN="\033[0;36m"
readonly C_RESET="\033[0m"
readonly C_BOLD="\033[1m"

log_date() {
  printf "${C_MAGENTA}[%s]" "$(date +'%Y-%m-%dT%H:%M:%S%z')"
}

err() {
  printf "%s ${C_RED_BOLD}[ERROR] ${C_RESET}%s${C_BOLD} %s${C_RESET} %s" "$(log_date)" "${1}" "${2}" "${@:3}" >&2
  printf "\n\n(Try ${C_BOLD}%s --help${C_RESET} for more information.)\n" "$(basename "${0}")"
  cleanup
}

info() {
  printf "%s ${C_GREEN}INFO:${C_RESET} %s${C_BOLD} %s${C_RESET} %s\n" "$(log_date)" "${1}" "${2}" "${@:3}"
}

show_help() {
  printf "\nsudo ${C_BOLD}%s${C_RESET} [register deregister] arguments..\n" "$(basename "${0}")"
  printf "\n  Required arguments:\n"
  printf "\t--sg-node-token\t\tToken provided by StackGuardian platform.\n"
  printf "\t--sg-node-api-endpoint\tStackGuardian API endpoint.\n"
  printf "\n  Optional arguments:\n"
  printf "\t--debug\t\t\tShow log output.\n"
  printf "\t--help\t\t\tShow this help menu.\n"
  exit 2
}

spinner() {
    local pid=$1
    local delay=0.15
    local spinstr='|/-\'
    if [[ "${LOG_DEBUG}" == "false" ]]; then
      while ps a | awk '{print $1}' | grep "${pid}" >&/dev/null; do
          local temp=${spinstr#?}
          printf " [%c] " "$spinstr"
          local spinstr=$temp${spinstr%"$temp"}
          sleep $delay
          printf "\b\b\b\b\b\b"
      done
    else
      tail -n0 -f /var/log/ecs-install.log --pid "${pid}"
    fi
    wait "${pid}"
    local exit_status=$?
    if (( "${exit_status}" != 0 )); then
      # err "Process failed with exit code status" "${exit_status}"
      if [[ "${LOG_DEBUG}" == "true" ]]; then
        info "Showing 10 last lines from" "/var/log/ecs/ecs-init.log"
        tail -n10 /var/log/ecs/ecs-init.log
      fi
      err "Script" "ecs-anywhere-install.sh" "failed to register external instance"
    fi
    printf "    \b\b\b\b"
}

#######################################
# Fetch necessary info from API.
# Globals:
#   SG_NODE_TOKEN
#   SG_NODE_API_ENDPOINT
# Arguments:
#   None
# Outputs:
#   Write to STDERR if error and exit.
#   Set all neccessary environment variables.
#######################################
fetch_organization_info() {
  local response
  local metadata

  # info "Fetching data..."
  # if ! response=$(curl -fSsLk -H "Authorization: apikey ${SG_NODE_TOKEN}" "${SG_NODE_API_ENDPOINT}/orgs/${ORGANIZATION_ID}/runnergroups/${RESOURCE_ID}/register/"); then
  #   err "Could not fetch data from API"
  #   exit 1
  # fi

  response=$(cat data.json)

  ## API response values (Registration Metadata)
  metadata="$(echo "${response}" | jq -r '.data.RegistrationMetadata[0]')"
  ECS_CLUSTER="${ECS_CLUSTER:=$(echo "${metadata}" | jq -r '.ECSCluster')}"
  AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:=$(echo "${metadata}" | jq -r '.AWSDefaultRegion')}"
  SSM_ACTIVATION_ID="${SSM_ACTIVATION_ID:=$(echo "${metadata}" | jq -r '.SSMActivationId')}"
  SSM_ACTIVATION_CODE="${SSM_ACTIVATION_CODE:=$(echo "${metadata}" | jq -r '.SSMActivationCode')}"

  if [[ "${LOG_DEBUG}" == "true" ]]; then
    echo "ECS_CLUSTER: ${ECS_CLUSTER}"
    echo "AWS_DEFAULT_REGION: ${AWS_DEFAULT_REGION}"
    echo "SSMActivationId: ${SSM_ACTIVATION_ID}"
    echo "SSM_ACTIVATION_CODE: ${SSM_ACTIVATION_CODE}"
  fi

  ## Everything else
  ORGANIZATION_NAME="${ORGANIZATION_NAME:=$(echo "${response}" | jq -r '.data.OrgName')}"
  ORGANIZATION_ID="${ORGANIZATION_ID:=$(echo "${response}" | jq -r '.data.OrgId')}"
  EXTERNAL_ID="${EXTERNAL_ID:=$(echo "${response}" | jq -r '.data.RunnerId')}"
  RESOURCE_ID="${RESOURCE_ID:=$(echo "${response}" | jq -r '.data.RunnerGroupId')}"
  AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:=$(echo "${response}" | jq -r '.data.AWSAccessKeyId')}"
  AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:=$(echo "${response}" | jq -r '.data.AWSSecretAccessKey')}"

  if [[ "${LOG_DEBUG}" == "true" ]]; then
    echo "ORGANIZATION_NAME: ${ORGANIZATION_NAME}"
    echo "ORGANIZATION_ID: ${ORGANIZATION_ID}"
    echo "EXTERNAL_ID: ${EXTERNAL_ID}"
    echo "RESOURCE_ID: ${RESOURCE_ID}"
    echo "AWS_ACCESS_KEY_ID: ${AWS_ACCESS_KEY_ID}"
    echo "AWS_SECRET_ACCESS_KEY: ${AWS_SECRET_ACCESS_KEY}"
  fi

}

#######################################
# Configure local direcotries and files.
# Globals:
#   ECS_CLUSTER
#   AWS_DEFAULT_REGION
#   ORGANIZATION_ID
#   EXTERNAL_ID
#   RESOURCE_ID
# Arguments:
#   None
# Outputs:
#   Writes STOUT on success.
#######################################
configure_local_data() {
  # Set up directories the agent uses
  mkdir -p /var/log/ecs /etc/ecs /var/lib/ecs/data
  rm -rf /etc/ecs/ecs.config /var/lib/ecs/ecs.config > /dev/null
  # rm -rf /var/lib/amazon/ssm/Vault/Store/*

  cat > /etc/ecs/ecs.config << EOF
  info "Configuring local data.."
ECS_CLUSTER=${ECS_CLUSTER}
AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}
ECS_INSTANCE_ATTRIBUTES={"sg_organization": "${ORGANIZATION_NAME}","sg_externalid": "${EXTERNAL_ID}"}
ECS_LOGLEVEL=/log/ecs-agent.log
ECS_DATADIR=/data/
ECS_ENABLE_TASK_IAM_ROLE=true
ECS_ENABLE_TASK_IAM_ROLE_NETWORK_HOST=true
EOF

  cat > /var/lib/ecs/ecs.config << EOF
AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}
ECS_EXTERNAL=true
EOF

}

#######################################
# Configure local network.
# Globals:
#   None
# Arguments:
#   None
# Outputs:
#   Writes STOUT on success.
#######################################
configure_local_network() {
  info "Configuring local network.."

  # Create wf-steps-net docker network
  docker network create --driver bridge "${SG_DOCKER_NETWORK}" >&/dev/null
  bridge_id="br-$(docker network ls -q --filter "name=${SG_DOCKER_NETWORK}")"
  iptables -I DOCKER-USER -i "${bridge_id}" -d 169.254.169.254,10.0.0.0/24 -j DROP
  info "Docker network ${SG_DOCKER_NETWORK} created."

  # Set up necessary rules to enable IAM roles for tasks
  sysctl -w net.ipv4.conf.all.route_localnet=1 >/dev/null
  # sysctl -w net.ipv4.ip_forward=1
  iptables -t nat -A PREROUTING -p tcp -d 169.254.170.2 --dport 80 -j DNAT --to-destination 127.0.0.1:51679
  iptables -t nat -A OUTPUT -d 169.254.170.2 -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 51679

}

#######################################
# Run fluentbit Docker container for logging
# Globals:
#
# Arguments:
#   AWS_ACCESS_KEY_ID
#   AWS_SECRET_ACCESS_KEY
# Outputs:
#   Write to STDOUT/STERR
#   if successfull/error.
#######################################
configure_fluentbit() {
  info "Starting fluentbit agent.."
  local running=$(docker ps -q --filter "name=fluentbit-agent")
  local exists=$(docker ps -aq --filter "name=fluentbit-agent")
  if [[ -z "${exists}" ]]; then
    docker run -d \
      --name fluentbit-agent \
      -p 24224:24224 \
      -e AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID}" \
      -e AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY}" \
      -v "$(pwd)"/fluentbit.conf:/fluent-bit/etc/fluentbit.conf \
      fluent/fluent-bit:2.0.9 \
      /fluent-bit/bin/fluent-bit -c /fluent-bit/etc/fluentbit.conf >/dev/null
    info "Registered fluentbit agent."
  else
    if [[ -z "${running}" ]]; then
      docker start fluentbit-agent >&/dev/null
      info "Started fluentbit agent."
    else
      info "Fluentbit agent already running."
    fi
  fi

}

#######################################
# Check if specific service.$1 is runing.
# If not try reload or restart.
# Globals:
#   None
# Arguments:
#   systemctl service
# Returns:
#   None
# Outputs:
#   Write to STDOUT/STDERR
#   if successfull/error.
#######################################
check_systemctl_status() {
  if ! systemctl is-active "$1" >&/dev/null; then
    info "Reloading/Restarting service.$1.."
    systemctl reload-or-restart "$1"
  fi
}

#######################################
# Check if ecs.service exists
# and if it is healthy and running.
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   0 if ecs.service does not exists
# Outputs:
#   Write to STDOUT/STERR
#   if successfull/error.
#######################################
check_systemcl_ecs_status() {
  systemctl status ecs --no-pager >&/dev/null
  if [[ "$?" =~ 4|0 ]]; then
    return 0
  else
    check_systemctl_status "ecs"
  fi
}

#######################################
# Check if docker.service exists
# and if it is healthy and running.
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   None
# Outputs:
#   Write to STDOUT/STERR
#   if successfull/error.
#######################################
check_systemcl_docker_status() {
  if type docker >&/dev/null; then
    check_systemctl_status "docker"
  fi
}

#######################################
# Register instance to AWS ECS.
# Globals:
#   AWS_DEFAULT_REGION
#   ECS_CLUSTER
#   SSM_ACTIVATION_ID
#   SSM_ACTIVATION_CODE
# Arguments:
#   None
# Outputs:
#   Write to STDOUT/STERR
#   if successfull/error.
#######################################
register_instance() {
  local registered=$(docker ps -q --filter "name=ecs-agent")
  if [[ -n "${registered}" ]]; then
    info "ECS Agent already registered and running."
    configure_local_network
    configure_fluentbit
    exit 0
  fi
  # check_sg_args
  fetch_organization_info
  configure_local_data

  rm /tmp/ecs* >&/dev/null

  curl -fSsL --proto "https" -o "/tmp/ecs-anywhere-install.sh" "https://amazon-ecs-agent.s3.amazonaws.com/ecs-anywhere-install-latest.sh" 2> /tmp/ecs_anywhere_download.log

  if (( $? != 0 )); then
    cat /tmp/ecs_anywhere_download.log
    err "Unable to download" "ecs-anywhere-install.sh" "script"
  fi

  # TODO(devops@hllvc.com): verify ecs-anywhere script integrity
  # gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv BCE9D9A42D51784F
  # curl --proto "https" -o "/tmp/ecs-anywhere-install.sh.asc" "https://amazon-ecs-agent.s3.amazonaws.com/ecs-anywhere-install-latest.sh.asc"
  # gpg --verify /tmp/ecs-anywhere-install.sh.asc /tmp/ecs-anywhere-install.sh | grep "Primary key"

  # Primary key fingerprint: F34C 3DDA E729 26B0 79BE  AEC6 BCE9 D9A4 2D51 784F
  #      Subkey fingerprint: D64B B6F9 0CF3 77E9 B5FB  346F 50DE CCC4 710E 61AF

  info "Trying to register instance to ECS cluster..."

  check_systemcl_docker_status
  check_systemcl_ecs_status

  [[ ! -e /var/log/ecs-install.log ]] && touch /var/log/ecs-install.log

  # if [[ "${LOG_DEBUG}" == "true" ]]; then
  #   tail -q -f /var/log/ecs-install.log &
  #   tail_pid="$!"
  # fi

  /bin/bash /tmp/ecs-anywhere-install.sh \
      --region "${AWS_DEFAULT_REGION}" \
      --cluster "${ECS_CLUSTER}" \
      --activation-id "${SSM_ACTIVATION_ID}" \
      --activation-code "${SSM_ACTIVATION_CODE}" \
      >>/var/log/ecs-install.log 2>&1 &
  spinner "$!"

  # if ! /bin/bash /tmp/ecs-anywhere-install.sh \
  #     --region "${AWS_DEFAULT_REGION}" \
  #     --cluster "${ECS_CLUSTER}" \
  #     --activation-id "${SSM_ACTIVATION_ID}" \
  #     --activation-code "${SSM_ACTIVATION_CODE}" \
  #     >>/var/log/ecs-install.log 2>&1 & spinner $!; then
  #   err "Script" "ecs-anywhere-install.sh" "failed to register external instance"
  #   [[ "${LOG_DEBUG}" == "true" ]] && tail -n10 /var/log/ecs/ecs-init.log
  #   exit 1
  # fi

  # [[ -n ${tail_pid} ]] && kill "${tail_pid}"

  info "Instance successfully registered to ECS cluster."

  configure_local_network
  configure_fluentbit
}

#######################################
# Make API call for de-registering.
# Globals:
#   SG_NODE_API_ENDPOINT
#   SG_NODE_TOKEN
# Arguments:
#   None
# Outputs:
#   Writes to STDOUT/STDERR
#   if de-registration is sucessfull.
#######################################
deregister_instance() {
  info "Stopping docker containers.."
  docker stop ecs-agent fluentbit-agent >&/dev/null
  info "Removing docker containers.."
  docker rm ecs-agent fluentbit-agent >&/dev/null
  info "Removing docker network: ${SG_DOCKER_NETWORK}.."
  docker network rm "${SG_DOCKER_NETWORK}" >&/dev/nul
  info "Removing local configuration.."
  rm -rf /var/log/ecs /etc/ecs /var/lib/ecs

  ## TODO(devops@hllvc.com): Handle de-registration process.
  return 0
  local response

  response=$(curl -vLk -H "Authorization: apikey ${SG_NODE_TOKEN}" "${SG_NODE_API_ENDPOINT}"/deregister_runner)
}

#######################################
# Print frame for doctor check.
# Globals:
#   None
# Arguments:
#   Title
#   Contents of frame
# Returns:
#   None
# Outputs:
#   Write to STDOUT frame with contents
#######################################
doctor_frame() {
  printf " + %s " "${1}"
  printf "\n |"
  printf "%s" "$2"
  # printf "\n |\n"
  printf "\n"
}

#######################################
# Check if all services is working
# Globals:
#
# Arguments:
#
# Returns:
#
# Outputs:
#  Write to STDOUT list
#  of services with status
#######################################
doctor() {
  info "Generating service doctor.."
  echo

  local status_list=""
  local service_status
  local service_list=( "ecs" "docker" )

  for service in "${service_list[@]}"; do
    service_status="$(systemctl is-active "${service}")"
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

  service_status="$(systemctl is-active docker)"
  if [[ "${service_status}" != "active" ]]; then
    printf " + Container Status (${C_BOLD}docker ${C_RESET}service: ${C_RED}%s${C_RESET})\n\n" "${service_status}"
    return
  fi

  status_list=""
  local containers=( "ecs" "fluentbit" )

  for container in "${containers[@]}"; do
    local container_status="$(docker ps \
      --filter "name=${container}-agent" \
      --format '{{.Status}}'\
      )"
    if [[ -z ${container_status} ]]; then
      status_list="$(printf "%s\n%s" \
        "${status_list}" \
        "$(printf " | * ${C_BOLD}%s${C_RESET} agent: ${C_RED}Not Running${C_RESET}\n" "${container}")")"
    else
      status_list="$(printf "%s\n%s" \
        "${status_list}" \
        "$(printf " | * ${C_BOLD}%s${C_RESET} agent: ${C_GREEN}%s${C_RESET}\n" "${container}" "${container_status}")")"
    fi
  done
  doctor_frame "Container Status" "${status_list}"

  echo
  info "Service doctor finished."
}

#######################################
# Check if provided argument is valid.
# Globals:
#   None
# Arguments:
#   Argument name
#   Argument value
# Returns:
#   0 if argument is valid.
# Outputs:
#   If error, write to STDERR and exit.
#######################################
check_arg_value() {
  ## TODO(devops@hllvc.com): make sure to validate double parameter input
  if [[ "${2:0:2}" == "--" ]]; then
    err "Argument" "${1}" "has invalid value: $2"
    exit 1
  elif [[ -z "${2}" ]]; then
    err "Argument" "${1}" "can't be empty"
    exit 1
  fi
  return 0
}

is_root() {
  if (( $(id -u) != 0 )); then
    err "This script must be run as" "root"
    exit 1
  fi
  return 0
}

init_args_are_valid() {
  if [[ ! "$1" =~ register|deregister ]]; then
    err "Provided option" "${1}" "is invalid"
    exit 1
  elif (( $# != 5 )); then
    err "Arguments:" "--sg-node-token, --sg-node-api-endpoint" "are required"
    exit 1
  fi
  return 0
}

check_sg_args() {
  if [[ -z "$SG_NODE_TOKEN" && -z "$SG_NODE_API_ENDPOINT" ]]; then
    err "Arguments: " "--sg-node-token, --sg-node-api-endpoint" "are required"
    exit 1
  fi
  return 0
}

main() {

if ! type jq >&/dev/null; then
  err "Command" "jq" "not installed" && exit 1
fi

[[ "${*}" =~ "--help" || $# -lt 1 ]] && show_help && exit 0

# is_root && init_args_are_valid "$@"

OPTION="${1}"
shift

while :; do
  case "${1}" in
  --sg-node-token)
    check_arg_value "${1}" "${2}"
    SG_NODE_TOKEN="${2}"
    shift 2
    ;;
  --sg-node-api-endpoint)
    check_arg_value "${1}" "${2}"
    SG_NODE_API_ENDPOINT="${2}"
    shift 2
    ;;
  --organization)
    check_arg_value "${1}" "${2}"
    ORGANIZATION_NAME="${2}"
    shift 2
    ;;
  --runner-group)
    check_arg_value "${1}" "${2}"
    RESOURCE_ID="${2}"
    shift 2
    ;;
  --debug)
      LOG_DEBUG=true
      shift
    ;;
  *)
    [[ -z "${1}" ]] && break
    err "Invalid argument:" "${1}"
    exit 1
    ;;
  esac
done
readonly SG_NODE_TOKEN SG_NODE_API_ENDPOINT
# readonly SG_NODE_TOKEN SG_NODE_API_ENDPOINT ORGANIZATION_ID RESOURCE_ID
readonly SG_DOCKER_NETWORK="wf-steps-net"
readonly LOG_DEBUG=${LOG_DEBUG:=false}

case "${OPTION}" in
  register)
    register_instance
    ;;
  deregister)
    deregister_instance
    ;;
  doctor)
    doctor
    ;;
esac

# Run the agent
# TODO: check which volumes will be exported?
# docker run --name ecs-agent9 \
#     --detach=true \
#     --restart=on-failure:10 \
#     --volume=/var/run/docker.sock:/var/run/docker.sock \
#     --volume=/var/log/ecs:/log \
#     --volume=/var/lib/ecs/data:/data \
#     --net=host \
#     --env-file=/etc/ecs/ecs.config \
#     amazon/amazon-ecs-agent:latest

# TODO: API call to ping the node
#
}

cleanup() {
  echo "Gracefull shutdown.."
  [[ -n ${script_pid} ]] && kill "${script_pid}" >&/dev/null
  exit 0
}

trap cleanup SIGINT

main "$@"

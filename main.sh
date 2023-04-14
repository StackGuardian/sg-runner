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
  printf "\n%s ${C_RED_BOLD}[ERROR] ${C_RESET}%s${C_BOLD} %s${C_RESET} %s" "$(log_date)" "${1}" "${2}" "${@:3}" >&2
  printf "\n\n(Try ${C_BOLD}%s --help${C_RESET} for more information.)\n" "$(basename "${0}")"
}

show_help() {
  printf "\nsudo ${C_BOLD}%s${C_RESET} [register deregister] arguments..\n" "$(basename "${0}")"
  printf "\n  Required arguments:\n"
  printf "\t--sg-node-token\t\tToken provided by StackGuardian platform.\n"
  printf "\t--sg-node-api-endpoint\tStackGuardian API endpoint.\n"
  printf "\n  Optional arguments:\n"
  printf "\t--help\t\t\tShow this help menu.\n"
  exit 2
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

  printf "\n%s ${C_GREEN}INFO:${C_RESET} Fetching data..\n" "$(log_date)"
  # if ! response=$(curl -fSsLk -H "Authorization: apikey ${SG_NODE_TOKEN}" "${SG_NODE_API_ENDPOINT}"/register_runner); then
  #   err "Could not fetch data from API"
  #   exit 1
  # fi

  response=$(cat data.json)

  ## API response values
  ECS_CLUSTER="${ECS_CLUSTER:=$(echo "${response}" | jq -r '.data.ECSCluster')}"
  AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:=$(echo "${response}" | jq -r '.data.AWSDefaultRegion')}"
  SSM_ACTIVATION_ID="${SSM_ACTIVATION_ID:=$(echo "${response}" | jq -r '.data.SSMActivationId')}"
  SSM_ACTIVATION_CODE="${SSM_ACTIVATION_CODE:=$(echo "${response}" | jq -r '.data.SSMActivationCode')}"
  ORGANIZATION_NAME="${ORGANIZATION_NAME:=$(echo "${response}" | jq -r '.data.OrgName')}"
  ORGANIZATION_ID="${ORGANIZATION_ID:=$(echo "${response}" | jq -r '.data.OrgId')}"
  EXTERNAL_ID="${EXTERNAL_ID:=$(echo "${response}" | jq -r '.data.ExternalId')}"
  RESOURCE_ID="${RESOURCE_ID:=$(echo "${response}" | jq -r '.data.ResourceId')}"

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

  printf "\n%s ${C_GREEN_BOLD}INFO: ${C_GREEN}Configured local data.\n" "$(log_date)"
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
  # Create wf-steps-net docker network
  docker network create --driver bridge "${SG_DOCKER_NETWORK}"
  bridge_id="br-$(docker network ls --filter "name=${SG_DOCKER_NETWORK}")"
  iptables -I DOCKER-USER -i "${bridge_id}" -d 169.254.169.254,10.0.0.0/24 -j DROP

  # Set up necessary rules to enable IAM roles for tasks
  sysctl -w net.ipv4.conf.all.route_localnet=1
  # sysctl -w net.ipv4.ip_forward=1
  iptables -t nat -A PREROUTING -p tcp -d 169.254.170.2 --dport 80 -j DNAT --to-destination 127.0.0.1:51679
  iptables -t nat -A OUTPUT -d 169.254.170.2 -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 51679

  printf "\n%s ${C_GREEN_BOLD}INFO: ${C_GREEN}Configured local network." "$(log_date)"
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
  # check_sg_args
  fetch_organization_info
  configure_local_data
  configure_local_network

  rm /tmp/ecs* >&/dev/null

  curl -fSsL --proto "https" -o "/tmp/ecs-anywhere-install.sh" "https://amazon-ecs-agent.s3.amazonaws.com/ecs-anywhere-install-latest.sh" 2> /tmp/ecs_anywhere_download.log

  if (( $? != 0 )); then
    err "Unable to download" "ecs-anywhere-install.sh" "script"
    echo
    cat /tmp/ecs_anywhere_download.log
    exit 1
  fi

  # TODO(devops@hllvc.com): verify ecs-anywhere script integrity
  # gpg --keyserver hkp://keyserver.ubuntu.com:80 --recv BCE9D9A42D51784F
  # curl --proto "https" -o "/tmp/ecs-anywhere-install.sh.asc" "https://amazon-ecs-agent.s3.amazonaws.com/ecs-anywhere-install-latest.sh.asc"
  # gpg --verify /tmp/ecs-anywhere-install.sh.asc /tmp/ecs-anywhere-install.sh | grep "Primary key"

  # Primary key fingerprint: F34C 3DDA E729 26B0 79BE  AEC6 BCE9 D9A4 2D51 784F
  #      Subkey fingerprint: D64B B6F9 0CF3 77E9 B5FB  346F 50DE CCC4 710E 61AF

  if ! /bin/bash /tmp/ecs-anywhere-install.sh \
      --region "${AWS_DEFAULT_REGION}" \
      --cluster "${ECS_CLUSTER}" \
      --activation-id "${SSM_ACTIVATION_ID}" \
      --activation-code "${SSM_ACTIVATION_CODE}"; then
    err "Script" "ecs-anywhere-install.sh" "failed to register external instance"
    exit 1
  fi

  printf "\n%s ${C_GREEN_BOLD}INFO: ${C_GREEN}Instance successfully registered to ECS cluster." "$(log_date)"
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
  rm -rf /var/log/ecs /etc/ecs /var/lib/ecs

  docker rm -f "$(docker ps -aq)"
  docker network rm "${SG_DOCKER_NETWORK}"

  ## TODO(devops@hllvc.com): Handle de-registration process.
  return 0
  local response

  response=$(curl -vLk -H "Authorization: apikey ${SG_NODE_TOKEN}" "${SG_NODE_API_ENDPOINT}"/deregister_runner)
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

# [[ "${*}" =~ "--help" || $# -lt 1 ]] && show_help && exit 0

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
  *)
    [[ -z "${1}" ]] && break
    err "Invalid argument:" "${1}"
    exit 1
    ;;
  esac
done
readonly SG_NODE_TOKEN SG_NODE_API_ENDPOINT
readonly SG_DOCKER_NETWORK="wf-steps-net"

case "${OPTION}" in
  register)
    register_instance
    ;;
  deregister)
    deregister_instance
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

main "$@"

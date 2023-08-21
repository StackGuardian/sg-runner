#!/bin/bash
#
# Register external instance to Stackguardian platform.

set -o pipefail

#{{{ Environment variables

## main
CONTAINER_ORCHESTRATOR=
LOG_DEBUG=${LOG_DEBUG:=false}
CGROUPSV2_PREVIEW=${CGROUPSV2_PREVIEW:=false}

readonly LOG_FILE="/tmp/sg_runner.log"

if [[ ! -e "$LOG_FILE" ]]; then
  touch "$LOG_FILE"
fi

# static
readonly COMMANDS=( "jq" "crontab" )
readonly CONTAINER_ORCHESTRATORS=( "docker" "podman" )
readonly SG_BASE_API=${SG_BASE_API:="https://api.app.stackguardian.io/api/v1"}
readonly FLUENTBIT_IMAGE="fluent/fluent-bit:2.0.9-debug"

# source .env if exists
# overrides [main] environment variables
[[ -f .env ]] && . .env

## other
readonly SG_DOCKER_NETWORK="sg-net"

# configure diagnostics environment
readonly SG_DIAGNOSTIC_FILE="/tmp/diagnostic.json"
readonly SG_DIAGNOSTIC_TMP_FILE="/tmp/diagnostic.json.tmp"

if [[ ! -e "$SG_DIAGNOSTIC_FILE" ]]; then
  touch "$SG_DIAGNOSTIC_FILE"
  echo "{}" > "$SG_DIAGNOSTIC_FILE"
fi

## colors for printf
readonly C_RED_BOLD="\033[1;31m"
readonly C_RED="\033[0;31m"
readonly C_GREEN_BOLD="\033[1;32m"
readonly C_GREEN="\033[0;32m"
# readonly C_YELLOW_BOLD="\033[1;33m"
# readonly C_YELLOW="\033[0;33m"
# readonly C_BLUE_BOLD="\033[1;34m"
readonly C_BLUE="\033[0;34m"
readonly C_MAGENTA_BOLD="\033[1;35m"
# readonly C_MAGENTA="\033[0;35m"
# readonly C_CYAN_BOLD="\033[1;36m"
# readonly C_CYAN="\033[0;36m"
readonly C_RESET="\033[0m"
readonly C_BOLD="\033[1m"

#}}}: Environment variables

#{{{ Print functions

show_help() { #{{{
  cat <<EOF

main.sh is script for registration of Private Runner Nodes on Stackguardian.

  More information available at: https://docs.qa.stackguardian.io/docs/

Examples:
  # Register new runner
  ./$(basename "$0") register --sg-node-token "some-token" --organization "demo-org" --runner-group "private-runner-group"

  # De-Register new runner
  ./$(basename "$0") deregister --sg-node-token "some-token" --organization "demo-org" --runner-group "private-runner-group"

Available commands:
  register              Register new Private Runner
  deregsiter            Deregister existing Private Runner
  doctor                Show health status of used services/containers

Options:
  --sg-node-token '': (required)
    The runner node token acquired from Stackguardian platform.

  --organization '': (required)
    The organization name on Stackguardian platform.

  --runner-group '': (required)
    The runner group where new runner will be registered.

  --debug
    Print more verbose output during command execution.

  --force, -f
    Execute some commands with force. Skip some sections in case of errors.

Usage:
  ./$(basename "$0") <command> [options]
EOF
}
#}}}: show_help

log_date() { #{{{
  printf "${C_BLUE}[%s]" "$(date +'%Y-%m-%dT%H:%M:%S%z')"
}
#}}}: log_date

err() { #{{{
  printf "%s ${C_RED_BOLD}[ERROR] ${C_RESET}%s${C_BOLD} %s${C_RESET} %s\n" "$(log_date)" "${1}" "${2}" "${@:3}" >&2
}
#}}}: err

info() { #{{{
  printf "%s ${C_GREEN_BOLD}[INFO]${C_RESET} %s${C_BOLD} %s${C_RESET} %s\n" "$(log_date)" "${1}" "${2}" "${@:3}"
}
#}}}: info

debug() { #{{{
  [[ "$LOG_DEBUG" =~ true|True ]] && \
    printf "%s ${C_MAGENTA_BOLD}[DEBUG]${C_RESET} %s${C_BOLD} %s${C_RESET} %s\n" "$(log_date)" "${1}" "${2}" "${@:3}"
}
#}}}: debug

exit_help() { #{{{
  exit_code=$?
  (( "$exit_code" != 0 )) && \
    printf "\n(Try ${C_BOLD}%s --help${C_RESET} for more information.)\n" "$(basename "${0}")"
}
#}}}: exit_help

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
doctor_frame() { #{{{
  printf " + %s " "${1}"
  printf "\n |"
  printf "%s" "$2"
  # printf "\n |\n"
  printf "\n"
}
#}}}: doctor_frame

#######################################
# Print details at the end of registration
# Globals:
#   ORGANIZATION_NAME
#   RUNNER_GROUP_ID
#   RUNNER_ID
# Arguments:
#   None
# Outputs:
#   Write to STDOUT
#######################################
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
  details_item "Organization" "${ORGANIZATION_NAME}"
  details_item "Runner Group" "${RUNNER_GROUP_ID}"
  details_item "Runner ID" "${RUNNER_ID}"
  echo
}
#}}}: print_details

#}}}: Print functions

#{{{ Other functions

cleanup() { #{{{
  echo "Gracefull shutdown.."
  [[ -n ${spinner_pid} ]] && kill "${spinner_pid}" >&/dev/null
  exit 0
}
#}}}: cleanup

force_exec() { #{{{
  [[ "$FORCE_PASS" == true ]] && return 0
  return 1
}
#}}}: force_exec

spinner() { #{{{
    local spinner_pid=$1
    local log_file="$LOG_FILE"
    local delay=0.15
    local spinstr='|/-\'
    if [[ "${LOG_DEBUG}" == "false" ]]; then
      while ps a | awk '{print $1}' | grep "${spinner_pid}" >&/dev/null; do
          local temp=${spinstr#?}
          printf " [%c] " "$spinstr"
          local spinstr=$temp${spinstr%"$temp"}
          sleep $delay
          printf "\b\b\b\b\b\b"
      done
    else
      tail -n0 -f "${log_file}" --pid "${spinner_pid}"
    fi
    wait "${spinner_pid}"
    printf "    \b\b\b\b"
}
#}}}: spinner

clean_local_setup() { #{{{
  info "Starting cleanup.."

  debug "Stopping services.."
  systemctl stop ecs 2>/dev/null
  debug "Stopping $CONTAINER_ORCHESTRATOR containers.."
  $CONTAINER_ORCHESTRATOR stop ecs-agent fluentbit-agent >&/dev/null
  debug "Removing $CONTAINER_ORCHESTRATOR containers.."
  $CONTAINER_ORCHESTRATOR rm ecs-agent fluentbit-agent >&/dev/null
  debug "Removing $CONTAINER_ORCHESTRATOR network: ${SG_DOCKER_NETWORK}.."
  $CONTAINER_ORCHESTRATOR network rm "${SG_DOCKER_NETWORK}" >&/dev/nul
  debug "Removing local configuration.."
  rm -rf /var/log/ecs /etc/ecs /var/lib/ecs ./fluent-bit.conf volumes/ ./aws-credentials ./db-state ./ssm-binaries >&/dev/null
}
#}}}: clean_local_setup

#}}}: Other functions

#{{{ Local data functions

#######################################
# Configure local directories and files.
# Globals:
#   ECS_CLUSTER
#   AWS_DEFAULT_REGION
#   ORGANIZATION_ID
#   RUNNER_ID
#   RUNNER_GROUP_ID
# Arguments:
#   None
# Outputs:
#   Writes STDOUT on success.
#######################################
configure_local_data() { #{{{
  mkdir -p /var/log/ecs /etc/ecs /var/lib/ecs/data /etc/fluentbit/
  rm -rf /etc/ecs/ecs.config /var/lib/ecs/ecs.config > /dev/null

  info "Configuring local data.."

  cat > /etc/ecs/ecs.config << EOF
ECS_CLUSTER=${ECS_CLUSTER}
AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}
ECS_INSTANCE_ATTRIBUTES={"sg_organization": "${ORGANIZATION_NAME}","sg_runner_id": "${RUNNER_ID}", "sg_runner_group_id": "${RUNNER_GROUP_ID}"}
ECS_LOGLEVEL=/log/ecs-agent.log
ECS_DATADIR=/data/
ECS_ENABLE_TASK_IAM_ROLE=true
ECS_ENABLE_TASK_IAM_ROLE_NETWORK_HOST=true
EOF

  cat > /var/lib/ecs/ecs.config << EOF
AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}
ECS_EXTERNAL=true
EOF

#Fluentbit configuration for aws_s3 output
if [[ "${STORAGE_BACKEND_TYPE}" == "azure_blob_storage" ]]; then
  cat > ./fluent-bit.conf << EOF
[SERVICE]
    Flush         1
    Log_Level     info
    Buffer_Chunk_size 1M
    Buffer_Max_Size 6M
    HTTP_Server On
    HTTP_Listen 0.0.0.0
    HTTP_PORT 2020
    Health_Check On
    HC_Errors_Count 5
    HC_Period 5
[INPUT]
    Name forward
    Listen 0.0.0.0
    port 24224
[INPUT]
    Name tail
    Tag ecsagent
    path /var/lib/docker/containers/*/*-json.log
    DB /var/log/flb_docker.db
    Mem_Buf_Limit 50MB
[OUTPUT]
    Name  azure_blob
    Match  fluentbit
    account_name ${STORAGE_ACCOUNT_NAME}
    shared_key ${SHARED_KEY}
    blob_type blockblob
    path fluentbit/log
    container_name system
    auto_create_container on
    tls on

[OUTPUT]
    Name  azure_blob
    Match  ecsagent
    account_name ${STORAGE_ACCOUNT_NAME}
    shared_key ${SHARED_KEY}
    blob_type blockblob
    path ecsagent/log
    container_name system
    auto_create_container on
    tls on

[OUTPUT]
    Name  azure_blob
    Match_Regex orgs**
    account_name ${STORAGE_ACCOUNT_NAME}
    shared_key ${SHARED_KEY}
    container_name runner
    auto_create_container on
    tls on
EOF
fi

#Fluentbit configuration for aws_s3 output
if [[ "${STORAGE_BACKEND_TYPE}" == "aws_s3" ]]; then
  cat > ./fluent-bit.conf << EOF
[SERVICE]
    Flush         1
    Log_Level     info
    Buffer_Chunk_size 1M
    Buffer_Max_Size 6M
    HTTP_Server On
    HTTP_Listen 0.0.0.0
    HTTP_PORT 2020
    Health_Check On
    HC_Errors_Count 5
    HC_Retry_Failure_Count 5
    HC_Period 5

[INPUT]
    Name forward
    Listen 0.0.0.0
    port 24224

[INPUT]
    Name tail
    Tag ecsagent
    path /var/lib/docker/containers/*/*-json.log
    DB /var/log/flb_docker.db
    Mem_Buf_Limit 50MB

[OUTPUT]
    Name s3
    Match fluentbit
    region              ${S3_AWS_REGION}
    upload_timeout      5s
    store_dir_limit_size 2G
    total_file_size 250M
    retry_limit 20
    use_put_object  On
    compression gzip
    bucket              ${S3_BUCKET_NAME}
    s3_key_format /system/fluentbit/fluentbit

[OUTPUT]
    Name s3
    Match ecsagent
    region              ${S3_AWS_REGION}
    upload_timeout      5s
    store_dir_limit_size 2G
    total_file_size 250M
    retry_limit 20
    use_put_object  On
    compression gzip
    bucket              ${S3_BUCKET_NAME}
    s3_key_format /system/ecsagent/ecsagent

[OUTPUT]
    Name s3
    Match_Regex orgs**
    region              ${S3_AWS_REGION}
    upload_timeout      5s
    use_put_object  On
    store_dir_limit_size 2G
    total_file_size 250M
    retry_limit 20
    compression gzip
    bucket              ${S3_BUCKET_NAME}
    s3_key_format /\$TAG/logs/log
EOF

  cat > ./aws-credentials << EOF
[default]
region = ${S3_AWS_REGION}
aws_access_key_id = ${S3_AWS_ACCESS_KEY_ID}
aws_secret_access_key = ${S3_AWS_SECRET_ACCESS_KEY}
EOF

fi
}
#}}}: configure_local_data

#######################################
# Configure local network.
# Globals:
#   SG_DOCKER_NETWORK
# Arguments:
#   None
# Outputs:
#   Writes STDOUT on success.
#######################################
configure_local_network() { #{{{
  info "Configuring local network.."

  # Create SG_DOCKER_NETWORK $CONTAINER_ORCHESTRATOR network
  $CONTAINER_ORCHESTRATOR network create --driver bridge "${SG_DOCKER_NETWORK}" >&/dev/null
  bridge_id="br-$($CONTAINER_ORCHESTRATOR network ls -q --filter "name=${SG_DOCKER_NETWORK}")"
  iptables \
    -I DOCKER-USER \
    -i "${bridge_id}" \
    -d 169.254.169.254,10.0.0.0/24 \
    -j DROP

  info "$CONTAINER_ORCHESTRATOR network ${SG_DOCKER_NETWORK} created."

  # Set up necessary rules to enable IAM roles for tasks
  sysctl -w net.ipv4.conf.all.route_localnet=1 >/dev/null
  sysctl -w net.ipv4.ip_forward=1 >/dev/null

  iptables \
    -t nat \
    -A PREROUTING \
    -p tcp \
    -d 169.254.170.2 \
    --dport 80 \
    -j DNAT \
    --to-destination 127.0.0.1:51679

  iptables \
    -t nat \
    -A OUTPUT \
    -d 169.254.170.2 \
    -p tcp \
    -m tcp \
    --dport 80 \
    -j REDIRECT \
    --to-ports 51679

}
#}}}: configure_local_network

#}}}: Local data functions

#{{{ Services

#######################################
# Check fluentbit errors for storage.
# If errors, print and exit.
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   None
# Outputs:
#   Write to STDOUT/STDERR
#   if successfull/error.
#######################################
check_fluentbit_status() { #{{{
  info "Starting fluentbit status check.."

  local container_id
  local log_file

  until [[ -n "$container_id" ]]; do
    container_id="$($CONTAINER_ORCHESTRATOR ps -q --filter "name=fluentbit-agent")"
  done
  debug "Fluentbit container id:" "$container_id"

  until [[ -n "$log_file" ]]; do
    log_file="$(echo /var/lib/docker/containers/"$container_id"*/*.log)"
    [[ ! -e $log_file ]] && unset log_file
  done
  debug "Fluentbit log file:" "$log_file"

  info "Waiting for fluentbit logs.."
  until (( $(grep -ia -A2 "stream processor started" "$log_file" | wc -l)>=2 )); do
    sleep 1
  done & spinner "$!"
  printf "    \b\b\b\b"

  if [[ "$STORAGE_BACKEND_TYPE" == "aws_s3" ]]; then
    debug "Checking" "AWS S3" "errors"
    err_msg="$(grep -aio -E "error='.*'" "$log_file" \
      | grep -io -m1 -E "message='.*'" \
      | grep -io -E "'.*'" | tr -d "'\0")"
  elif [[ "$STORAGE_BACKEND_TYPE" == "azure_blob_storage" ]]; then
    debug "Checking" "Azure Blob" "errors"
    err_msg="$(grep -aio -m1 -E "\[error.*" "$log_file" \
      | cut -d" " -f3- | tr -d '\0')"
  fi

  if [[ -n "$err_msg" ]]; then
    err "Fluentbit failed to start:" "$err_msg"
    clean_local_setup &
    spinner "$!"
    info "Cleanup finished."
    exit 1
  fi

  info "Fluentbit status:" "healthy"
}
#}}}: check_fluentbit_status

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
check_systemctl_status() { #{{{
  if ! systemctl is-active "$1" >&/dev/null; then
    debug "Reloading/Restarting neccessary services.."
    if ! systemctl reload-or-restart "$1" 2>/dev/null; then
      return 2
    fi
    return 0
  else
    return 0
  fi
}
#}}}: check_systemctl_status

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
check_systemctl_ecs_status() { #{{{
  systemctl status ecs --no-pager >&/dev/null
  if [[ "$?" =~ 4|0 ]]; then
    return 0
  else
    check_systemctl_status "ecs"
  fi
}
#}}}: check_systemctl_status

#######################################
# Check if container orchestartor exists
# and if it is healthy and running.
# Globals:
#   None
# Arguments:
#   Container Orchestrator Command
# Returns:
#   None
# Outputs:
#   Write to STDOUT/STERR
#   if successfull/error.
#######################################
check_container_orchestrator() { #{{{
  if type "$1" >&/dev/null; then
    check_systemctl_status "$1"
    return $?
  else
    return 1
  fi
}
#}}}: check_container_orchestrator

#######################################
# Enable/Disable cgroupsv2 (Preview)
# Globals:
#   None
# Arguments:
#   enable/disable
# Returns:
#   None
# Outputs:
#   Write to STDOUT/STERR
#   if successfull/error.
#######################################
cgroupsv2() { #{{{
  local cgroup_toggle
  [[ "$1" == "enable" ]] &&
    cgroup_toggle=1 || cgroup_toggle=0

  if (( cgroup_toggle==0 )); then
    info "Switching to" "cgroupsv1"
  else
    info "Swithcing to" "cgroupsv2"
  fi

  if type grubby >&/dev/null; then
    grubby --update-kernel=ALL --args="systemd.unified_cgroup_hierarchy=$cgroup_toggle"
  else
    grub_cmdline="$(grep "GRUB_CMDLINE_LINUX=.*" /etc/default/grub | grep -o '".*"' | tr -d '"')"
    debug "GRUB_CMDLINE_LINUX" "$grub_cmdline"
    if [[ -n "$grub_cmdline" ]]; then
      pattern="(systemd.unified_cgroup_hierarchy)=(.*)"
      if [[ $grub_cmdline =~ $pattern ]]; then
        grub_cmdline="$(echo "$grub_cmdline" \
          | sed "s/(systemd.unified_cgroup_hierarchy)=(.*)/\1=$cgroup_toggle/")"
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

  info "Reboot required. Continue.."
  read -r
  reboot
  info "Rebooting.."
  exit 0
} #}}}

api_call() { #{{{
  response=$(curl -i -s \
    -X POST \
    -H "Authorization: apikey ${SG_NODE_TOKEN}" \
    -H "Content-Type: application/json" \
    "${url}")

  if [[ -z "$response" ]]; then
    exit 1
  else
    full_response="$response"
  fi

  debug "Response:" \
    && echo "${response}"

  # get first status code from response
  status_code="$(echo "$response" \
    | awk '/^HTTP/ {print $2}')"

  # actual response data
  response="$(echo "$response" \
    | awk '/^Response/ {print $2}')"
  [[ -z "$response" ]] && \
  response="$(echo "$full_response" | sed -n '/^{.*/,$p' | tr '\n' ' ')"

  # msg from data
  message="$(echo "$response" \
    | jq -r '.msg // .message //  "Unknown error"')"

  if [[ -z "$status_code" ]]; then
    err "Unknown status code."
    exit 1
  elif [ "$status_code" != "200" ] && [ "$status_code" != "201" ] && [ "$status_code" != "100" ]; then
    return 1
  else
    return 0
  fi
}
#}}}: cgroupsv2

#}}}: Services

#######################################
# Fetch necessary info from API.
# Globals:
#   SG_NODE_TOKEN
#   ORGANIZATION_ID
#   RUNNER_GROUP_ID
# Arguments:
#   None
# Outputs:
#   Write to STDERR if error and exit.
#   Set all neccessary environment variables.
#######################################
fetch_organization_info() { #{{{
  local url
  local metadata

  info "Trying to fetch registration data.."
  url="${SG_BASE_API}/orgs/${ORGANIZATION_ID}/runnergroups/${RUNNER_GROUP_ID}/register/"

  debug "Calling URL:" "${url}"

  if api_call; then
    info "Success. Preparing environment.."
    metadata="$(echo "${response}" | jq -r '.data.RegistrationMetadata[0]')"
    [[ "$metadata" == "null" || -z "$metadata" ]] && \
      err "API data missing registration metadata." && exit 1
  else
    err "Could not fetch data from API. >>" "$message $status_code" "<<"
    exit 1
  fi

  ## API response values (Registration Metadata)
  ECS_CLUSTER="${ECS_CLUSTER:=$(echo "${metadata}" | jq -r '.ECSCluster')}"
  AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:=$(echo "${metadata}" | jq -r '.AWSDefaultRegion')}"
  SSM_ACTIVATION_ID="${SSM_ACTIVATION_ID:=$(echo "${metadata}" | jq -r '.SSMActivationId')}"
  SSM_ACTIVATION_CODE="${SSM_ACTIVATION_CODE:=$(echo "${metadata}" | jq -r '.SSMActivationCode')}"

  debug "ECS_CLUSTER:" "${ECS_CLUSTER}"
  debug "AWS_DEFAULT_REGION:" "${AWS_DEFAULT_REGION}"
  debug "SSM_ACTIVATION_ID:" "${SSM_ACTIVATION_ID:0:5}*****"
  debug "SSM_ACTIVATION_CODE:" "${SSM_ACTIVATION_CODE:0:5}*****"

  ## Everything else
  ORGANIZATION_NAME="${ORGANIZATION_NAME:=$(echo "${response}" | jq -r '.data.OrgName')}"
  ORGANIZATION_ID="${ORGANIZATION_ID:=$(echo "${response}" | jq -r '.data.OrgId')}"
  RUNNER_ID="${RUNNER_ID:=$(echo "${response}" | jq -r '.data.RunnerId')}"
  RUNNER_GROUP_ID="${RUNNER_GROUP_ID:=$(echo "${response}" | jq -r '.data.RunnerGroupId')}"
  TAGS="${TAGS:=$(echo "${response}" | jq -r '.data.Tags')}"
  STORAGE_ACCOUNT_NAME="${STORAGE_ACCOUNT_NAME:=$(echo "${response}" | jq -r '.data.RunnerGroup.StorageBackendConfig.azureBlobStorageAccountName')}"
  SHARED_KEY="${SHARED_KEY=$(echo "${response}" | jq -r '.data.RunnerGroup.StorageBackendConfig.azureBlobStorageAccessKey')}"
  STORAGE_BACKEND_TYPE="${STORAGE_BACKEND_TYPE:=$(echo "${response}" | jq -r '.data.RunnerGroup.StorageBackendConfig.type')}"
  S3_BUCKET_NAME="${S3_BUCKET_NAME:=$(echo "${response}" | jq -r '.data.RunnerGroup.StorageBackendConfig.s3BucketName')}"
  S3_AWS_REGION="${S3_AWS_REGION:=$(echo "${response}" | jq -r '.data.RunnerGroup.StorageBackendConfig.awsRegion')}"
  S3_AWS_ACCESS_KEY_ID="${S3_AWS_ACCESS_KEY_ID:=$(echo "${response}" | jq -r '.data.RunnerGroup.StorageBackendConfig.auth.config[0].awsAccessKeyId')}"
  S3_AWS_SECRET_ACCESS_KEY="${S3_AWS_SECRET_ACCESS_KEY:=$(echo "${response}" | jq -r '.data.RunnerGroup.StorageBackendConfig.auth.config[0].awsSecretAccessKey')}"

  debug "ORGANIZATION_NAME:" "${ORGANIZATION_NAME}"
  debug "ORGANIZATION_ID:" "${ORGANIZATION_ID}"
  debug "RUNNER_ID:" "${RUNNER_ID}"
  debug "RUNNER_GROUP_ID:" "${RUNNER_GROUP_ID}"
  debug "SHARED_KEY:" "${SHARED_KEY}"
  debug "STORAGE_ACCOUNT_NAME:" "${STORAGE_ACCOUNT_NAME}"
  debug "STORAGE_BACKEND_TYPE:" "${STORAGE_BACKEND_TYPE}"
  debug "S3_BUCKET_NAME:" "${S3_BUCKET_NAME}"
  debug "S3_AWS_REGION:" "${S3_AWS_REGION}"
  debug "S3_AWS_ACCESS_KEY_ID:" "${S3_AWS_ACCESS_KEY_ID}"
  debug "S3_AWS_SECRET_ACCESS_KEY:" "${S3_AWS_SECRET_ACCESS_KEY:0:5}*****"
}
#}}}: fetch_organization_info

#######################################
# Run fluentbit $CONTAINER_ORCHESTRATOR container for logging
# Globals:
#
# Arguments:
#   AWS_ACCESS_KEY_ID
#   AWS_SECRET_ACCESS_KEY
# Outputs:
#   Write to STDOUT/STERR
#   if successfull/error.
#######################################
# This portion checks whether the STORAGE_BACKEND_TYPE is
# aws_s3 or azure_blob and runs the container accordingly.
########################################
configure_fluentbit() { #{{{
  local running
  local exists
  local image

  image="$($CONTAINER_ORCHESTRATOR images -q -f reference="$FLUENTBIT_IMAGE")"
  if [[ -z "$image" ]]; then
    info "Pulling fluentbit image:" "$FLUENTBIT_IMAGE"
    $CONTAINER_ORCHESTRATOR pull "$FLUENTBIT_IMAGE" >> "$LOG_FILE" 2>&1 &
    spinner "$!"
  fi

  info "Starting fluentbit agent.."
  docker_run_command="$CONTAINER_ORCHESTRATOR run -d \
      --name fluentbit-agent \
      --restart=always \
      -p 24224:24224 \
      -p 2020:2020 \
      --network bridge \
      -v /var/lib/docker/containers:/var/lib/docker/containers:ro \
      -v $(pwd)/volumes/db-state/:/var/log/ \
      -v $(pwd)/fluent-bit.conf:/fluent-bit/etc/fluentbit.conf \
      --log-driver=fluentd \
      --log-opt tag=fluentbit
       "
  running=$($CONTAINER_ORCHESTRATOR ps -q --filter "name=fluentbit-agent")
  exists=$($CONTAINER_ORCHESTRATOR ps -aq --filter "name=fluentbit-agent")

  if [[ -z "${exists}" ]]; then
    if [[ "${STORAGE_BACKEND_TYPE}" == "azure_blob_storage" ]]; then
      extra_options="$FLUENTBIT_IMAGE \
        /fluent-bit/bin/fluent-bit -c /fluent-bit/etc/fluentbit.conf"
      $docker_run_command $extra_options >> "$LOG_FILE" 2>&1
    elif [[ "${STORAGE_BACKEND_TYPE}" == "aws_s3" ]]; then
      extra_options="-v $(pwd)/aws-credentials:$HOME/.aws/credentials \
        $FLUENTBIT_IMAGE \
        /fluent-bit/bin/fluent-bit -c /fluent-bit/etc/fluentbit.conf"
      $docker_run_command $extra_options >> "$LOG_FILE" 2>&1
    fi
    info "Registered fluentbit agent."
    else
      if [[ -z "${running}" ]]; then
        $CONTAINER_ORCHESTRATOR start fluentbit-agent >&/dev/null
        info "Started fluentbit agent."
      else
        info "Fluentbit agent already running."
    fi
  fi
  check_fluentbit_status
}
#}}}: configure_fluentbit

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
register_instance() { #{{{
  local registered
  registered=$($CONTAINER_ORCHESTRATOR ps -q --filter "name=ecs-agent")

  if [[ -n "${registered}" ]]; then
    debug "Instance ecs-agent status:" "${registered}"
    info "Instance agent already registered and running."
    configure_local_network
    configure_fluentbit
    print_details
    exit 0
  fi

  fetch_organization_info
  configure_local_data
  configure_fluentbit

  if [[ ! -e /tmp/ecs-anywhere-install.sh ]]; then
    info "Downloading support files.."

    if ! curl -fSsLk \
      --proto "https" \
      -o "/tmp/ecs-anywhere-install.sh" \
      "https://amazon-ecs-agent.s3.amazonaws.com/ecs-anywhere-install-latest.sh" \
      >> "$LOG_FILE" 2>&1; then
      debug "Response:" "$(cat $LOG_FILE)"
      err "Unable to download" "ecs-anywhere-install.sh" "script"
      exit 1
    else
      info "Download completed. Continuing.."
    fi
  else
    info "Skiping support files download.."
  fi

  info "Trying to register instance.."

  check_systemctl_ecs_status

  [[ ! -e "$LOG_FILE" ]] \
    && touch "$LOG_FILE"

  if ! /bin/bash /tmp/ecs-anywhere-install.sh \
      --region "${AWS_DEFAULT_REGION}" \
      --cluster "${ECS_CLUSTER}" \
      --activation-id "${SSM_ACTIVATION_ID}" \
      --activation-code "${SSM_ACTIVATION_CODE}" \
      --docker-install-source none \
      >> "$LOG_FILE" 2>&1 & spinner "$!"; then
    container_status="$($CONTAINER_ORCHESTRATOR ps -a --filter='name=ecs-agent' --format '{{.Status}}')"
    container_id="$($CONTAINER_ORCHESTRATOR ps -aq --filter 'name=ecs-agent')"
    if [[ "$?" != 0 || "$container_status" =~ Exited ]]; then
      err "Failed to register external instance."
      grep Error /var/lib/docker/containers/"$container_id"*/*-json.log
      exit 1
    else
      info "Instance successfully registered to Stackguardian platform."
    fi
  else
    err "Failed to register external instance."
    exit 1
  fi

  configure_local_network
  setup_cron
  print_details
}
#}}}: register_instance

#######################################
# Make API call for de-registering.
# Globals:
#   SG_BASE_API
#   SG_NODE_TOKEN
# Arguments:
#   None
# Outputs:
#   Writes to STDOUT/STDERR
#   if de-registration is sucessfull.
#######################################
deregister_instance() { #{{{
  local url

  if [[ -e /etc/ecs/ecs.config ]]; then
    RUNNER_ID="$(grep ECS_INSTANCE_ATTRIBUTES /etc/ecs/ecs.config \
      | cut -d "=" -f2 \
      | jq -r '.sg_runner_id')"
  else
    err "Local data could not be found:" "/etc/ecs/ecs.config"
    force_exec && clean_local_setup
    exit 1
  fi

  url="${SG_BASE_API}/orgs/${ORGANIZATION_ID}/runnergroups/${RUNNER_GROUP_ID}/deregister/"

  debug "Calling URL:" "${url}"

  payload="{ \"RunnerId\": \"${RUNNER_ID}\" }"

  debug "Payload:" "${payload}"

  info "Trying to deregsiter instance.."
  if api_call & spinner "$!"; then
    info "Instance deregistered. Removing local data.."
    clean_local_setup
  else
    err "Could not fetch data from API. >>" "$message - $status_code" "<<"
    force_exec && clean_local_setup
  fi

  info "Instance successfully deregisterd."
}
#}}}: deregister_instance

doctor() { #{{{
  info "Checking services health status.."
  echo

  jq ".system.last_check = \"$(date)\"" "$SG_DIAGNOSTIC_FILE" >> "$SG_DIAGNOSTIC_TMP_FILE"
  mv "$SG_DIAGNOSTIC_TMP_FILE" "$SG_DIAGNOSTIC_FILE"

  local status_list=""
  local service_status
  local service_list=( "ecs" "docker" )

  for service in "${service_list[@]}"; do
    service_status="$(systemctl is-active "${service}")"
    jq ".health.service.${service} = \"$service_status\"" $SG_DIAGNOSTIC_FILE > $SG_DIAGNOSTIC_TMP_FILE
    mv $SG_DIAGNOSTIC_TMP_FILE $SG_DIAGNOSTIC_FILE
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
    jq ".health.service.$CONTAINER_ORCHESTRATOR = \"$service_status\"" "$SG_DIAGNOSTIC_FILE" > "$SG_DIAGNOSTIC_TMP_FILE"
    mv "$SG_DIAGNOSTIC_TMP_FILE" "$SG_DIAGNOSTIC_FILE"
    printf " + Container Status (${C_BOLD}$CONTAINER_ORCHESTRATOR ${C_RESET}service: ${C_RED}%s${C_RESET})\n\n" "${service_status}"
    return
  fi

  status_list=""
  local containers=( "ecs" "fluentbit" )

  for container in "${containers[@]}"; do
    local container_status
    container_status="$($CONTAINER_ORCHESTRATOR ps \
      --filter "name=${container}-agent" \
      --format '{{.Status}}'\
      )"
    if [[ -z ${container_status} ]]; then
      jq ".health.container.$container = \"Not Running\"" $SG_DIAGNOSTIC_FILE > $SG_DIAGNOSTIC_TMP_FILE
      mv $SG_DIAGNOSTIC_TMP_FILE $SG_DIAGNOSTIC_FILE
      status_list="$(printf "%s\n%s" \
        "${status_list}" \
        "$(printf " | * ${C_BOLD}%s${C_RESET} agent: ${C_RED}Not Running${C_RESET}\n" "${container}")")"
    else
      jq ".health.container.$container = \"$container_status\"" $SG_DIAGNOSTIC_FILE > $SG_DIAGNOSTIC_TMP_FILE
      mv $SG_DIAGNOSTIC_TMP_FILE $SG_DIAGNOSTIC_FILE
      status_list="$(printf "%s\n%s" \
        "${status_list}" \
        "$(printf " | * ${C_BOLD}%s${C_RESET} agent: ${C_GREEN}%s${C_RESET}\n" "${container}" "${container_status}")")"
    fi
  done
  doctor_frame "Container Status" "${status_list}"

  echo
  info "Services health status generated."
}
#}}}: doctor

prune() { #{{{
  local reclaimed

  info "Cleaning up system.."

  reclaimed=$($CONTAINER_ORCHESTRATOR system prune -f \
    --filter "until=240h" \
    | cut -d: -f2 | tr -d ' ')

  jq ".system.docker.last_prune = \"$(date)\"" "$SG_DIAGNOSTIC_FILE" >> "$SG_DIAGNOSTIC_TMP_FILE"
  mv "$SG_DIAGNOSTIC_TMP_FILE" "$SG_DIAGNOSTIC_FILE"
  jq ".system.docker.reclaimed = \"$reclaimed\"" "$SG_DIAGNOSTIC_FILE" >> "$SG_DIAGNOSTIC_TMP_FILE"
  mv "$SG_DIAGNOSTIC_TMP_FILE" "$SG_DIAGNOSTIC_FILE"

  info "System cleaned. Reclimed:" "$reclaimed"
}
#}}}: prune

#{{{ Argument/init checks

check_arg_value() { #{{{
  ## TODO(adis.halilovic@stackguardian.io): make sure to validate double parameter input
  if [[ "${2:0:2}" == "--" ]]; then
    err "Argument" "${1}" "has invalid value: $2"
    exit 1
  elif [[ -z "${2}" ]]; then
    err "Argument" "${1}" "can't be empty"
    exit 1
  fi
  return 0
}
#}}}: check_arg_value

is_root() { #{{{
  if (( $(id -u) != 0 )); then
    err "This script must be run as" "root"
    exit 1
  fi
  return 0
}
#}}}: is_root

init_args_are_valid() { #{{{
  if [[ ! "$1" =~ ^register$|^deregister$|^doctor$|^prune$|^cgroupsv2$ ]]; then
    err "Provided option" "${1}" "is invalid"
    exit 1
  elif [[ "$1" == "cgroupsv2" && ! "$2" =~ ^enable$|^disable$ ]]; then
    err "Arguments:" "enable, disable" "are required."
    exit 1
  elif [[ "$1" =~ register|deregister && \
    ( ! "$*" =~ --sg-node-token || \
    ! "$*" =~ --organization || \
    ! "$*" =~ --runner-group ) ]]; then
    err "Arguments:" "--sg-node-token, --organization, --runner-group" "are required"
    exit 1
  fi
  return 0
}
#}}}: init_args_are_valid

check_sg_args() { #{{{
  if [[ -z "${SG_NODE_TOKEN}" \
    || -z "${ORGANIZATION_ID}" \
    || -z "${RUNNER_GROUP_ID}" ]]; then
    err "Arguments: " "--sg-node-token, --organization, --runner-group" "are required"
    exit 1
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
    -f | --force)
      FORCE_PASS=true
      shift
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
}
#}}}: parse_arguments

#######################################
# Run fluentbit $CONTAINER_ORCHESTRATOR container for logging
# Globals:
#
# Arguments:
#   AWS_ACCESS_KEY_ID
#   AWS_SECRET_ACCESS_KEY
# Outputs:
#   Write to STDOUT/STERR
#   if successfull/error.
#######################################
# This portion checks whether the STORAGE_BACKEND_TYPE is
# aws_s3 or azure_blob and runs the container accordingly.
########################################
setup_cron() { #{{{
  local temp_file

  temp_file=$(mktemp)
  crontab -l > "$temp_file" || echo "" > "$temp_file"

  if ! grep -qi -E "doctor|prune" "$temp_file"; then
    {
      echo "* * * * * /bin/bash $PWD/main.sh doctor";
      echo "0 0 * * * /bin/bash $PWD/main.sh prune"
    } >> "$temp_file"
  fi
  /usr/bin/crontab "$temp_file"
  doctor
}
#}}}:setup_cron

#}}}: Argument/init checks

main() { #{{{

  [[ "${*}" =~ --help || $# -lt 1 ]] && show_help && exit 0

  is_root && init_args_are_valid "$@"

  if ! pidof systemd >&/dev/null; then
    err "Private runner only available for" "systemd-based" "systems"
  fi

  if [[ "$CGROUPSV2_PREVIEW" == true ]]; then
    if [[ "$1" == "cgroupsv2" && "$2" =~ enable|disable ]]; then
      parse_arguments "${@:3}"
      cgroupsv2 "$2"
    elif [[ -e /sys/fs/cgroup/cgroup.controllers ]] &&
      [[ "$(grep "^GRUB_CMDLINE_LINUX=\".*systemd.unified_cgroup_hierarchy=0\"" /etc/default/grub)" == "" ]]; then
      err "Private runner does not support" "cgroupsv2"
      exit 1
    fi
  else
    err "Preview off: private runner does not support" "cgroupsv2"
    exit 1
  fi

  for cmd in "${COMMANDS[@]}"; do
    if ! type "$cmd" >&/dev/null; then
      err "Command" "$cmd" "not installed"
      exit 1
    fi
  done

  for container_orchestrator in "${CONTAINER_ORCHESTRATORS[@]}"; do
    if check_container_orchestrator "$container_orchestrator"; then
      info "Default container orchesrator:" "$container_orchestrator"
      if [[ "$container_orchestrator" == "podman" ]]; then
        info "Container orchestartor not supported. Aborting.."
        exit 0
      fi
      CONTAINER_ORCHESTRATOR="$container_orchestrator"
      break
    else
      info "Container orchestrator" "$container_orchestrator" "not found. Trying next.."
    fi
  done

  if [[ -z $CONTAINER_ORCHESTRATOR ]]; then
    err "One of following container orchestrators required:" "${CONTAINER_ORCHESTRATORS[@]}"
    exit 1
  fi

  case "${1}" in
    register)
      shift
      parse_arguments "$@"
      check_sg_args
      register_instance
      ;;
    deregister)
      shift
      parse_arguments "$@"
      check_sg_args
      deregister_instance
      ;;
    prune)
      prune
      exit 0
      ;;
    doctor)
      doctor
      exit 0
      ;;
    disable-cgroupsv2)
      cgroupsv2 0
      ;;
    enable-cgroupsv2)
      cgroupsv2 1
      ;;
  esac

  # TODO: API call to ping the node

}
#}}}: main

trap cleanup SIGINT
trap exit_help EXIT

main "$@"

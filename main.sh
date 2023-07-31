#!/bin/bash
#
# Register external instance to Stackguardian platform.

set -o pipefail

# Environment variables
SG_NODE_API_ENDPOINT="https://api.app.stackguardian.io/api/v1"
LOG_DEBUG=${LOG_DEBUG:=false}
SG_DOCKER_NETWORK="sg-net"

DIAGNOSTIC_FILE="/tmp/diagnostic.json"
TMP_FILE="/tmp/diagnostic.json.tmp"

if [[ ! -e "$DIAGNOSTIC_FILE" ]]; then
  touch "$DIAGNOSTIC_FILE"
  echo "{}" > "$DIAGNOSTIC_FILE"
fi

# Source .env if exists (testing purposes)
[[ -f .env ]] && . .env

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

log_date() { #{{{
  printf "${C_BLUE}[%s]" "$(date +'%Y-%m-%dT%H:%M:%S%z')"
}
#}}}

cleanup() { #{{{
  echo "Gracefull shutdown.."
  [[ -n ${spinner_pid} ]] && kill "${spinner_pid}" >&/dev/null
  exit 0
}
#}}}

force_exec() { #{{{
  [[ "$FORCE_PASS" == true ]] && return 0
  return 1
}
#}}}

err() { #{{{
  printf "%s ${C_RED_BOLD}[ERROR] ${C_RESET}%s${C_BOLD} %s${C_RESET} %s\n" "$(log_date)" "${1}" "${2}" "${@:3}" >&2
}
#}}}

info() { #{{{
  printf "%s ${C_GREEN_BOLD}[INFO]${C_RESET} %s${C_BOLD} %s${C_RESET} %s\n" "$(log_date)" "${1}" "${2}" "${@:3}"
}
#}}}

debug() { #{{{
  [[ "$LOG_DEBUG" =~ true|True ]] && \
    printf "%s ${C_MAGENTA_BOLD}[DEBUG]${C_RESET} %s${C_BOLD} %s${C_RESET} %s\n" "$(log_date)" "${1}" "${2}" "${@:3}"
}
#}}}

exit_help() { #{{{
  exit_code=$?
  (( "$exit_code" != 0 )) && \
    printf "\n(Try ${C_BOLD}%s --help${C_RESET} for more information.)\n" "$(basename "${0}")"
}
#}}}

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
#}}}

spinner() { #{{{
    spinner_pid=$1
    local log_file="$2"
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
#}}}

clean_local_setup() { #{{{
  info "Stopping services.."
  systemctl stop ecs
  info "Stopping docker containers.."
  docker stop ecs-agent fluentbit-agent >&/dev/null
  info "Removing docker containers.."
  docker rm ecs-agent fluentbit-agent >&/dev/null
  info "Removing docker network: ${SG_DOCKER_NETWORK}.."
  docker network rm "${SG_DOCKER_NETWORK}" >&/dev/nul
  info "Removing local configuration.."
  rm -rf /var/log/ecs /etc/ecs /var/lib/ecs ./fluent-bit.conf volumes/ ./aws-credentials ./db-state ./ssm-binaries >&/dev/null

  info "Local data removed."
}
#}}}

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
#}}}

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
  local metadata
  local url

  info "Trying to fetch registration data.."
  url="${SG_NODE_API_ENDPOINT}/orgs/${ORGANIZATION_ID}/runnergroups/${RUNNER_GROUP_ID}/register/"

  debug "Calling URL:" "${url}"

  if api_call; then
    info "Registration data fetched. Preparing environment.."
  else
    err "Could not fetch data from API. >>" "$message $status_code" "<<"
    exit 1
  fi

  ## API response values (Registration Metadata)
  metadata="$(echo "${response}" | jq -r '.data.RegistrationMetadata[0]')"
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

  info "Environment ready."

}
#}}}

#######################################
# Configure local direcotries and files.
# Globals:
#   ECS_CLUSTER
#   AWS_DEFAULT_REGION
#   ORGANIZATION_ID
#   RUNNER_ID
#   RUNNER_GROUP_ID
# Arguments:
#   None
# Outputs:
#   Writes STOUT on success.
#######################################
configure_local_data() { #{{{
  # Set up directories the agent uses
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

  info "Local data configured."

}
#}}}

#######################################
# Configure local network.
# Globals:
#   None
# Arguments:
#   None
# Outputs:
#   Writes STOUT on success.
#######################################
configure_local_network() { #{{{
  info "Configuring local network.."

  # Create wf-steps-net docker network
  docker network create --driver bridge "${SG_DOCKER_NETWORK}" >&/dev/null
  bridge_id="br-$(docker network ls -q --filter "name=${SG_DOCKER_NETWORK}")"
  iptables \
    -I DOCKER-USER \
    -i "${bridge_id}" \
    -d 169.254.169.254,10.0.0.0/24 \
    -j DROP

  info "Docker network ${SG_DOCKER_NETWORK} created."

  # Set up necessary rules to enable IAM roles for tasks
  sysctl -w net.ipv4.conf.all.route_localnet=1 >/dev/null
  # sysctl -w net.ipv4.ip_forward=1

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

  info "Local network configured."

}
#}}}

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
# This portion checks whether the STORAGE_BACKEND_TYPE is
# aws_s3 or azure_blob and runs the container accordingly.
########################################
configure_fluentbit() { #{{{
  local running
  local exists

  info "Starting fluentbit agent.."
  docker_run_command="docker run -d \
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
  running=$(docker ps -q --filter "name=fluentbit-agent")
  exists=$(docker ps -aq --filter "name=fluentbit-agent")

  if [[ -z "${exists}" ]]; then
    if [[ "${STORAGE_BACKEND_TYPE}" == "azure_blob_storage" ]]; then
      extra_options="fluent/fluent-bit:2.0.9-debug \
        /fluent-bit/bin/fluent-bit -c /fluent-bit/etc/fluentbit.conf"
      $docker_run_command $extra_options >/dev/null

    fi
    if [[ "${STORAGE_BACKEND_TYPE}" == "aws_s3" ]]; then
      extra_options="-v $(pwd)/aws-credentials:$HOME/.aws/credentials \
        fluent/fluent-bit:2.0.9-debug \
        /fluent-bit/bin/fluent-bit -c /fluent-bit/etc/fluentbit.conf"
      $docker_run_command $extra_options >/dev/null
    fi
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
#}}}

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
    info "Reloading/Restarting neccessary services.."
    systemctl reload-or-restart "$1"
    info "Done. Continuing registration.."
    return 0
  else
    return 1
  fi
}
#}}}

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
check_systemcl_ecs_status() { #{{{
  systemctl status ecs --no-pager >&/dev/null
  if [[ "$?" =~ 4|0 ]]; then
    return 0
  else
    check_systemctl_status "ecs"
  fi
}
#}}}

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
check_systemcl_docker_status() { #{{{
  if type docker >&/dev/null; then
    check_systemctl_status "docker"
    return $?
  else
    return 1
  fi
}
#}}}

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
#}}}

details_item() { #{{{
  printf " | * %s: ${C_GREEN_BOLD}%s${C_RESET}\n" "$1" "$2"
}
#}}}

print_details() { #{{{
  echo
  details_frame "Registration Details"
  details_item "Organization" "${ORGANIZATION_NAME}"
  details_item "Runner Group" "${RUNNER_GROUP_ID}"
  details_item "Runner ID" "${RUNNER_ID}"
  echo
}
#}}}

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

  check_systemcl_docker_status && \
    registered=$(docker ps -q --filter "name=ecs-agent")

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

  if [[ ! -e /tmp/ecs-anywhere-install.sh ]]; then
    info "Downloading necessary files.."

    if ! curl -fSsLk \
      --proto "https" \
      -o "/tmp/ecs-anywhere-install.sh" \
      "https://amazon-ecs-agent.s3.amazonaws.com/ecs-anywhere-install-latest.sh" \
      >&/tmp/ecs_anywhere_download.log; then
      debug "Response:" "$(cat /tmp/ecs_anywhere_download.log)"
      err "Unable to download" "ecs-anywhere-install.sh" "script"
      exit 1
    else
      info "Download completed. Continuing.."
    fi
  else
    info "Skiping download. Files already exist."
  fi

  info "Trying to register instance.."

  check_systemcl_docker_status
  check_systemcl_ecs_status

  [[ ! -e /var/log/ecs-install.log ]] \
    && touch /var/log/ecs-install.log

  if ! /bin/bash /tmp/ecs-anywhere-install.sh \
      --region "${AWS_DEFAULT_REGION}" \
      --cluster "${ECS_CLUSTER}" \
      --activation-id "${SSM_ACTIVATION_ID}" \
      --activation-code "${SSM_ACTIVATION_CODE}" \
      >>/var/log/ecs-install.log 2>&1 &
  spinner "$!" "/var/log/ecs-install.log"; then
    container_status="$(docker ps -a --filter='name=ecs-agent' --format '{{.Status}}')"
    if [[ "$?" != 0 || "$container_status" =~ Exited ]]; then
      err "Failed to register external instance."
      grep Error /var/lib/docker/containers/*/*-json.log
      exit 1
    else
      info "Instance successfully registered to Stackguardian platform."
    fi
  else
    err "Failed to register external instance."
    exit 1
  fi

  configure_local_network
  configure_fluentbit
  setup_cron
  print_details
}
#}}}

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

  url="${SG_NODE_API_ENDPOINT}/orgs/${ORGANIZATION_ID}/runnergroups/${RUNNER_GROUP_ID}/deregister/"

  debug "Calling URL:" "${url}"

  payload="{ \"RunnerId\": \"${RUNNER_ID}\" }"

  debug "Payload:" "${payload}"

  info "Trying to deregsiter instance.."
  if api_call; then
    info "Instance deregistered. Removing local data.."
    clean_local_setup
  else
    err "Could not fetch data from API. >>" "$message - $status_code" "<<"
    force_exec && clean_local_setup
  fi
}
#}}}

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
#}}}

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
doctor() { #{{{
  info "Checking services health status.."
  echo

  jq ".system.last_check = \"$(date)\"" "$DIAGNOSTIC_FILE" >> "$TMP_FILE"
  mv "$TMP_FILE" "$DIAGNOSTIC_FILE"

  local status_list=""
  local service_status
  local service_list=( "ecs" "docker" )

  for service in "${service_list[@]}"; do
    service_status="$(systemctl is-active "${service}")"
    jq ".health.service.${service} = \"$service_status\"" $DIAGNOSTIC_FILE > $TMP_FILE
    mv $TMP_FILE $DIAGNOSTIC_FILE
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
    jq ".health.service.docker = \"$service_status\"" $DIAGNOSTIC_FILE > $TMP_FILE
    mv $TMP_FILE $DIAGNOSTIC_FILE
    printf " + Container Status (${C_BOLD}docker ${C_RESET}service: ${C_RED}%s${C_RESET})\n\n" "${service_status}"
    return
  fi

  status_list=""
  local containers=( "ecs" "fluentbit" )

  for container in "${containers[@]}"; do
    local container_status
    container_status="$(docker ps \
      --filter "name=${container}-agent" \
      --format '{{.Status}}'\
      )"
    if [[ -z ${container_status} ]]; then
      jq ".health.container.$container = \"Not Running\"" $DIAGNOSTIC_FILE > $TMP_FILE
      mv $TMP_FILE $DIAGNOSTIC_FILE
      status_list="$(printf "%s\n%s" \
        "${status_list}" \
        "$(printf " | * ${C_BOLD}%s${C_RESET} agent: ${C_RED}Not Running${C_RESET}\n" "${container}")")"
    else
      jq ".health.container.$container = \"$container_status\"" $DIAGNOSTIC_FILE > $TMP_FILE
      mv $TMP_FILE $DIAGNOSTIC_FILE
      status_list="$(printf "%s\n%s" \
        "${status_list}" \
        "$(printf " | * ${C_BOLD}%s${C_RESET} agent: ${C_GREEN}%s${C_RESET}\n" "${container}" "${container_status}")")"
    fi
  done
  doctor_frame "Container Status" "${status_list}"

  echo
  info "Services health status generated."
}
#}}}

prune() { #{{{
  local reclaimed

  info "Cleaning up system.."

  reclaimed=$(docker system prune -f \
    --filter "until=$(date -d "10 days ago" +%Y-%m-%d)" \
    | cut -d: -f2 | tr -d ' ')

  jq ".system.docker.last_prune = \"$(date)\"" "$DIAGNOSTIC_FILE" >> "$TMP_FILE"
  mv "$TMP_FILE" "$DIAGNOSTIC_FILE"
  jq ".system.docker.reclaimed = \"$reclaimed\"" "$DIAGNOSTIC_FILE" >> "$TMP_FILE"
  mv "$TMP_FILE" "$DIAGNOSTIC_FILE"

  info "System cleaned. Reclimed:" "$reclaimed"
}
#}}}

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
#}}}


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
#}}}

is_root() { #{{{
  if (( $(id -u) != 0 )); then
    err "This script must be run as" "root"
    exit 1
  fi
  return 0
}
#}}}

init_args_are_valid() { #{{{
  if [[ ! "$1" =~ register|deregister|doctor|prune ]]; then
    err "Provided option" "${1}" "is invalid"
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
#}}}

check_sg_args() { #{{{
  if [[ -z "${SG_NODE_TOKEN}" \
    || -z "${ORGANIZATION_ID}" \
    || -z "${RUNNER_GROUP_ID}" ]]; then
    err "Arguments: " "--sg-node-token, --organization, --runner-group" "are required"
    exit 1
  fi
  return 0
}
#}}}

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
#}}}

main() { #{{{

for command in jq crontab; do
  if ! type $command >&/dev/null; then
    err "Command" "$command" "not installed"
    exit 1
  fi
done

[[ "${*}" =~ --help || $# -lt 1 ]] && show_help && exit 0

is_root && init_args_are_valid "$@"

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
esac

# TODO: API call to ping the node

}
#}}}

trap cleanup SIGINT
trap exit_help EXIT

main "$@"

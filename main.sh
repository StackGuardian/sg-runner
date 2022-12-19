#!/usr/bin/env bash

# set -e -o "pipefail"

## colors for printf
C_RED_BOLD="\033[1;31m"
C_RED="\033[0;31m"
C_GREEN_BOLD="\033[1;32m"
C_GREEN="\033[0;32m"
C_YELLOW_BOLD="\033[1;33m"
C_YELLOW="\033[0;33m"
C_BLUE_BOLD="\033[1;34m"
C_BLUE="\033[0;34m"
C_MAGENTA_BOLD="\033[1;35m"
C_MAGENTA="\033[0;35m"
C_CYAN_BOLD="\033[1;36m"
C_CYAN="\033[0;36m"
C_RESET="\033[0m"
C_BOLD="\033[1m"

_err() {
  printf "\n${C_RED_BOLD}==> [ERROR] ${C_RED}%s" "$*" 1>&2
  exit 1
}

_help() {
  echo ""
  echo "$(basename "$0") [register deregister]"
  exit 2
}

_check_args_value() {
  if [[ "${2:0:2}" == "--" ]]; then
    _err "Argument $1 has invalid value: $2."
  elif [[ -z "${2}" ]]; then
    _err "Argument $1 is empty."
  fi
}

_fetch_credentials() {
  response=$(curl -vLk -H "Authorization: apikey ${SG_NODE_TOKEN}" "${SG_NODE_API_ENDPOINT}"/register_runner)

  # response={
  #     "AWSDefaultRegion": "",
  #     "AWSAccessKeyId": "",
  #     "AWSSecretAccessKey": "",
  #     "AWSSessionToken": "",
  #     "IAMRoleName",
  #     "SSMActivationId": "",
  #     "SSMActivationCode": "",
  #     "OrgId": "",
  #     "ExternalId": "",
  #     "ResourceId": ""
  # }

}

_register_instance() {

  # curl --proto "https" -o "/tmp/ecs-anywhere-install.sh" "https://amazon-ecs-agent.s3.amazonaws.com/ecs-anywhere-install-latest.sh"

  # TODO: verify ecs-anywhere script integrity
  # gpg --keyserver hkp://keys.gnupg.net:80 --recv BCE9D9A42D51784F
  # curl --proto "https" -o "/tmp/ecs-anywhere-install.sh.asc" "https://amazon-ecs-agent.s3.amazonaws.com/ecs-anywhere-install-latest.sh.asc"
  # gpg --verify /tmp/ecs-anywhere-install.sh.asc /tmp/ecs-anywhere-install.sh

  ## expected output
  # gpg: Signature made Tue 25 May 2021 07:16:29 PM UTC
  # gpg:                using RSA key 50DECCC4710E61AF
  # gpg: Good signature from "Amazon ECS <ecs-security@amazon.com>" [unknown]
  # gpg: WARNING: This key is not certified with a trusted signature!
  # gpg:          There is no indication that the signature belongs to the owner.
  # Primary key fingerprint: F34C 3DDA E729 26B0 79BE  AEC6 BCE9 D9A4 2D51 784F
  #      Subkey fingerprint: D64B B6F9 0CF3 77E9 B5FB  346F 50DE CCC4 710E 61AF

  /usr/bin/bash /tmp/ecs-anywhere-install.sh \
      --region "${AWS_DEFAULT_REGION}" \
      --cluster "${SG_ECS_CLUSTER}" \
      --activation-id "${SSM_ACTIVATION_ID}" \
      --activation-code "${SSM_ACTIVATION_CODE}"

  source ecs-anywhere-install.sh --region ${AWS_DEFAULT_REGION} --cluster ${ECS_CLUSTER} --activation-id "${SSM_ACTIVATION_ID}" --activation-code "${SSM_ACTIVATION_CODE}"
}

_deregister_instance() {
  aws ecs deregister-container-instance --cluster ${ECS_CLUSTER} --container-instance ${}
}

if [[ $(id -u) -ne 0 ]]; then
  _err "This script must be run as root."
fi

if [[ "$#" -lt 1 || ! "$*" =~ register|deregister ]]; then
  _help
fi

OPTION=$1
shift

while :; do
  case "$1" in
  --sg-node-token)
    _check_args_value "$1" "$2"
    SG_NODE_TOKEN="$2"
    shift 2
    ;;
  --sg-node-api-endpoint)
    _check_args_value "$1" "$2"
    SG_NODE_API_ENDPOINT="$2"
    shift 2
    ;;
  --sg-ecs-cluster)
    _check_args_value "$1" "$2"
    SG_ECS_CLUSTER="$2"
    shift 2
    ;;
  *)
    [ -z "$1" ] && break
    _err "Invalid option: [$1]"
    ;;
  esac
done

if [[ -z "$SG_NODE_TOKEN" && -z "$SG_NODE_API_ENDPOINT" && -z "$SG_ECS_CLUSTER" ]]; then
  _err "Arguments: --sg-node-token, --sg-node-api-endpoint, --sg-ecs-cluster are required."
fi

echo "SG_NODE_TOKEN: ${SG_NODE_TOKEN}, SG_NODE_API_ENDPOINT: ${SG_NODE_API_ENDPOINT}, SG_ECS_CLUSTER: ${SG_ECS_CLUSTER}, OPTION: ${OPTION}" && exit 0

# TODO: save responses to variables for further usage in script
SG_ECS_CLUSTER=private-runner-test
#
AWS_DEFAULT_REGION=eu-central-1
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_SESSION_TOKEN=
IAM_ROLE_NAME=
SSM_ACTIVATION_ID=
SSM_ACTIVATION_CODE=
ORGANIZATION_ID=
EXTERNAL_ID=
RESOURCE_ID=

# Set up directories the agent uses
mkdir -p /var/log/ecs /etc/ecs /var/lib/ecs/data
rm -rf /etc/ecs/ecs.config /var/lib/ecs/ecs.config
# rm -rf /var/lib/amazon/ssm/Vault/Store/*

# echo ECS_CLUSTER=$sgECSCluster >> /etc/ecs/ecs.config
# echo AWS_DEFAULT_REGION=${response['AWSDefaultRegion']} >> /etc/ecs/ecs.config
# echo AWS_ACCESS_KEY_ID=${response['AWSAccessKeyId']} >> /etc/ecs/ecs.config
# echo AWS_SECRET_ACCESS_KEY=${response['AWSSecretAccessKey']} >> /etc/ecs/ecs.config
# echo AWS_SESSION_TOKEN=${response['AWSSessionToken']} >> /etc/ecs/ecs.config
# echo ECS_INSTANCE_ATTRIBUTES={"sg_organization": ${response['OrgName']},"sg_externalid": ${response['ExternalId']}} >> /etc/ecs/ecs.config

# echo ECS_LOGLEVEL=/log/ecs-agent.log >> /etc/ecs/ecs.config
# echo ECS_DATADIR=/data/ >> /etc/ecs/ecs.config
# echo ECS_ENABLE_TASK_IAM_ROLE=true >> /etc/ecs/ecs.config
# echo ECS_ENABLE_TASK_IAM_ROLE_NETWORK_HOST=true >> /etc/ecs/ecs.config

cat > /etc/ecs/ecs.config << EOF
ECS_CLUSTER=${SG_ECS_CLUSTER}
AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}
ECS_INSTANCE_ATTRIBUTES={"sg_organization": "test","sg_externalid": "1"}
ECS_LOGLEVEL=/log/ecs-agent.log
ECS_DATADIR=/data/
ECS_ENABLE_TASK_IAM_ROLE=true
ECS_ENABLE_TASK_IAM_ROLE_NETWORK_HOST=true
EOF

cat > /var/lib/ecs/ecs.config << EOF
AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION}
ECS_EXTERNAL=true
EOF

# Set up necessary rules to enable IAM roles for tasks
sysctl -w net.ipv4.conf.all.route_localnet=1
# sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A PREROUTING -p tcp -d 169.254.170.2 --dport 80 -j DNAT --to-destination 127.0.0.1:51679
iptables -t nat -A OUTPUT -d 169.254.170.2 -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 51679

case "$OPTION" in
  register)
    _register_instance
    exit 0
    ;;
  deregister)
    _deregister_instance
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

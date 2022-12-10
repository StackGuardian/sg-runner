#!/usr/bin/env bash

# set -e -o "pipefail"

# sgNodeToken=${SG_NODE_TOKEN}
# sgNodeAPIEndpoint=${SG_NODE_API_ENDPOINT}
# sgECSCluster=${SG_ECS_CLUSTER}

# sgNodeToken || echo "A Node Token is not provided. Read docs. Use Env var: SG_NODE_TOKEN" && exit 1
# sgNodeAPIEndpoint || echo "StackGuardian Node API is not provided. Read docs. Env var: SG_NODE_API_ENDPOINT" && exit 1

# response=$(curl -vLk -H "Authorization: apikey ${sgNodeToken}" ${sgNodeAPIEndpoint}/register_runner)

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

# TODO: save responses to variables for further usage in script

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
ECS_CLUSTER=private-runner-test
AWS_DEFAULT_REGION=eu-central-1
ECS_INSTANCE_ATTRIBUTES={"sg_organization": "test","sg_externalid": "1"}
ECS_LOGLEVEL=/log/ecs-agent.log
ECS_DATADIR=/data/
ECS_ENABLE_TASK_IAM_ROLE=true
ECS_ENABLE_TASK_IAM_ROLE_NETWORK_HOST=true
EOF

cat > /var/lib/ecs/ecs.config << EOF
AWS_DEFAULT_REGION=eu-central-1
ECS_EXTERNAL=true
EOF

# Set up necessary rules to enable IAM roles for tasks
# sysctl -w net.ipv4.conf.all.route_localnet=1
# sysctl -w net.ipv4.ip_forward=1
# iptables -t nat -A PREROUTING -p tcp -d 169.254.170.2 --dport 80 -j DNAT --to-destination 127.0.0.1:51679
# iptables -t nat -A OUTPUT -d 169.254.170.2 -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 51679

curl --proto "https" -o "/tmp/ecs-anywhere-install.sh" "https://amazon-ecs-agent.s3.amazonaws.com/ecs-anywhere-install-latest.sh"

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
    --region eu-central-1 \
    --cluster private-runner-test \
    --activation-id "${SSMActivationId}" \
    --activation-code "${SSMActivationCode}"

# source ecs-anywhere-install.sh --region eu-central-1 --cluster private-runner-test --activation-id "${SSMActivationId}" --activation-code "${SSMActivationCode}"

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

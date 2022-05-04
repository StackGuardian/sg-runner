#!/bin/sh

set -e -o "pipefail"

sgNodeToken=${SG_NODE_TOKEN}
sgNodeAPIEndpoint=${SG_NODE_API_ENDPOINT}
sgECSCluster=${SG_ECS_CLUSTER}

sgNodeToken || echo "A Node Token is not provided. Read docs. Use Env var: SG_NODE_TOKEN"
sgNodeAPIEndpoint || echo "StackGuardian Node API is not provided. Read docs. Env var: SG_NODE_API_ENDPOINT"

response=$(curl -vLk -H "Authorization: apikey ${sgNodeToken}" ${sgNodeAPIEndpoint}/register_runner)

# Set up directories the agent uses
mkdir -p /var/log/ecs /etc/ecs /var/lib/ecs/data
touch /etc/ecs/ecs.config

echo ECS_CLUSTER=$sgECSCluster >> /etc/ecs/ecs.config
echo AWS_DEFAULT_REGION=$sgECSCluster >> /etc/ecs/ecs.config
echo AWS_ACCESS_KEY_ID=$sgECSCluster >> /etc/ecs/ecs.config
echo AWS_SECRET_ACCESS_KEY=$sgECSCluster >> /etc/ecs/ecs.config
echo AWS_SESSION_TOKEN=$sgECSCluster >> /etc/ecs/ecs.config
echo ECS_LOGLEVEL=/log/ecs-agent.log >> /etc/ecs/ecs.config
echo ECS_DATADIR=/data/ >> /etc/ecs/ecs.config
echo ECS_ENABLE_TASK_IAM_ROLE=true >> /etc/ecs/ecs.config
echo ECS_ENABLE_TASK_IAM_ROLE_NETWORK_HOST=true >> /etc/ecs/ecs.config
echo ECS_INSTANCE_ATTRIBUTES={"sg_organization": ${response['Org']},"sg_externalid": ${response['ExternalId']}} >> /etc/ecs/ecs.config


# Set up necessary rules to enable IAM roles for tasks
sysctl -w net.ipv4.conf.all.route_localnet=1
iptables -t nat -A PREROUTING -p tcp -d 169.254.170.2 --dport 80 -j DNAT --to-destination 127.0.0.1:51679
iptables -t nat -A OUTPUT -d 169.254.170.2 -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 51679
# Run the agent
# TODO: check which volumes will be exported?
docker run --name ecs-agent \
    --detach=true \
    --restart=on-failure:10 \
    --volume=/var/run/docker.sock:/var/run/docker.sock \
    --volume=/var/log/ecs:/log \
    --volume=/var/lib/ecs/data:/data \
    --net=host \
    --env-file=/etc/ecs/ecs.config \
    amazon/amazon-ecs-agent:latest
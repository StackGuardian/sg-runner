# sg-runner Kubernetes prototype image: one image backs every container of
# the pod (see runner.sh). Build from the repo root:
#   docker build -f k8s/Dockerfile -t sg-runner-k8s:dev .

# Pinned for reproducible builds; each exists for linux/amd64 and linux/arm64.
# ECS agent: Docker Hub tags (https://hub.docker.com/r/amazon/amazon-ecs-agent/tags).
ARG ECS_AGENT_VERSION=v1.108.0

FROM amazon/amazon-ecs-agent:${ECS_AGENT_VERSION} AS ecs-agent

FROM debian:bookworm-slim

ARG TARGETARCH
ARG DOCKER_VERSION=27.5.1
# SSM agent: .../SSMAgent/latest/VERSION names the current release.
ARG SSM_AGENT_VERSION=3.3.5390.0

# upgrade: pick up Debian security fixes newer than the base image.
RUN apt-get update \
  && apt-get upgrade -y \
  && apt-get install -y --no-install-recommends \
    bash ca-certificates curl jq iproute2 iptables procps xz-utils \
  && rm -rf /var/lib/apt/lists/*

# Docker engine + CLI (static build), run nested in the privileged container.
RUN arch="$([ "$TARGETARCH" = arm64 ] && echo aarch64 || echo x86_64)" \
  && curl -fsSL "https://download.docker.com/linux/static/stable/${arch}/docker-${DOCKER_VERSION}.tgz" \
    | tar -xz -C /usr/local/bin --strip-components=1

# SSM agent. Unpacked rather than installed: the postinst expects systemd.
# Staged first: extracting onto / would replace the merged-usr /lib symlink.
RUN curl -fsSL -o /tmp/ssm.deb \
    "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/${SSM_AGENT_VERSION}/debian_${TARGETARCH}/amazon-ssm-agent.deb" \
  && mkdir /tmp/ssm \
  && dpkg-deb -x /tmp/ssm.deb /tmp/ssm \
  && cp /tmp/ssm/usr/bin/* /usr/bin/ \
  && cp -r /tmp/ssm/etc/amazon /etc/ \
  && cp /etc/amazon/ssm/seelog.xml.template /etc/amazon/ssm/seelog.xml \
  && rm -rf /tmp/ssm /tmp/ssm.deb

# ECS agent, run directly instead of through ecs-init.
COPY --from=ecs-agent /agent /usr/local/bin/ecs-agent
COPY --from=ecs-agent /amazon-ecs-cni-plugins /amazon-ecs-cni-plugins
COPY --from=ecs-agent /images /images

COPY main.sh /opt/sg-runner/main.sh
COPY k8s/runner.sh /opt/sg-runner/runner.sh

ENTRYPOINT ["/opt/sg-runner/runner.sh"]

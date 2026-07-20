# Tier-3 integration image for main.sh.
#
# Why a container at all?
#   preflight() in main.sh dies unless /run/systemd/system exists. The unit and
#   smoke tiers run on the host and never reach preflight (they call functions
#   directly). The integration tier drives whole flows through main(), so it
#   must satisfy preflight. We do NOT want real systemd/docker — just a Linux
#   userland where we can fake the one directory preflight probes.
#
# The trick:
#   preflight only checks that /run/systemd/system is a directory; it never
#   talks to systemd. `mkdir -p /run/systemd/system` is enough to get past it.
#   Every host-affecting command (systemctl, docker, curl, iptables, ...) is
#   already shadowed by the stubs in test/mocks/bin, so once that directory
#   exists the flows run with zero real side effects.
#
# Image contents:
#   - bash 5 (the suite requires GNU bash 5+ as the first bash on PATH)
#   - jq + coreutils (main.sh parses API JSON with jq; tests use cut/sed/awk)
#   - the vendored bats-core under test/lib (nothing is fetched at runtime)
FROM debian:stable-slim

# bash 5, jq, and coreutils are the only real binaries the flows need; the rest
# of main.sh's externals come from the mock stubs put on PATH below.
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    coreutils \
    jq \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --create-home --uid 1000 runner

WORKDIR /sg-runner

# Copy only what the tier needs — main.sh under test plus the test tree (mocks,
# vendored bats, fixtures) — rather than the whole build context.
COPY main.sh ./
COPY test/ ./test/

# Satisfy preflight()'s only environment probe (see header). The container has
# no real systemd; this empty directory is all preflight inspects. Hand the repo
# to an unprivileged user so the tier runs without root.
RUN mkdir -p /run/systemd/system \
  && chown -R runner:runner /sg-runner

USER runner

# Put the mock stubs first on PATH so systemctl/docker/curl/iptables/... resolve
# to the recording stubs, exactly as load.bash does for the host-run tiers.
ENV PATH="/sg-runner/test/mocks/bin:${PATH}"

# Default to running the integration tier. Override the args to run a single
# file, e.g. `docker run <img> test/integration/register_flow.bats`.
ENTRYPOINT ["./test/lib/bats-core/bin/bats"]
CMD ["test/integration/"]

# sg-runner on Kubernetes (prototype)

> **Status: prototype.** Not supported, not documented for customers.

Runs a Private Runner as a pod. Each StatefulSet replica is one registered
runner: it stands in for the VM that `main.sh register` normally prepares.

## How it maps to a VM

| VM (`main.sh` + `ecs-anywhere-install.sh`) | Pod                                                      |
|--------------------------------------------|----------------------------------------------------------|
| `systemd` + `dockerd`                       | `dockerd` container (privileged, nested Docker)           |
| `amazon-ssm-agent` service                  | `ssm-agent` container                                     |
| `ecs-init` → `ecs-agent` container          | `ecs-agent` container, env loaded from `ecs.config`       |
| `register` (API + SSM activation)           | `register` init container, skipped if state exists        |
| `/etc/ecs`, `/var/lib/ecs`, `/var/lib/amazon/ssm` | `state` PVC: runner identity survives pod restarts  |
| `/root/.aws/credentials` (SSM → agent)      | in-memory `emptyDir` shared by both agents                |
| `configure_local_network` (iptables/sysctl) | same function, run in the pod's network namespace         |

All containers use one image (`Dockerfile`) and `runner.sh`, which sources
`main.sh` for the API, config and network helpers.

## Usage (OrbStack Kubernetes)

```sh
cd k8s
cp .env.example .env   # fill in a throwaway runner group's credentials
make build             # build sg-runner-k8s:dev
make secret            # namespace + credentials Secret
make up                # deploy; first start registers the runner
make logs              # follow all containers
make status            # pod state + ECS agent metadata

make deregister        # SG deregister + wipe identity (reads .env on stdin)
make nuke              # deregister, then delete StatefulSet, PVCs, namespace
```

`make nuke` deregisters first and stops if that fails: deleting the PVC without
deregistering would leave a dead runner in the runner group.

## Resource sizing

The ECS agent sizes the runner from the node, not the pod: CPU is
`runtime.NumCPU() x 1024` (CPU affinity, not the cgroup quota) and memory is
`MemTotal` from `/proc/meminfo`. Workflows run inside the `dockerd` container,
so its limits are what the runner should advertise. `runner.sh ecs-agent`
reads them through the downward API and:

- sets `ECS_RESERVED_MEMORY` to node memory minus (limit - 256 MiB for dockerd,
  `SG_DOCKERD_OVERHEAD_MIB`). The agent parses it as `uint16`; a reservation
  above 65535 MiB would silently become 0, so the agent refuses to start instead.
- pins the agent to `limits.cpu` CPUs (rounded up) with `taskset`.

Without limits on `dockerd`, the runner advertises the whole node.

## Stopping and scaling down

The `ecs-agent` container's `preStop` hook (`runner.sh drain`) first sets the
runner's ECS container instance `DRAINING`, so ECS stops placing new tasks on
it, then holds the pod until running workflows finish, up to
`terminationGracePeriodSeconds` (1h). Draining on every shutdown keeps a
busy runner from picking up new work during a restart or rollout, which would
otherwise hold each pod for the full hour. `dockerd` and `ssm-agent` wait for
the hook (`wait-drained`), so workflows keep their Docker daemon and the agent
keeps rotating credentials meanwhile. On start, the agent sets the container
instance `ACTIVE` again once it has registered.

It tells a scale-down from any other termination by reading its own
StatefulSet (a Role allows `get` on it only; the token is projected into
`ecs-agent` alone): the pod's ordinal no longer fits under `spec.replicas`.

| Termination | Drain behavior |
|---|---|
| Scale-down (`kubectl scale`) | `DRAINING`, wait for workflows, deregister from SG, wipe identity |
| Restart, rollout, eviction, StatefulSet deleted | `DRAINING`, wait for workflows, keep the identity; `ACTIVE` again on start |

PVCs are kept on scale-down: if deregistration fails, the identity is still
there for the next scale-up.

## Known gaps

- **Privileged pod.** Needed for nested Docker; restricted PSA clusters reject it.
  Non-privileged works with `SYS_ADMIN`, `NET_ADMIN`, `SYS_RESOURCE`, Unconfined
  seccomp and read-write remounts of `/sys/fs/cgroup` and `/proc/sys` (verified on
  OrbStack), but that's no real isolation gain. See [`docs/TODO.md`](../docs/TODO.md).
- **Network isolation.** The VM rule (`DOCKER-USER` DROP for
  `169.254.169.254,10.0.0.0/24`) doesn't fit a cluster: job containers can
  resolve cluster DNS and reach the Kubernetes API (verified). Needs a
  NetworkPolicy on the runner pod and a CNI that enforces it
  ([`docs/TODO.md`](../docs/TODO.md)).
- **Workspaces in the container layer.** `/var/tmp/workspace`, bind-mounted
  by the run controller and steps, isn't on a volume yet
  ([`docs/TODO.md`](../docs/TODO.md)).
- **Task cgroup limits off** (`ECS_ENABLE_TASK_CPU_MEM_LIMIT=false`): the agent
  can't create task cgroups from its container. Size the pod's resources instead.
- **No proxy support** yet (`--http-proxy` path not wired).
- **`DRAINING`/`ACTIVE` are denied on QA** (`AccessDeniedException` on the
  container-instance ARN; `ECSAnywherePolicy` only names the cluster ARN). Shutdowns
  still wait for running workflows, but ECS may place new tasks meanwhile, so a
  busy runner can hold its pod for the full grace period
  ([`docs/TODO.md`](../docs/TODO.md)).
- **SG token in the pod.** Deregistering on scale-down needs it, so the
  credentials Secret is mounted (read-only) into `ecs-agent`.
- **Pods end in `Error`.** The containers exit non-zero on SIGTERM after a
  clean drain; cosmetic.
- **SSM Run Command** lands in the `ssm-agent` container (it has the Docker
  CLI and socket), not on a host. Unverified whether SG relies on it.
- `ecs-init` is bypassed: agent defaults it sets are copied in `runner.sh` and
  may drift with new agent releases.

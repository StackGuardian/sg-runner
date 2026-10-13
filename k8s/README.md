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

kubectl -n sg-runner scale sts sg-runner --replicas=N   # park / wake runners

make deregister        # wake parked runners, deregister all (reads .env on stdin)
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

## Parking: stopping and scaling down

Scaling down doesn't deregister a runner, it **parks** it: the pod stops, the
registration and Docker image cache stay on its PVCs, and scaling back up
wakes the same runner without registering again.

| Measured on QA | Time to ECS `ACTIVE` + connected |
|---|---|
| Wake a parked runner (`kubectl scale` up) | **8s**, same container instance, image cache kept |
| Fresh runner (new ordinal, full registration) | 20s, plus image pulls on its first workflow |
| Park a runner (`kubectl scale` down, idle) | 14s |

Every shutdown (scale-down, restart, rollout, eviction) parks the same way.
The `ecs-agent` container's `preStop` hook (`runner.sh drain`):

1. sets the runner `DRAINING` through SG's `runner_status` API (the same call
   `sg-runner-autoscaler` uses), so no new workflows are placed on it, and
   leaves a marker on the state PVC;
2. waits for running workflows, up to `terminationGracePeriodSeconds` (1h).
   `dockerd` and `ssm-agent` wait for the hook (`wait-drained`), so workflows
   keep their Docker daemon and the agent keeps rotating credentials.

On wake the runner sets itself `ACTIVE` again once the agent has reconnected,
only if the marker is there. A runner that was already `DRAINING` when it
parked, drained on purpose from the SG UI or by an autoscaler, stays drained.

A parked runner shows in SG as registered but disconnected and `DRAINING`;
it still counts against the runner group's `MaxNumberOfRunners`. Pods are
managed in parallel (`podManagementPolicy: Parallel`), so several runners park
or wake at once.

Status changes use the runner group's node token, the same credential the
runner registers with; no extra key is needed. The runner never calls ECS
itself: a customer's runner has no ECS permissions.

Deregistering is explicit: `make deregister` wakes every parked runner (each
state PVC) and deregisters them all; `make nuke` does that and deletes
everything. Runners parked longer than `SCALER_PARK_TTL` are reaped by the scaler.

## Autoscaling

`manifests/scaler.yaml` runs the scaler ([`scaler/`](scaler), Go; image
built with `make build-scaler`), a loop that owns the runner StatefulSet's
`replicas`. Every `SCALER_INTERVAL` (15s) it reads the runner
group from SG with the node token (`?getActiveWorkflows=true`) and:

| Rule | When | Action |
|---|---|---|
| Scale out | workflows queued and no awake runner fully idle | +1 runner: wakes a parked one, or registers a new one |
| Headroom (optional) | less than `SCALER_HEADROOM_PCT` of awake runners' CPU or memory free (0 = off, the default) | +1 runner, kept as a warm spare |
| Scale in | nothing queued, highest awake runner idle for `SCALER_IDLE_SECONDS` (60), the rest still keeps the headroom | park it (-1) |
| Stuck queue | workflows queued while an awake runner sits fully idle for `SCALER_STUCK_SECONDS` (180) | warn, ignore the queue (it needs more than a runner pod offers) |
| Reap | runner parked longer than `SCALER_PARK_TTL` (12h) | Job deregisters it from its PVC, then its PVCs are deleted |

Replicas stay within `SCALER_MIN` (≥ 1: SG pauses workflows without an
`ACTIVE` runner) and the lower of `SCALER_MAX` and the runner group's
`MaxNumberOfRunners`. Runners map to ordinals by hostname (the pod's FQDN).
While an awake runner hasn't connected yet, the scaler waits instead of
deciding again, for up to `SCALER_SETTLE_TIMEOUT` (300s); a runner that still
isn't connected by then (failed registration, crash loop) is left out of the
decision, reported and set `DRAINING`, so one broken pod can't freeze scaling.

A parked runner that SG still shows `ACTIVE` (its pod went away without the
`preStop` drain: node loss, force delete) is set `DRAINING` too. Drains the
scaler does are marked on the runner's state PVC
(`sg-runner.stackguardian.io/drained-by-scaler`), and the scaler sets the
runner `ACTIVE` again once it's awake and connected. Drains from anyone else
(SG UI, an autoscaler) leave no mark and stick.

Two replicas share a leader Lease (`<statefulset>-scaler`;
`SCALER_LEADER_ELECT=false` turns it off). The idle, stuck and settle timers
are kept as annotations on the StatefulSet, so a restart or a new leader
carries on where the last one stopped. On SG or Kubernetes API errors a loop
decides nothing and the next one waits longer (doubling, up to 5 minutes).
Decisions and warnings (`StuckQueue`, `RunnerNotConnected`, `SGUnreachable`,
`ReapFailed`, ...) are Events on the StatefulSet; Prometheus metrics
(`sg_runner_scaler_*`), `/healthz` and `/readyz` are served on port 9090.

Its Role covers only this StatefulSet, its scale and annotations, PVCs, reap
Jobs, Events and its Lease; runner pods have no Kubernetes API access.

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
- **Workflows bigger than a runner pod never run.** A workflow reserves
  0.5 vCPU / 512 MiB plus its own resource setting; if that exceeds the
  `dockerd` container's limits it stays queued. The scaler detects it and warns
  instead of waking every runner, but the pod size must cover the largest
  workflow.
- **Restarting a single runner pauses new workflows** for the ~10s it takes:
  SG pauses workflows submitted while no runner is `ACTIVE`, and a StatefulSet
  stops the old pod before starting the new one. Use `SCALER_MIN=2` where that
  matters.
- **Unverified: long parking.** Waking was tested after seconds. Whether SSM
  and ECS reconnect after hours or days parked isn't tested yet.
- **Unverified: hard kills.** A pod killed without its `preStop` hook (node
  crash) parks as `ACTIVE` but disconnected; how ECS treats that isn't tested.
- **SG credentials in the pod.** The credentials Secret is mounted
  (read-only) into `ecs-agent` for the status changes.
- **Pods end in `Error`.** The containers exit non-zero on SIGTERM after a
  clean drain; cosmetic.
- **SSM Run Command** lands in the `ssm-agent` container (it has the Docker
  CLI and socket), not on a host. Unverified whether SG relies on it.
- `ecs-init` is bypassed: agent defaults it sets are copied in `runner.sh` and
  may drift with new agent releases.

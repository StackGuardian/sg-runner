# sg-runner on Kubernetes (prototype)

> **Status: prototype.** Not supported, not documented for customers.

Runs Private Runners as pods (Kubernetes ≥ 1.29). Each StatefulSet replica is
one registered runner on a node of its own: it stands in for the VM that
`main.sh register` normally prepares. Run controllers run in the pod's nested
Docker; each workflow step runs as a pod of its own on the runner's node,
created by the `steps` broker sidecar ([`docs/steps-api.md`](docs/steps-api.md)).
A scaler parks idle runners (pod stopped, registration kept, woken again in
seconds) and wakes or adds runners when workflows queue.

| Component | Where | What |
|---|---|---|
| Runner image | [`Dockerfile`](Dockerfile), [`runner.sh`](runner.sh) | nested `dockerd`, SSM agent, ECS agent; `runner.sh` sources `main.sh` |
| Scaler image | [`scaler/`](scaler) (Go) | sizes the StatefulSet from SG's queue, parks, wakes and reaps runners; also ships the steps broker (`/sg-runner-steps`) |
| Helm chart | [`chart/sg-runner`](chart/sg-runner/README.md) | runner StatefulSet, scaler, credentials, optional NetworkPolicy and PDB |

## How it maps to a VM

| VM (`main.sh` + `ecs-anywhere-install.sh`) | Pod                                                      |
|--------------------------------------------|----------------------------------------------------------|
| `systemd` + `dockerd`                       | `dockerd` container (privileged, nested Docker, run controllers only; guarded by the broker's authorization plugin) |
| workflow step containers                    | step pods on the runner's node (`steps` sidecar)          |
| `amazon-ssm-agent` service                  | `ssm-agent` container                                     |
| `ecs-init` → `ecs-agent` container          | `ecs-agent` container, env loaded from `ecs.config`       |
| `register` (API + SSM activation)           | `register` init container, skipped if state exists        |
| `/etc/ecs`, `/var/lib/ecs`, `/var/lib/amazon/ssm` | `state` PVC: runner identity survives pod restarts  |
| `/root/.aws/credentials` (SSM → agent)      | in-memory `emptyDir` shared by both agents                |
| `configure_local_network` (iptables/sysctl) | same function, run in the pod's network namespace         |

All runner containers use one image (`Dockerfile`) and `runner.sh`, which
sources `main.sh` for the API, config and network helpers.

## Usage (OrbStack Kubernetes)

```sh
cd k8s
cp .env.example .env   # fill in a throwaway runner group's credentials
make build             # runner image sg-runner-k8s:dev
make build-scaler      # scaler image sg-runner-scaler:dev
make secret            # namespace (privileged PSA) + credentials Secret
make up                # helm upgrade --install chart/sg-runner; first start registers the runner
make logs              # follow all containers
make status            # pod state + ECS agent metadata

kubectl -n sg-runner scale sts sg-runner --replicas=N   # park / wake runners

make down              # uninstall --no-hooks, keep PVCs (runners stay registered, parked)
make nuke              # helm uninstall (deregisters every runner, deletes PVCs), then the namespace
```

`helm uninstall` cleans up through the chart's pre-delete hook (see the
[chart README](chart/sg-runner/README.md#uninstall)). If a runner can't be
deregistered, the hook fails and keeps that runner's PVCs, and `make nuke`
stops before deleting the namespace: deleting the PVC without deregistering
would leave a dead runner in the runner group.

Outside OrbStack, install the published chart (GHCR, beta; its defaults use
the images of the same release). Only the node token is a Secret; the runner
group is plain values. Label the namespace where Pod Security is enforced
(runner pods are privileged):

```sh
kubectl create namespace sg-runner
kubectl label namespace sg-runner pod-security.kubernetes.io/enforce=privileged
kubectl -n sg-runner create secret generic sg-runner-credentials \
  --from-literal=SG_NODE_TOKEN=...
helm upgrade --install sg-runner oci://ghcr.io/stackguardian/charts/sg-runner --version <v> \
  -n sg-runner \
  --set sg.organization=<org> --set sg.runnerGroup=<runner group> \
  --set credentials.existingSecret=sg-runner-credentials \
  --set runner.size=medium
```

The chart in this repo (`k8s/chart/sg-runner`) installs the same way; its
default images carry the `dev` tag, so point `image.*` and `scaler.image.*` at
images you built (`make up` uses the local `:dev` builds).

### Choosing the runner size

Every workflow reserves 0.5 vCPU / 512 MiB for its run controller plus its own
resource setting (default 0.5 vCPU / 1 GiB), so a default workflow takes
1 vCPU / 1.5 GiB. `runner.size` picks what the runner advertises (step pods
and run controllers together; the node needs it free) and the `dockerd`
container's resources, which only hold the run controllers:

| `runner.size` | Advertised | Default workflows at once |
|---|---|---|
| `small` (default) | 2 vCPU / 4Gi | 2 |
| `medium` | 4 vCPU / 8Gi | 4 |
| `large` | 8 vCPU / 16Gi | 8 |
| `custom` | `runner.advertise` + `runner.controllerResources` (required) | |

The runner must be larger than the largest workflow (its setting plus
0.5 vCPU / 512 MiB), or that workflow stays queued; the scaler then warns
(`StuckQueue`) instead of waking every runner.

Image versions are pinned as build args in `Dockerfile` (`ECS_AGENT_VERSION`,
`SSM_AGENT_VERSION`, `DOCKER_VERSION`). `make build-multiarch` builds
`linux/amd64` and `linux/arm64` on a dedicated buildx builder and keeps only
the build cache; `PUSH=1 REGISTRY=<registry/namespace>` pushes the result.

## Workflow steps

Steps are pods (`app.kubernetes.io/component=step`), so `kubectl logs` shows
their output; finished ones stay for `runner.steps.finishedTTL`, labelled with
their outcome. Details in the
[chart README](chart/sg-runner/README.md#how-a-runner-runs-workflows).

## Docker cleanup

On a VM, `main.sh prune` runs from cron. In the pod, the `dockerd` container
prunes the nested Docker itself: once at start (a runner may park before a
full interval) and then every `SG_PRUNE_INTERVAL_SECONDS`.

| Env (on `dockerd`) | Default | |
|---|---|---|
| `SG_PRUNE_INTERVAL_SECONDS` | `14400` (4h, as the VM cron) | `0` turns cleanup off |
| `SG_PRUNE_UNTIL` | `24h` | minimum age of stopped containers, images and build cache it removes |
| `SG_PRUNE_IMAGES_ABOVE_PCT` | `70` | unused images go only once the Docker volume is this full (`0`: every run) |

Every sweep that can remove a container is age-guarded: an unguarded prune
deletes containers the ECS agent created but hasn't started yet. Volumes are
pruned on their own (`docker volume prune`). Unused images are the wake-up
cache, so they're kept until the volume fills up; Docker filters images by
creation time, not last use, so a prune under pressure removes every unused
image older than `SG_PRUNE_UNTIL`.

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

Runners are deregistered when they're reaped (parked longer than
`SCALER_PARK_TTL`) and on `helm uninstall`, which deregisters every runner,
awake or parked, from its state PVC and deletes the PVCs.

## Autoscaling

The chart's scaler Deployment ([`chart/sg-runner`](chart/sg-runner/README.md))
runs the scaler ([`scaler/`](scaler), Go; image built with `make build-scaler`),
a loop that owns the runner StatefulSet's `replicas`. Every `SCALER_INTERVAL`
(15s) it reads the runner
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
Reap Job pods take extra labels, pull secrets, node selector and tolerations
from `SCALER_REAP_POD_LABELS`, `SCALER_REAP_IMAGE_PULL_SECRETS`,
`SCALER_REAP_NODE_SELECTOR` and `SCALER_REAP_TOLERATIONS`; the chart sets them
from the runner's values.

The scaler reads the SG credentials once, at start: restart it
(`kubectl rollout restart deploy/<release>-sg-runner-scaler`) after rotating
the node token.

## Development

```sh
make lint test                       # repo root: shellcheck + bats (main.sh, k8s/runner.sh)
(cd k8s/scaler && go vet ./... && go test ./...)
helm lint --strict k8s/chart/sg-runner --set credentials.existingSecret=x
```

## Releasing

`.github/workflows/k8s-release.yml` publishes to GHCR: push a tag
`k8s/vX.Y.Z` (SemVer, optionally `-pre`) on `main` after the merge. After the
full k8s CI (`k8s.yml`) passes, it pushes the runner and scaler images
(`ghcr.io/stackguardian/sg-runner-k8s`, `sg-runner-scaler`, linux/amd64 and
arm64, with build provenance) and the chart
(`oci://ghcr.io/stackguardian/charts/sg-runner`), all as version `X.Y.Z` (the
chart's appVersion too), and creates the GitHub release with the install
command. An existing image tag or chart version fails the run instead of
being overwritten. A dry run (`workflow_dispatch` with a `version`) builds
and packages everything and pushes nothing. After the first publish, make
the three GHCR packages public once in the org's package settings.

## Known gaps

- **Privileged pod.** Needed for nested Docker; restricted PSA clusters reject it.
  Non-privileged works with `SYS_ADMIN`, `NET_ADMIN`, `SYS_RESOURCE`, Unconfined
  seccomp and read-write remounts of `/sys/fs/cgroup` and `/proc/sys` (verified on
  OrbStack), but that's no real isolation gain. See [`docs/TODO.md`](../docs/TODO.md).
- **Network isolation is opt-in.** Workflow containers can resolve cluster DNS
  and reach the Kubernetes API (verified). The chart's NetworkPolicy
  (`networkPolicy.enabled`, with the cluster's CIDRs) blocks cluster ranges and
  the metadata endpoint for runner, step and reap pods; it needs a CNI that
  enforces NetworkPolicy and isn't tested on one yet. The steps broker needs
  the Kubernetes API: allow its endpoint in `networkPolicy.extraEgress`.
- **Workspaces are scratch.** `/var/tmp/workspace` is a PVC per runner pod
  (`<pod>-workspace`, generic ephemeral, `runner.steps.workspace.size`,
  default 20Gi), deleted with the pod: a run doesn't survive a pod restart.
- **Task cgroup limits off** (`ECS_ENABLE_TASK_CPU_MEM_LIMIT=false`): the agent
  can't create task cgroups from its container. Run controllers share the
  `dockerd` container's limits; steps get their own pod requests and limits.
- **No proxy support** yet (`--http-proxy` path not wired).
- **Workflows bigger than a runner pod never run.** A workflow reserves
  0.5 vCPU / 512 MiB plus its own resource setting; if that exceeds the
  `dockerd` container's limits it stays queued. The scaler detects it and warns
  instead of waking every runner, but the pod size must cover the largest
  workflow.
- **Restarting a single runner pauses new workflows** for the ~10s it takes:
  SG pauses workflows submitted while no runner is `ACTIVE`, and a StatefulSet
  stops the old pod before starting the new one. `podDisruptionBudget.enabled`
  keeps node drains from evicting the last runner; for rollouts use
  `scaler.min=2` where that matters. Unverified: whether SG resumes such
  workflows on its own once a runner reconnects.
- **Unverified: long parking.** Waking was tested after seconds. Whether SSM
  and ECS reconnect after hours or days parked isn't tested yet.
- **Hard kills.** A pod killed without its `preStop` hook (node loss, force
  delete) parks as `ACTIVE` but disconnected; the scaler sets it `DRAINING` and
  reactivates it on wake. Unverified against real SG/ECS (tested with a fake
  SG). If someone also drains such a runner from the SG UI while the scaler's
  mark is on it, the scaler reactivates it on wake.
- **SG credentials in the pod.** The credentials Secret is mounted
  (read-only) into `ecs-agent` for the status changes, and into the scaler.
- **Pods end in `Error`.** The containers exit non-zero on SIGTERM after a
  clean drain; cosmetic.
- **SSM Run Command** lands in the `ssm-agent` container (it has the Docker
  CLI and socket), not on a host. Unverified whether SG relies on it.
- `ecs-init` is bypassed: agent defaults it sets are copied in `runner.sh` and
  may drift with new agent releases.
- **Go scaler not yet run against real SG.** Its rules were validated on QA in
  the shell version it replaces, and the Go version against a fake SG; the
  chart + Go scaler end to end on QA is still to do.

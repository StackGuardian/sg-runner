# sg-runner on Kubernetes (prototype)

> **Status: prototype, not supported.** Workflows run only with a run
> controller release that supports the step broker, and that release is not
> out yet. If the run controller lacks it, the runner refuses to start the
> workflow's steps and those steps fail with an error.

Runs Private Runners as pods (Kubernetes ≥ 1.29). Each StatefulSet replica is
one registered runner on a node of its own: it stands in for the VM that
`main.sh register` normally prepares. Run controllers run in the pod's nested
Docker; each workflow step runs as a pod of its own on the runner's node,
created by the `steps` broker sidecar ([How workflows run](#how-workflows-run)).
A scaler parks idle runners (pod stopped, registration kept, woken again in
seconds) and wakes or adds runners when workflows queue.

| Component | Where | What |
|---|---|---|
| Runner image | [`Dockerfile`](Dockerfile), [`runner.sh`](runner.sh) | nested `dockerd`, SSM agent, ECS agent; `runner.sh` sources `main.sh` |
| Scaler image | [`scaler/`](scaler) (Go) | sizes the StatefulSet from StackGuardian's queue, parks, wakes and reaps runners; also ships the steps broker (`/sg-runner-steps`) |
| Helm chart | [`chart/sg-runner`](chart/sg-runner/README.md) | runner StatefulSet, scaler, credentials, optional NetworkPolicy and PDB |

Install, uninstall, runner sizes, Docker cleanup and every chart value are in
the [chart README](chart/sg-runner/README.md).

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

## How workflows run

The run controller is an ECS task in the runner pod's nested `dockerd`,
registered through ECS Anywhere as on a VM. The workflow steps it starts are
Kubernetes pods.

- **Step pods.** The `steps` broker sidecar (`/sg-runner-steps`, from the
  scaler image) takes the run controller's requests over a unix socket and
  creates one pod per step on the runner's node. The step pod has no service
  account token, runs unprivileged with `RuntimeDefault` seccomp, and
  requests the CPU and memory the step asks for. Env and registry credentials
  go into Secrets that are deleted as soon as the step finishes.
- **Shared workspace.** The run controller and the step pods mount the same
  workspace volume (a PVC per runner pod). Each step pod mounts only its own
  run's directory; mounts from outside it (host paths, `docker.sock`) are
  refused.
- **Guard.** `dockerd` runs with an authorization plugin served by the broker.
  It refuses to create step containers (labeled `wfrunId`) in the nested
  Docker, so user code can't run next to the privileged `dockerd`. A run
  controller without step broker support gets that refusal for each step.
  The guard fails closed: while it doesn't answer, `dockerd` refuses every
  call.
- **Exit codes 11 and 12** (approval required, completed early) end the step
  pod as `Completed`. The step runs under a small wrapper that leaves the real
  code in the termination message for the broker. If the broker can't read
  the image's config, the step runs unwrapped and those codes show as
  `Error`.
- **Images** are pulled by the kubelet and cached per node. StackGuardian's
  step images are amd64 only.

The runner advertises its size to StackGuardian as its workflow capacity.
The chart passes `SG_TASK_CPU_LIMIT` and `SG_TASK_MEMORY_LIMIT_MIB` from `runner.size`
(or `runner.advertise` with `custom`) and sets `SG_DOCKERD_OVERHEAD_MIB` to 0,
since steps don't run in `dockerd`. `runner.sh ecs-agent` then sets
`ECS_RESERVED_MEMORY` to node memory minus the advertised memory and pins the
agent to as many CPUs as it advertises. The agent reads the reservation as a
`uint16` of MiB, so the runner refuses to start when it would exceed 65535.
The runner pod itself only requests what its run controllers need; step pods
use the advertised capacity, so each runner takes a node of its own.

Step pods carry `app.kubernetes.io/component=step`, so `kubectl logs` shows
their output; finished ones stay for `runner.steps.finishedTTL`, labeled with
their outcome. More in the
[chart README](chart/sg-runner/README.md#how-a-runner-runs-workflows).

## Parking: stopping and scaling down

Scaling down doesn't deregister a runner, it **parks** it: the pod stops, the
registration and Docker image cache stay on its PVCs, and scaling back up
wakes the same runner without registering again.

| Measured | Time to ECS `ACTIVE` + connected |
|---|---|
| Wake a parked runner (`kubectl scale` up) | **8s**, same container instance, image cache kept |
| Fresh runner (new ordinal, full registration) | 20s, plus image pulls on its first workflow |
| Park a runner (`kubectl scale` down, idle) | 14s |

Every shutdown (scale-down, restart, rollout, eviction) parks the same way.
The `ecs-agent` container's `preStop` hook (`runner.sh drain`):

1. sets the runner `DRAINING` through StackGuardian's `runner_status` API (the same call
   `sg-runner-autoscaler` uses), so no new workflows are placed on it, and
   leaves a marker on the state PVC;
2. waits for running workflows, up to `terminationGracePeriodSeconds` (1h).
   `dockerd` and `ssm-agent` wait for the hook (`wait-drained`), so workflows
   keep their Docker daemon and the agent keeps rotating credentials.

On wake the runner sets itself `ACTIVE` again once the agent has reconnected,
only if the marker is there. A runner that was already `DRAINING` when it
parked, drained on purpose from the StackGuardian UI or by an autoscaler, stays drained.

A parked runner shows in StackGuardian as registered but disconnected and `DRAINING`;
it still counts against the runner group's `MaxNumberOfRunners`. Pods are
managed in parallel (`podManagementPolicy: Parallel`), so several runners park
or wake at once.

Status changes use the runner group's node token, the same credential the
runner registers with; no extra key is needed. The runner never calls ECS
itself: a customer's runner has no ECS permissions.

Runners are deregistered when they're reaped (parked longer than
`SCALER_PARK_TTL`) and on `helm uninstall`, which deregisters every runner,
awake or parked, from its state PVC and deletes the PVCs (see the
[chart README](chart/sg-runner/README.md#uninstall)).

## Autoscaling

The chart's scaler Deployment ([`chart/sg-runner`](chart/sg-runner/README.md))
runs the scaler ([`scaler/`](scaler), Go), a loop that owns the runner
StatefulSet's `replicas`. Every `SCALER_INTERVAL` (15s) it reads the runner
group from StackGuardian with the node token (`?getActiveWorkflows=true`) and:

| Rule | When | Action |
|---|---|---|
| Scale out | workflows queued and no awake runner fully idle | +1 runner: wakes a parked one, or registers a new one |
| Headroom (optional) | less than `SCALER_HEADROOM_PCT` of awake runners' CPU or memory free (0 = off, the default) | +1 runner, kept as a warm spare |
| Scale in | nothing queued, highest awake runner idle for `SCALER_IDLE_SECONDS` (60), the rest still keeps the headroom | park it (-1) |
| Stuck queue | workflows queued while an awake runner sits fully idle for `SCALER_STUCK_SECONDS` (180) | warn, ignore the queue (it needs more than a runner pod offers) |
| Reap | runner parked longer than `SCALER_PARK_TTL` (12h) | Job deregisters it from its PVC, then its PVCs are deleted |

Replicas stay within `SCALER_MIN` (≥ 1: StackGuardian pauses workflows without
an `ACTIVE` runner) and the lower of `SCALER_MAX` (`scaler.max`) and the runner
group's `MaxNumberOfRunners`. Runners map to ordinals by hostname (the pod's
FQDN). While an awake runner hasn't connected yet, the scaler waits instead of
deciding again, for up to `SCALER_SETTLE_TIMEOUT` (300s); a runner that still
isn't connected by then (failed registration, crash loop) is left out of the
decision, reported and set `DRAINING`, so one broken pod can't freeze scaling.

A parked runner that StackGuardian still shows `ACTIVE` (its pod went away without the
`preStop` drain: node loss, force delete) is set `DRAINING` too. Drains the
scaler does are marked on the runner's state PVC
(`sg-runner.stackguardian.io/drained-by-scaler`), and the scaler sets the
runner `ACTIVE` again once it's awake and connected. Drains from anyone else
(the StackGuardian UI, an autoscaler) leave no mark and stick.

Two replicas share a leader Lease (`<statefulset>-scaler`;
`SCALER_LEADER_ELECT=false` turns it off). The idle, stuck and settle timers
are kept as annotations on the StatefulSet, so a restart or a new leader
carries on where the last one stopped. On StackGuardian or Kubernetes API errors a loop
decides nothing and the next one waits longer (doubling, up to 5 minutes).
Decisions and warnings (`StuckQueue`, `RunnerNotConnected`, `SGUnreachable`,
`ReapFailed`, ...) are Events on the StatefulSet; Prometheus metrics
(`sg_runner_scaler_*`), `/healthz` and `/readyz` are served on port 9090.

Its Role covers this StatefulSet, its scale and annotations, PVCs, reap Jobs,
Events and its Lease, plus read access to pods and events in the namespace
for the cluster autoscaler placeholders (`scaler.nudge.enabled`, on by
default). Runner pods have no Kubernetes API access except the `steps`
container. Reap Job pods take extra labels, pull secrets, node selector and
tolerations from `SCALER_REAP_POD_LABELS`, `SCALER_REAP_IMAGE_PULL_SECRETS`,
`SCALER_REAP_NODE_SELECTOR` and `SCALER_REAP_TOLERATIONS`; the chart sets them
from the runner's values.

Rotating the node token in an `existingSecret` needs a restart of the scaler
and the runners; see the chart README's Notes.

## Known limitations

- **Privileged pod.** The nested Docker daemon needs it; clusters that enforce
  restricted Pod Security reject it. Workflow steps run as unprivileged pods.
- **Network isolation is opt-in.** Workflow containers can resolve cluster DNS
  and reach the Kubernetes API. The chart's NetworkPolicy
  (`networkPolicy.enabled`, with the cluster's CIDRs) blocks cluster ranges and
  the metadata endpoint for runner, step and reap pods; it needs a CNI that
  enforces NetworkPolicy and is untested on one. The steps broker needs
  the Kubernetes API: allow its endpoint in `networkPolicy.extraEgress`.
- **Workspaces are scratch.** `/var/tmp/workspace` is a PVC per runner pod
  (`<pod>-workspace`, generic ephemeral, `runner.steps.workspace.size`,
  default 20Gi), deleted with the pod: a run doesn't survive a pod restart.
- **Task cgroup limits off** (`ECS_ENABLE_TASK_CPU_MEM_LIMIT=false`): the agent
  can't create task cgroups from its container. Run controllers share the
  `dockerd` container's limits; steps get their own pod requests and limits.
- **No proxy support.** The `--http-proxy` path isn't wired up.
- **amd64 nodes** for StackGuardian's step images; arm64 only with preloaded
  images (`runner.steps.step.imagePullPolicy: IfNotPresent`).
- **Workflows bigger than a runner never run.** A workflow reserves
  0.5 vCPU / 512 MiB plus its own resource setting; if that exceeds what the
  runner advertises, it stays queued. The scaler detects it and warns instead
  of waking every runner, but the runner size must cover the largest workflow.
- **Restarting a single runner pauses new workflows** for the ~10s it takes:
  StackGuardian pauses workflows submitted while no runner is `ACTIVE`, and a
  StatefulSet stops the old pod before starting the new one.
  `podDisruptionBudget.enabled` keeps node drains from evicting the last
  runner; for rollouts use `scaler.min=2` where that matters. Such workflows
  may need to be resumed by hand.
- **Long parking is untested.** Waking is tested after seconds, not hours or
  days.
- **Hard kills.** A pod killed without its `preStop` hook (node loss, force
  delete) parks as `ACTIVE` but disconnected; the scaler sets it `DRAINING` and
  reactivates it on wake. End-to-end testing of this against StackGuardian is
  not complete. If someone also drains such a runner from the StackGuardian UI
  while the scaler's mark is on it, the scaler reactivates it on wake.
- **The Go scaler.** End-to-end testing against StackGuardian is not
  complete.
- **StackGuardian credentials in the pod.** The credentials Secret is mounted
  (read-only) into `ecs-agent` for the status changes, and into the scaler.
- **Pods end in `Error`.** The containers exit non-zero on SIGTERM after a
  clean drain; cosmetic.
- **SSM Run Command** lands in the `ssm-agent` container (it has the Docker
  CLI and socket), not on a host.
- `ecs-init` is bypassed: agent defaults it sets are copied in `runner.sh` and
  may drift with new agent releases.

## Development

```sh
make lint test                       # repo root: shellcheck + bats (main.sh, k8s/runner.sh)
(cd k8s/scaler && go vet ./... && go test ./...)
helm lint --strict k8s/chart/sg-runner --set credentials.existingSecret=x
```

`make build` and `make build-scaler` in `k8s/` build the runner and scaler
images (`:dev`).

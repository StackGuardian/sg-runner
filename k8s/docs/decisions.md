# Decisions and background

## Facts the design rests on

From StackGuardian's own code (the backend and the run controller), the ECS
agent's source, and tests on QA. Re-check them if behavior seems off.

- **ECS Anywhere is the dispatch path.** SG places each workflow run as an
  ECS task (the "run controller") on a runner group's container instances,
  matched by instance attributes (organization, runner group, and for newer
  runner groups a signature). The run controller then starts the workflow
  steps itself through `/var/run/docker.sock`. Both layers need a Docker API,
  which is why a runner pod runs a nested `dockerd`.
- **Workflow size reaches ECS.** The run task is started with a task-level
  CPU/memory override of 512 + the workflow's own setting each (default
  512 / 1024, so 1024 CPU units / 1536 MiB in total). ECS reserves that
  against what the runner advertises.
- **Step limits.** The run controller starts steps with a hard memory limit
  (the workflow's memory setting) but only a CPU *weight*, so a step can use
  all of the pod's CPU.
- **No `ACTIVE` runner means paused, not queued.** When ECS can't place a run
  and no runner in the group is `ACTIVE` and connected, SG sets the run
  queued and the workflow paused, without retrying. A separate handler is
  meant to resume it. With an `ACTIVE` connected runner, SG retries.
- **`QueuedWorkflowsCount`** (runner group API) counts the group's workflows
  whose latest active run is queued. `EcsTaskFailAgentCount` is the
  equivalent the shared-runner autoscaler uses.
- **The node token is enough.** With the runner group's node token: read the
  group with `?getActiveWorkflows=true`, `POST .../runner_status/`
  (`DRAINING`/`ACTIVE`, really changes the ECS instance), and deregister. The
  group GET response contains secrets (the group's runner token): never log
  it.
- **The ECS agent sizes itself from the node**: CPU =
  `runtime.NumCPU() × 1024` (affinity, not cgroup quota), memory = `MemTotal`
  minus `ECS_RESERVED_MEMORY` (parsed as `uint16`: values above 65535 silently
  become 0).
- **The runner's instance role can't change its own ECS status** on QA (the
  policy names the cluster ARN, the action is authorized against the
  container-instance ARN). Irrelevant now: status changes go through SG.

- **The run controller's mounts.** Its ECS task bind-mounts the host's
  `/var/run/docker.sock` and `/var/tmp/workspace` at the same paths
  (`WORKSPACES_DIR=/var/tmp/workspace`), runs as root, and its image is set by
  tag, not digest. Steps get `.../wfruns/<run>/shared-workspace` at
  `/mnt/sg_workspace` plus the AWS credentials files at their own paths.
  Verified with `docker inspect` on QA.
- **ECS keeps a runner's registered size.** `registeredResources` are fixed
  at the container instance's first registration; an agent restart with a
  different size changes nothing (seen on QA: 2048/3840 stayed after the agent
  advertised 4096/6144). The runner therefore re-registers when its size
  changes (see below).
- **Exit codes 11 and 12 are signals.** A step exits 11 when it needs approval
  and 12 to finish the run early; the run controller acts on the code.

## Decisions

| Decision | Why | Rejected alternatives |
|---|---|---|
| One pod = one runner host; nested `dockerd` | ECS agent and run controller both need a Docker API; real clusters run containerd | Host Docker socket (not on modern clusters) |
| Native steps: steps as pods through a step broker in the runner pod; run controller unchanged otherwise ([native-steps.md](native-steps.md)) | User code out of the privileged pod; Kubernetes owns scheduling and images; the broker, not the controller, holds cluster credentials and builds the pod spec | A Docker API shim in front of `dockerd` (emulates Docker semantics, works with an unmodified controller); the controller calling the Kubernetes API itself; a new run controller (12k lines of logic to fork) |
| Broker client duck-types docker-py in the controller | `main()` stays unchanged apart from one line; the existing exit-code and status logic and its tests keep working | A `StepRunner` refactor of `main()` |
| Native-only on Kubernetes, with a `dockerd` authorization plugin refusing step containers | The Kubernetes runner isn't released, so non-native mode has no users; one mode halves the code and tests; the guard makes an old controller fail clearly instead of running steps in a `dockerd` sized for controllers | Keep non-native as a fallback (old controllers, arm64 emulation, host mounts) |
| Broker as a native sidecar | Starts before `dockerd` (the guard must answer first) and stops after the main containers (no drain-marker tricks) | Regular container with preStop wait and SIGTERM handling (the first version) |
| A run on the broker never falls back to Docker | A silent fallback would run user code in a `dockerd` sized for controllers only | Fallback with a warning |
| Workspace as a generic ephemeral PVC, steps pinned to the runner's node | Same lifetime as the emptyDir it replaces; toggling is a normal rollout; works on any storage class | volumeClaimTemplate (immutable, needs scaler/teardown changes); hostPath; RWX (later option) |
| Wrap each step (`sg-step-wrapper`, PID 1 init) so exits 11/12 end `Completed`, with the real code in the termination message; read ENTRYPOINT/CMD from the image's registry config; run unwrapped if that fails | SG's step images signal approval and early finish with exit codes, which Kubernetes shows as failures; the controller keeps reading 11/12 unchanged | Delete finished pods ~10s after the result is read (the first version: hid the pods, lost `kubectl logs`); an outcome label only; step images signalling without exit codes (SG-wide change) |
| Keep finished step pods 1h with an outcome label; delete their Secrets at once | Debuggable with `kubectl`; credentials don't outlive the step | Keep Secrets with the pod |
| Re-register an idle runner whose advertised size changed (`runner.reregisterOnResize`) | ECS never updates a registered size; without it a resized runner keeps its old capacity silently | Document a manual reap; refuse to start (blocks rollouts) |
| Broker can create/delete Secrets but not read or list them | The node token is a Secret in the same namespace | Secret list for garbage collection |
| Run the ECS agent binary directly, not `ecs-init` | `ecs-init` needs systemd | Running the installer (systemd/packages) |
| Advertise the `dockerd` container's limits | Workflows run inside it; otherwise ECS over-places | Pod limits alone (the agent ignores cgroup quotas) |
| Never call ECS from the runner | Customers' runners have no ECS permissions; SG's `runner_status` API does it with SG's | Direct `UpdateContainerInstancesState` (also denied on QA) |
| Secret holds only the node token; organization, runner group and API URL are chart values in a ConfigMap | They aren't secret; visible and editable like any config, and secret stores only need the token | Everything in one Secret (the prototype's first layout) |
| Scaler nudges the cluster autoscaler with a volume-less placeholder Job | GKE's autoscaler won't add a node for a pod with a PD (template node lacks `topology.gke.io/zone`, and GKE refuses that node label); a placeholder with the runner's requests and affinity gets the node, which the runner then takes | Node pool label (rejected by GKE); always-on spare nodes (idle cost) |
| Node token only, no SG API key | Every call the runner and scaler make works with it; one credential instead of two | A separate org API key (tried, removed) |
| Park instead of deregister on scale-down | Waking takes 8s vs 20s for a fresh registration, keeps the image cache, avoids SSM/ECS churn | Stateless Deployment that re-registers every time |
| StatefulSet + PVC per runner | Stable identity and cache per runner; parking needs it | Deployment with pod-deletion-cost (stateless) |
| Drain on every shutdown, reactivate only the pod's own drain | No new work during restarts/rollouts; drains from the SG UI or an autoscaler must stick | Drain only on scale-down; reactivate unconditionally |
| Scaler as its own small loop, not KEDA | Must choose which runner to park (highest ordinal, only when idle), reap parked runners, detect stuck queues | KEDA / HPA (replica count only, extra install) |
| Scale out on queue only when no awake runner is fully idle | With an idle runner, SG's next retry places queued work there if it fits; a same-size runner can't help if it doesn't | Scale out on any queue (overshoots, wakes every runner for an oversized workflow) |
| Headroom optional, default off | Waking is fast enough; a warm spare is a cost choice | Always-on 80% reserved target (kept one idle runner per workload) |
| Timers: park after 60s idle, deregister after 12h parked | Fast scale-in, cheap re-wake through the working day | 300s / 24h (earlier defaults) |
| Go for the scaler | client-go, Events, metrics, leader election, small static non-root image; path to an operator | Python (team's main language), bash (prototype) |
| Helm chart, Helm 3 and 4 compatible | Customers install with either | Raw manifests (removed) |
| Size presets (`small`/`medium`/`large`/`custom`) | Customers pick runner size at install | Fixed size |
| Prune the image cache only under disk pressure | Docker filters images by creation time, not last use; age-only pruning empties the wake-up cache | Age-only pruning; no pruning |
| Trivy gates the scaler image only | Scaler findings are actionable; runner findings mostly come from bundled upstream binaries | Gating both (permanently red CI) |

## The scaler's rules (summary)

Every 15s, from SG's runner group data and the StatefulSet:

- max = min(`scaler.max`, `MaxNumberOfRunners`); min ≥ 1.
- **Settling**: an awake runner not yet connected blocks decisions for up to
  300s; after that it's reported (`RunnerNotConnected`), drained, and ignored.
- **Stuck**: work queued while an awake runner is fully idle for 180s →
  `StuckQueue`, the queue is ignored for scaling.
- **Out**: queue with no fully idle awake runner, or free capacity below
  `headroomPct` → +1 (wakes a parked runner if its PVC exists).
- **In**: no queue (or stuck), highest awake runner idle ≥ 60s, rest keeps the
  headroom → −1 (parks it).
- **Parked but `ACTIVE`** (hard kill) → `DRAINING` + PVC mark; reactivated on
  wake only if marked.
- **Reap**: parked ≥ 12h → Job runs `runner.sh reap` against the PVC
  (deregisters), then both PVCs are deleted.
- Timers persist as StatefulSet annotations; errors back off up to 5 minutes;
  Events and `sg_runner_scaler_*` metrics report everything.

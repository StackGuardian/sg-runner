# Proposal: workflow steps as native pods

Status: proposal, nothing built. Goal: the run controller stays an ECS task on
the runner (ECS Anywhere and registration are unchanged), but each workflow
step runs as its own Kubernetes pod instead of a container in the runner
pod's nested `dockerd`.

## What the run controller does with Docker today

From `src/run_controller/external.py` in sg-run-controller (docker-py 6.0.1).
All of it is in one place, the step loop of `main()` (about 250 lines):

| Call | Purpose |
|---|---|
| `docker.from_env()` | Talks to `/var/run/docker.sock`, bind-mounted into the controller task |
| `client.login(...)` | SG's ECR (token from SG's account) or a private registry (secret from the run) |
| `client.images.pull(...)` | Only for `:latest` tags |
| `client.containers.run(detach=True, ...)` | Image, name, env list, labels `orgId`/`wfrunId`, `privileged=False`, `cpu_shares` (CPU weight only, no limit), `mem_limit` = `mem_reservation`, `network="bridge"`, optional `command`, bind mounts |
| `container.logs(stream=True, follow=True)` | A thread relays every line into the controller's log (and from there to the storage backend) |
| `container.reload()` / `.status` / `.attrs["State"]["ExitCode"]` | Polled every 1.5 s |
| `container.wait(timeout=10)` | Exit code: 0 ok, 11 approval required, 12 finish the run early, other = errored |
| `container.kill(SIGTERM)`, wait 30 s, `kill(SIGKILL)` | Cancel and step timeout |

Bind mounts of a step:

- the run's shared workspace `${WORKSPACES_DIR}<org><run>/shared-workspace`
  (`WORKSPACES_DIR=/var/tmp/workspace`) at `/mnt/sg_workspace`: the cloned
  repo, artifacts, run facts, spilled env payloads, the step's
  `aws_credentials` / `aws_config` files;
- the step template's `mountPoints` (shape not confirmed; see open questions).

Containers are never removed, and the workspace is `chmod -R 777`'d before
each step (steps may run as any UID).

The controller and the step see the same paths because the controller's task
mounts the host's `/var/tmp/workspace` at the same path, and "host" is the
runner pod. That shared directory is the one hard problem: everything else
maps one to one onto the pod API.

## Options

### A. A new run controller (separate repo)

Not worth it. The controller is ~12k lines of business logic (approvals,
policies, VCS, interpolation, artifacts, drift, run facts, error surfacing,
the status rules in `fail_clean`), and Docker is ~250 of them. A fork would
drift from every controller release. And the image the ECS task runs is set
by SG's task definition: a separate controller only runs if SG points the
runner group at it.

### B. The controller talks to the Kubernetes API

A `KubernetesStepRunner` next to the Docker code. Needs a controller release,
puts cluster credentials in the controller (it has to get them through a
file, since we don't control the task definition's env), and every
Kubernetes policy decision (pod spec, security context, GC) lives in Python
in another team's repo.

### C. A step broker on the runner pod (recommended)

A new Go component in the runner pod, `sg-runner-steps`, owns everything
Kubernetes: it builds step pods from a fixed template, holds the RBAC, and
cleans up. The controller only asks it to run a step. Two fronts on the same
core:

1. **Docker API front (phase 1, no controller change).** The broker listens
   on the `/var/run/docker.sock` that the controller task mounts; the real
   `dockerd` moves to another socket that only the ECS agent uses. It
   implements the dozen endpoints listed above for containers labeled
   `wfrunId`, and proxies everything else to `dockerd` unchanged (the run
   analyzer and any other socket user keep working). Works with the
   official controller image today.
2. **Native front (phase 2, small controller change).** A `StepRunner`
   interface in the controller with today's Docker code as one
   implementation and a broker client as the other, selected by the
   broker's presence. Explicit semantics (pod phases, image pull errors as
   real errors) instead of emulating Docker. The Docker front is then
   retired.

The controller never holds cluster credentials, the pod spec is ours and
reviewable, and the broker shares code with the scaler (`internal/kube`).

## How the broker runs a step

| Docker call | Broker |
|---|---|
| `login` | Remembers the credentials per registry for this run's next step |
| `images.pull` | No-op; `:latest` gets `imagePullPolicy: Always` |
| `containers.create` + `start` | Secret `<pod>-env` with the env (the run payload and credentials stay out of the pod spec; `envFrom`), Secret with a `dockerconfigjson` if it logged in, then the pod |
| `logs(follow)` | Pod log stream, framed as Docker's multiplexed stream |
| `inspect` / `status` | Pod phase → `created` / `running` / `exited`; container exit code |
| `wait` | Watch until the container terminated |
| `kill(SIGTERM)` / `kill(SIGKILL)` | Delete the pod with a 30 s / 0 s grace period |
| (no remove) | Broker deletes step pods and their Secrets once finished and logs are read, and on startup any whose controller container is gone |

Step pod template:

- **Resources:** requests CPU `userJobCpu / 1024`, memory `userJobMemory` Mi,
  memory limit = request, no CPU limit (as today: a weight, not a cap).
- **Workspace:** the runner's `/var/tmp/workspace` moves onto a per-runner
  workspace PVC (RWO). The step mounts the same PVC with
  `subPath: <run>/shared-workspace` at `/mnt/sg_workspace`. RWO allows
  several pods **on the same node**, so step pods get a required pod
  affinity to their runner's node. Bind sources outside the workspace are
  refused with a clear error.
- **Security:** `privileged: false`, no service account token, Docker's
  default capability set (Pod Security "baseline", what steps get today),
  `runAsUser` left to the image.
- **Network:** NetworkPolicy for step pods: egress to the internet; no
  Kubernetes API, no other pods, no `169.254.169.254`.
- **Labels:** org, workflow, run, step, runner. Logs and events become
  `kubectl`-visible per run, so the `workflow-logs` sidecar isn't needed for
  steps.

## What it changes

- **Security:** user code leaves the privileged runner pod. Today a step that
  escapes its container lands in a privileged pod; as a pod it lands in an
  unprivileged one. The run controller (SG's code, not the user's) is all that
  stays in `dockerd`.
- **Visibility:** steps are pods: logs, events, metrics, OOM kills, image pull
  errors, all native.
- **Images:** pulled by the kubelet, cached per node, shared by every runner
  on it; the docker PVC shrinks to controller images.
- **Resources:** each step gets its requests enforced by the scheduler,
  instead of every workflow sharing one runner pod.
- **Not yet elastic:** in phase 1 steps run on their runner's node, so a
  runner still needs a node sized for its workflows. The runner advertises
  capacity to ECS as today (ECS reserves `512 + workflow size` per run, so
  admission control stays); the runner pod itself only requests what the
  ECS agent, `dockerd` and controllers need.

## Phase 3: steps anywhere

With an RWX storage class (Filestore, EFS, NFS) for the workspace, the node
affinity goes away: step pods schedule on any node and the cluster autoscaler
adds nodes for them directly (no persistent disk on a step pod, so no nudge).
Runners shrink to controller-only pods. Costs: an RWX storage prerequisite
and NFS performance for Terraform's provider directories. Optional, per
install.

## Effort (one engineer, rough)

| Work | Estimate |
|---|---|
| Phase 0: broker in pure proxy mode logging every Docker API call during real runs; confirms the exact surface docker-py 6.0.1 uses and the task's mounts | 2–3 days |
| Broker core: pod and Secret builder, log streaming, wait/exit codes, cancel, pull secrets, GC, events → errors, tests | 2–3 weeks |
| Docker API front: the endpoints, multiplexed log framing, version negotiation, passthrough | 1 week |
| Runner pod and chart: `dockerd` socket move (`DOCKER_HOST` for the ECS agent), workspace PVC, broker container, RBAC, step NetworkPolicy, capacity advertising | 1 week |
| GKE validation with real workflows (below) | 1 week |
| **Phase 1 total** | **~5–6 weeks** |
| Phase 2: `StepRunner` in sg-run-controller and a native broker API; then an SG controller release | 1–2 weeks plus their review and release |
| Phase 3: RWX workspace option | ~1 week plus storage testing |

A new controller (option A) would be months, then permanent upkeep.

## Validation list

Terraform plan/apply, approval (exit 11), early finish (12), failure, cancel
mid-step, step timeout, SG ECR image, private registry image, `:latest`,
command override, large payload (env spill files), drift and policy
discovery runs, resume after approval, runner park while a step runs, broker
restart mid-step, runner pod deleted mid-step (orphan GC), log volume beyond
kubelet rotation (10 MiB).

## Open questions (not confirmed)

- **The controller task's mounts.** That it mounts the host's
  `/var/run/docker.sock` and `/var/tmp/workspace` at the same paths is
  inferred from `docker.from_env()`, `WORKSPACES_DIR` and the step mounts
  seen in workflow logs, not read from the task definition (it lives in SG's
  account). Phase 0 confirms it with `docker inspect`.
- **Step `mountPoints`.** Passed straight to `docker.types.Mount(type="bind")`;
  where they come from and whether any template uses a host path outside the
  workspace wasn't found in the controller repo.
- **Anything a step reads from the ECS environment** (task metadata,
  `169.254.170.2` credentials). Steps get AWS credentials as files, but a
  custom step image could rely on more.
- **Who runs the official controller image.** Phase 2 needs SG to ship the
  `StepRunner` change in its controller release; worth raising with the
  controller's owners before building phase 1 too far.

# Native steps: workflow steps as pods

Opt-in (`runner.nativeSteps.enabled`, default off). The run controller stays
an ECS task in the runner pod's nested `dockerd`, registered through ECS
Anywhere as before; only the workflow **steps** it starts become Kubernetes
pods. Needs a run controller with the step broker client (sg-run-controller,
`external_runner/step_broker.py`); a controller without it keeps running steps
in `dockerd`.

Contract: [steps-api.md](steps-api.md). Tests: [testing.md](testing.md)
(plan 8, and the kind smoke's native-steps stage).

## Why

- **Security.** User code leaves the privileged runner pod. A step that
  escapes its container lands in an unprivileged pod (no service account
  token, `RuntimeDefault` seccomp, no privilege), not next to a privileged
  `dockerd`.
- **Visibility.** Steps are pods: scheduling, image pulls, OOM kills and exit
  codes show up as Kubernetes state and events.
- **Images.** Pulled by the kubelet and cached per node, shared by every
  runner on it.
- **Resources.** Each step requests its own CPU and memory; the runner pod
  only reserves what its run controllers need.

## How it works

```
runner pod (StatefulSet)                               step pods (same node)
┌─────────────────────────────────────────────┐
│ dockerd ── run controller (ECS task)        │        ┌──────────────────────┐
│              │ step_client(): unix socket   │        │ step (user image)    │
│              ▼                              │ create │  /mnt/sg_workspace = │
│ steps (broker, Go) ── Kubernetes API ───────┼───────▶│  subPath of the      │
│                                             │        │  runner's workspace  │
│ workspace: ephemeral PVC <pod>-workspace ◀──┼────────┤  PVC                 │
│ ecs-agent, ssm-agent                        │        └──────────────────────┘
└─────────────────────────────────────────────┘
```

- The run controller mounts the runner's `/var/tmp/workspace` (verified with
  `docker inspect`), so it finds the broker's socket at
  `/var/tmp/workspace/.sg-runner/steps.sock`: an emptyDir nested inside the
  workspace mount, shared with the broker container. Steps mount only their
  own run's directory and can't reach it.
- The controller's `step_client()` returns docker-py's client or, when that
  socket exists, a broker client that duck-types the docker-py calls
  `external.py` makes (`login`, `images.pull`, `containers.run` and the
  container's `status`, `attrs`, `reload`, `wait`, `kill`, `logs`). `main()`
  is unchanged apart from that one line. The choice is made once per run; a
  run on the broker **never falls back to Docker**: a broker failure fails the
  step with a clear error.
- The broker (`sg-runner-steps`, in the scaler image) builds the step pod
  itself, from a fixed template:
  - env in a Secret (`envFrom`), registry credentials in a pull Secret;
  - the step's command as `args` (the image's ENTRYPOINT is kept, as with
    Docker), `$` escaped so the kubelet never expands `$(VAR)`;
  - CPU request = Docker CPU shares / 1024, no CPU limit (Docker's shares were
    a weight); memory request = limit;
  - each Docker bind mount becomes a `subPath` of the runner's workspace PVC;
    sources outside the run's own directory are rejected;
  - pinned to the runner's node (required node affinity), owned by the runner
    pod, no service account token, `RuntimeDefault` seccomp, unprivileged.
- **Finished steps are deleted** (pod and Secrets) 10s (`FINISHED_GRACE`)
  after the controller has read the result and its log stream has closed.
  Their output is in SG's run log; `kubectl logs` works only while a step
  runs. The broker keeps the result in memory for an hour. Steps nobody read
  (controller gone) are deleted after `FINISHED_TTL`.
- **Drain.** The broker's preStop waits for the runner's drain marker and it
  ignores SIGTERM until then: run controllers keep their steps running through
  a runner shutdown.
- **RBAC.** The runner's ServiceAccount can create, read and delete pods, read
  pod logs, and create and delete Secrets. It can't read or list Secrets (the
  node token is one) or exec into pods. The token is mounted in the broker
  container only.

## Sizing: one runner per node

The runner pod requests only what its run controllers need
(`runner.nativeSteps.controllerResources`, roughly 512 Mi per concurrent run).
The ECS agent advertises `runner.nativeSteps.advertise` (whole CPUs, memory)
instead: that's what SG places workflows against, and the step pods consume
it. Nothing reserves that capacity on the node, so the supported layout is one
runner per node (required anti-affinity, rendered by the chart) with
`advertise` ≤ node allocatable − runner pod − DaemonSets.

ECS keeps the CPU and memory a runner registered with. When `advertise` (or
the runner size) changes, the pod rolls, and its register step compares what
SG has registered with what the agent will advertise: an idle runner
deregisters and registers again with the new size (new runner ID, same image
cache); one with runs placed on it keeps the old size and logs a warning
(`runner.reregisterOnResize`, default on).

## Workspace

A generic ephemeral PVC (`<pod>-workspace`, RWO), created and deleted with the
runner pod, like the emptyDir it replaces; step pods mount it through
`subPath`. RWO allows several pods on the same node, which is why steps are
pinned there. Turning native steps on or off is a normal rollout.

Later option: an RWX storage class, so steps can schedule on any node and the
cluster autoscaler adds nodes for steps (no PD on step pods, no nudge). Costs
an RWX prerequisite (Filestore, EFS, NFS) and slower small-file I/O.

## Known behaviour and limits

- **Steps that exit non-zero show as `Failed` / `Error`**, including SG's
  signal codes 11 (approval required) and 12 (finish the run early).
  Kubernetes sets the phase from the exit code and nothing can patch it.
  Mitigated by deleting finished steps ~10s after their result is read.
  Monitoring on failed pods must exclude `app.kubernetes.io/component=step`.
  Real fixes, later: a wrapper in the step pod that maps 11/12 to 0 and
  reports the code through the termination message (needs each image's
  ENTRYPOINT/CMD from the registry), or step images signalling approval and
  early finish without exit codes (an SG-wide contract change).
- **Architecture.** SG's step images are amd64-only. Nested Docker could run
  them on arm64 under emulation; the kubelet refuses to pull them. On arm64
  nodes they must be preloaded with `runner.nativeSteps.step.imagePullPolicy:
  IfNotPresent` (OrbStack testing); production runs on amd64 nodes.
- **Log bursts.** A step writing tens of MiB within a second can lose lines
  when the kubelet rotates its log file (10 MiB by default) faster than the
  stream reads it. At ~1 MiB/s nothing is lost. Raise the kubelet's
  `containerLogMaxSize` if steps log heavily.
- **Pending time** (scheduling, image pull) isn't part of the step's timeout
  in the run controller; the broker bounds it (`schedulingTimeout`,
  `startTimeout`).
- **NetworkPolicy.** With `networkPolicy.enabled`, the policy also covers
  step pods, but its cluster-CIDR exclusion blocks the broker's access to the
  Kubernetes API. Workaround: allow the API endpoint through
  `networkPolicy.extraEgress` (opens it to the whole runner pod).
- **Mount checks are lexical.** A symlink inside one run's directory pointing
  into another run's would be followed by the kubelet. Mount sources are
  chosen by the run controller, not users.
- **Node autoscaling.** The scaler's nudge placeholder copies the runner pod's
  requests, i.e. controller-sized, so on GKE a new node may be too small for
  the steps. Not handled yet.

## Testing a controller that isn't released yet

SG's task definition picks the run controller image. Until the broker client
ships in it, it's tested by overlaying the client onto the official image tag
inside the runner's `dockerd`, with the ECS agent set to
`ECS_IMAGE_PULL_BEHAVIOR=prefer-cached` (`runner.ecsAgent.extraEnv`). Steps in
[testing.md](testing.md), plan 8.

## Open

- Drift and policy-discovery runs (their workspace directories differ from a
  normal run's): not tested yet.
- ValidatingAdmissionPolicy limiting what the runner's ServiceAccount may
  create (the namespace is privileged for `dockerd`).
- RWX workspace; nudge sized for steps; NetworkPolicy value for the broker's
  API access; GKE validation (PD attach, multi-node).

# Native steps: workflow steps as pods

How the Kubernetes runner runs workflows: the run controller stays an ECS task
in the runner pod's nested `dockerd`, registered through ECS Anywhere as
before; the workflow **steps** it starts are Kubernetes pods. This is the only
mode of the Kubernetes runner.

## Requirements

- **A run controller with the step broker client** (sg-run-controller,
  `external_runner/step_broker.py`). SG's task definition picks the
  controller, so SG must release it before Kubernetes runners can run
  workflows. A controller without it is refused by the runner's guard (below):
  its steps fail with a clear error instead of running in `dockerd`.
- **Kubernetes 1.29 or newer** (the broker is a native sidecar).
- **amd64 nodes** for SG's step images (amd64-only); arm64 only with
  preloaded images (`runner.steps.step.imagePullPolicy: IfNotPresent`).
- **One runner per node** (rendered as a required anti-affinity; see Sizing).
- **No host bind mounts in steps.** Step `mountPoints` whose source is
  outside the run's workspace (host paths, `docker.sock`) are rejected. Not
  yet known whether any SG step template uses them (open item).

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
  - started through `sg-step-wrapper` (below): the container's command is
    the wrapper followed by the image's ENTRYPOINT and the step's command (or
    the image's CMD), as Docker would run them; `$` is escaped so the kubelet
    never expands `$(VAR)`;
  - CPU request = Docker CPU shares / 1024, no CPU limit (Docker's shares were
    a weight); memory request = limit;
  - each Docker bind mount becomes a `subPath` of the runner's workspace PVC;
    sources outside the run's own directory are rejected;
  - pinned to the runner's node (required node affinity), owned by the runner
    pod, no service account token, `RuntimeDefault` seccomp, unprivileged.
- **Exit codes 11 and 12 end `Completed`.** SG's step images exit 11 to ask
  for approval and 12 to finish the run early; Kubernetes would show both as
  `Failed` / `Error`. An init container copies `sg-step-wrapper` (a static
  binary from the broker's image) into the step pod, and the step runs under
  it as PID 1: it forwards signals, reaps zombies (like `docker run --init`),
  and turns 11 and 12 into exit 0 with the real code in the container's
  termination message, which the broker reports to the controller. Other
  codes pass through, so real failures still show `Error`. To build that
  command the broker reads the image's ENTRYPOINT and CMD from its registry
  (manifest and config only, never layers; the step's own registry
  credentials; cached 10 min). If that fails the step runs unwrapped, exactly
  as before (annotation `sg-runner.stackguardian.io/wrapped: "false"` with the
  reason), and 11/12 show as `Error` for that step only.
- **Finished steps stay** for `finishedTTL` (1h), labelled with their outcome
  (`sg-runner.stackguardian.io/outcome`: `succeeded`, `approval-required`,
  `completed-early`, `failed`, `stopped`), then are deleted. Their env and
  pull Secrets (the run's credentials) are deleted as soon as they finish.
  `kubectl get pods -l app.kubernetes.io/component=step -L
  sg-runner.stackguardian.io/outcome` shows what happened.
- **Guard.** `dockerd` runs with an authorization plugin served by the
  broker (`--authorization-plugin=sg-steps-guard`, socket shared through an
  emptyDir at `/run/docker/plugins`). It refuses to create any container
  labelled `wfrunId`, which is how the run controller labels steps, so a
  controller without the broker client can't run user code in `dockerd`; its
  step fails with "This runner runs workflow steps as Kubernetes pods and needs
  a run controller with native step support". Everything else (the ECS agent
  starting run controllers, pulls, logs) passes. Fail closed: while the
  guard doesn't answer, `dockerd` refuses every call, so a crash-looping broker
  blocks the runner.
- **Lifecycle.** The broker is a native sidecar (init container with
  `restartPolicy: Always`): it starts and passes its health check (both
  sockets) before `dockerd` and the agents start, and stops only after they
  have exited, so a draining runner's controllers keep their steps running to
  the end.
- **RBAC.** The runner's ServiceAccount can create, read, patch (the outcome
  label) and delete pods, read pod logs, and create and delete Secrets. It can't read or list Secrets (the
  node token is one) or exec into pods. The token is mounted in the broker
  container only.

## Sizing: one runner per node

The runner pod requests only what its run controllers need
(derived from `runner.size`, or `runner.controllerResources` with `custom`;
roughly 512 Mi per concurrent run). The ECS agent advertises the size's
workflow capacity (`small` 2 CPU / 4 GiB, `medium` 4 / 8, `large` 8 / 16, or
`runner.advertise` with `custom`)
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

- **Step processes aren't PID 1.** The wrapper is; a step that relied on
  PID 1's signal semantics (e.g. ignoring SIGTERM) now stops on SIGTERM, as
  under `docker run --init`.
- **Unwrapped steps** (registry config not readable, e.g. a registry the
  broker can't reach) still show `Failed` / `Error` for exit 11/12; their
  outcome label is right regardless. Monitoring on failed pods should use the
  outcome label for step pods.
- **Registry access.** The broker calls each step image's registry once per
  10 minutes per image (HTTPS); the first step with a new image waits up to
  20s for that lookup.
- **Architecture.** SG's step images are amd64-only. Nested Docker could run
  them on arm64 under emulation; the kubelet refuses to pull them. On arm64
  nodes they must be preloaded with `runner.steps.step.imagePullPolicy:
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

- Step templates with host `mountPoints`: check SG's templates for any;
  they can't run on Kubernetes runners.
- Drift and policy-discovery runs (their workspace directories differ from a
  normal run's): not tested yet.
- ValidatingAdmissionPolicy limiting what the runner's ServiceAccount may
  create (the namespace is privileged for `dockerd`).
- RWX workspace; nudge sized for steps; NetworkPolicy value for the broker's
  API access; GKE validation (PD attach, multi-node).

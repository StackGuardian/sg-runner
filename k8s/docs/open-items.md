# Open items and caveats

## Do first

1. **End-to-end run of the chart with the Go scaler on QA.** Nothing since
   the Go rewrite has talked to real StackGuardian. Plan:
   [testing.md](testing.md#1-end-to-end-chart--go-scaler-on-qa).
2. **Rotate the leaked QA credentials.** During development a QA runner
   group's node token and an SG API key were printed into a session
   transcript. Rotate both. The API key is no longer used anywhere; remove it
   from `k8s/.env` too. After rotating the node token, restart the scaler: it
   reads credentials once at start.
3. **Port the error-report recursion fix to `main`** (`25f059c`). On VM
   runners, an unreachable SG API makes `err()` → `update_runner_group` →
   `api_call` → `err()` loop until bash overflows its stack, sending one
   authenticated request per round (857 in 36s in the CI smoke test). The fix
   is self-contained (`main.sh` + `test/unit/update_runner_group.bats`) and
   deliberately left off `main` for now.

## Needs testing (details in [testing.md](testing.md))

- **Long parking**: wake a runner after 12–24h parked. The whole parking
  design depends on SSM and the ECS agent reconnecting after a long
  disconnect; only seconds have been tested.
- **Hard kills against real SG**: the scaler's "drain a parked runner that's
  still `ACTIVE`, reactivate on wake" path (3.2) is only tested with a fake SG.
- **Do paused workflows resume?** SG pauses (doesn't queue) workflows
  submitted while no runner is `ACTIVE` and connected. Restarting a single
  runner leaves a ~10s window. Unknown whether SG resumes them when a runner
  reconnects.
- **Queue latency**: how long a queued workflow waits for SG's retry after a
  runner wakes. Decides whether headroom should default on.
- **Overshoot under real load** with the Go scaler (the shell version once
  woke one runner too many; the queue rule was fixed afterwards).
- **NetworkPolicy on an enforcing CNI** (Calico, Cilium, VPC CNI policy mode).
- **CI on GitHub**: the gha build cache, QEMU arm64 build time, running
  trivy-action twice in one job, the job summary size, kind on ubuntu-latest.

## Decisions or input needed

- **Largest workflow size customers configure** (workflow CPU/memory
  settings). The runner size must exceed it plus 0.5 vCPU / 512 MiB, or that
  workflow stays queued forever. Product data, not something the code can tell.
- **Default runner size** for the chart (`small` = 2 vCPU / 4Gi today).
- **Minimum runners**: `scaler.min=1` leaves the restart window above;
  `scaler.min=2` avoids it at the cost of an idle pod.
- **Where images are published** (and multi-arch push in CI). Nothing pushes
  today.
- **Push and review the branch.** It includes `main.sh` changes that affect VM
  runners (private-IP detection, the recursion fix); reviewers should know.

## Follow-up work

| Item | Notes |
|---|---|
| Run without `privileged` (3.6) | Spike done on OrbStack: capabilities-only works but isn't a real security gain; rootless Docker doesn't fit; user namespaces need containerd 2.x or CRI-O (OrbStack's cri-dockerd can't); Sysbox untested. Next: a real cluster with `hostUsers: false` and `procMount: Unmasked`. |
| Docker past 27.5.1 | The runner image's remaining fixable CRITICALs (Trivy) are Go stdlib/grpc in the bundled static Docker binaries. A newer major raises the minimum Docker API version; check the ECS agent still works. |
| Rollouts without the restart window | Scaler-managed rollout (`updateStrategy: OnDelete`, wake a spare first, then restart outdated pods one by one). Only needed if paused workflows don't resume. |
| Mixed runner sizes | Two StatefulSets (e.g. small and large) in one runner group; ECS places each workflow where it fits. The scaler would need to know about pools and wake a large runner on a stuck queue. |
| Operator / `RunnerPool` CRD | Natural next step for the Go scaler (kubebuilder) if this becomes a product. |
| Proxy support | `main.sh`'s `--http-proxy` path isn't wired into the pod (env on the agents, Docker daemon proxy config). |
| `sg-net` bypass (known) | Workflow containers run on Docker's default bridge, so `main.sh`'s `DOCKER-USER` DROP rules for `sg-net` never apply to them, on VMs too. Known and parked. |
| Native steps: SG release of the run controller change | sg-run-controller branch `feat/k8s-run-controller` (`step_broker.py` + one line in `external.py`). Until it ships, native steps run only with an overlaid controller image (testing.md plan 8). |
| Native steps: drift and policy-discovery runs | Not tested; their workspace directories (`shared-workspace-drift`, `-discovery`) differ from a normal run's. |
| Native steps: NetworkPolicy and the broker | The policy's cluster-CIDR exclusion blocks the broker's API access; needs a dedicated value instead of the `extraEgress` workaround. |
| Native steps: GKE | Nudge placeholder sized for steps (`advertise`), PD attach and node pinning on multi-node clusters, NetworkPolicy enforcement. |
| Native steps: hardening | ValidatingAdmissionPolicy on what the runner's ServiceAccount may create; symlink-safe mount checks. |
| Native steps: RWX workspace | Steps on any node, autoscaler adds nodes for steps; needs an RWX storage class. |
| Scaler doc for operators | Metrics reference, Event reasons, alert suggestions (StuckQueue, RunnerNotConnected, SGUnreachable). |

## Caveats (current behavior to be aware of)

- **GKE's cluster autoscaler never adds a node for a runner pod** (its PVCs,
  new or bound, make the template node fail `NodeAffinity`; a plain pod of
  the same size scales up). Verified on GKE 1.36 with throwaway pods. GKE
  refuses the `topology.gke.io/zone` node label that would fix the template.
  The scaler's nudge (placeholder Job without volumes) works around it,
  verified on GKE for a woken parked runner (about 70 s from nudge to
  scheduled) and a new one. The placeholder is released at
  `TriggeredScaleUp`, so the runner takes the node as soon as it joins.

- **Workflow logs sidecar (opt-in)** follows step containers only: the run
  controller relays every step line to its own output (verified on QA), so
  following it too doubled the stream. Its own setup lines (health check,
  storage, VCS checkout, policies) aren't in the sidecar. Output lands in the
  cluster's log pipeline, secrets included.

- **`helm uninstall` waits for running workflows** (the hook parks runners
  first). Helm's default `--timeout` of 5m can expire first; the Job keeps
  going, and running `helm uninstall` again restarts it.
- **A runner already deregistered elsewhere** (SG UI) but with its PVC still
  there makes the uninstall hook fail on that runner; delete its PVCs by hand
  and uninstall again. Not tested against real SG yet.
- **`helm uninstall --no-hooks`**, or deleting the namespace first, skips the
  cleanup: runners stay registered with nothing left to deregister them.

- **Privileged pod.** `dockerd` runs privileged; clusters enforcing
  restricted Pod Security reject it. The namespace needs
  `pod-security.kubernetes.io/enforce=privileged`; the chart doesn't create it.
- **Workflows larger than a runner never run.** The scaler emits
  `StuckQueue` and stops reacting to that queue instead of waking every
  runner, but it can't fix it.
- **Single-runner restarts pause new workflows** for ~10s (see above).
  `podDisruptionBudget.enabled` protects against node drains only.
- **Parked runners count against `MaxNumberOfRunners`** and show in SG's UI
  as disconnected and `DRAINING`.
- **Credentials in pods.** The node token is mounted into `ecs-agent` (status
  changes) and the scaler. The scaler reads it once; restart after rotating.
- **A scaler-drained runner later drained from the SG UI** while the
  scaler's mark is on its PVC gets reactivated on wake by mistake.
- **No per-task CPU/memory cgroups** (`ECS_ENABLE_TASK_CPU_MEM_LIMIT=false`);
  the `dockerd` container's limits cap all workflows together. Step memory is
  still hard-limited by the run controller; step CPU is only a weight.
- **Workspaces are scratch** (`emptyDir`, 20Gi default limit): a run doesn't
  survive its pod, and exceeding the limit evicts the pod.
- **`ecs-init` is bypassed**: its agent defaults are copied into `runner.sh`
  and may drift with new ECS agent releases. Agent and SSM versions are
  pinned in `Dockerfile`.
- **Pods end in `Error`** after a clean drain (non-zero exit on SIGTERM);
  cosmetic.
- **SSM Run Command** would land in the `ssm-agent` container, not on a host.
  Unknown whether SG uses it.
- **CI's `k8s.yml` is path-filtered**: if made a required check, PRs that
  don't touch `k8s/**` or `main.sh` leave it pending.

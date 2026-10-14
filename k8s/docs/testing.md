# Testing: verified, not verified, and how to test

## Verified

| What | How | Result |
|---|---|---|
| Runner pod registers and runs workflows | QA, OrbStack Kubernetes (arm64) | Registration, SSM activation, ECS agent connects, run controller + steps run nested; amd64 workflow images run on arm64 via emulation |
| Sizing | QA, ECS `describe-container-instances` | Advertised 2048 CPU units / 3840 MiB for a 2 vCPU / 4Gi `dockerd` limit (was the whole node: 12288 / 12015) |
| Wake / fresh / park timings | QA, `kubectl scale` | Wake **8s** (same container instance), fresh registration 20s (+ ~10s image pull on first workflow), park 14s (idle) |
| Drain through SG (`runner_status`) | QA, ECS status observed | `ACTIVE` → `DRAINING` on shutdown → `ACTIVE` after restart; node token accepted and really changes ECS state |
| External drain survives restart | Unit test (stubs) | Already-`DRAINING` runner stays drained after a restart |
| Shell scaler: scale out, park, reap | QA with real workflows | 1→3 under load, parked to 1 after idle, reaped after TTL; SG left clean |
| Stuck queue, settle timeout, headroom | Simulation of the shell scaler; Go unit tests | Oversized workflow → no scale-out, warning; broken runner ignored after 300s; headroom 0 → 2 runners, 20% → 3 |
| Go scaler | `go test -race`, fake clientset, fake SG; OrbStack smoke with pause pods | Coverage `decide` 97%; leader failover keeps timers; back-off on SG outage; no token in logs/errors/Events |
| Chart | `helm lint --strict`, kubeconform (k8s 1.37), schema rejections, server-side dry run, kind install | Helm 3.22 and 4.3 |
| Docker prune | Privileged container with short timers | Fresh containers survive, old ones removed, running containers and their images kept |
| Recursion fix | bats (counts curl calls), runner image against an unreachable API | One attempt + one report, exit 1 in <1s |
| `make nuke` with parked runners (old Makefile flow, before the uninstall hook) | QA | Woke 2 parked runners, deregistered all 3, no SSM/ECS leftovers |
| Workflow logs sidecar | Runner image with nested dockerd, look-alike containers; then a real workflow on GKE (QA) | Concurrent runs tagged apart, stderr included, no replay after a sidecar restart, restarts not duplicated, JSON mode, exits at once on SIGTERM. On QA: run controllers carry `com.amazonaws.ecs.task-arn`, steps mount `.../wfruns/<run>/...`, and the run controller relays every step line (hence steps only) |
| `helm uninstall` hook | Go unit tests (fake clientset); kind smoke with a fake API | Stops the scaler, parks, reaps every state PVC (never-registered ones succeed), deletes PVCs and Jobs; a failed reap keeps that runner's PVCs and fails the hook |
| Native steps: broker on a real cluster | OrbStack, `curl` over the socket from `dockerd` | Exit codes 0/1/11/12, `$(VAR)` stays literal, workspace writes visible, mounts outside the run rejected, bad image fails at once, Unschedulable after the timeout, stop keeps the step's exit code (143), 503,329/503,329 log lines at ~1 MiB/s across rotations, runner SA can't read Secrets or exec |
| Native steps: controller client | OrbStack, client inside the controller image in nested `dockerd`, real broker | Both observation paths (exited / wait), failing exit, bad image → `AdminJobException`, cancel via `stop_container` (graceful and SIGKILL), `DockerLogger` relays step output |
| Native-only runner + guard | QA, OrbStack (chart 0.9.0) | Broker as native sidecar, `dockerd` started with `--authorization-plugin=sg-steps-guard`; overlaid controller: step pod Completed / `completed-early`, run COMPLETED; SG's official controller: step create refused with the guard's message (403), run ERRORED, nothing in `dockerd`, no step pod |
| Native steps end to end | QA, OrbStack, QA controller image + broker client overlaid ([plan 8](#8-native-steps-end-to-end-runbook)) | Scenarios 1–9, 11, 12, 14 pass: plan/apply, approval + resume, exit 12 (output of a 1s step kept), exit 3, cancel, step timeout, bad image, command override/env/workspace, two concurrent runs isolated, drain mid-step, step pods gone with their runner pod, nothing runs in `dockerd`. Scenario 15 (step wrapper): approval and exit-12 step pods `Completed`, outcome `approval-required` / `completed-early`, wrapped (image config read from SG's private ECR with the controller's login), Secrets deleted, pods kept |

## Not verified

- Go scaler against real SG (all of it).
- Scaler nudge's release at `TriggeredScaleUp` (chart 0.7.0) on GKE; the
  earlier release-when-running version was verified there.
- `helm uninstall` hook against real SG: deregistering awake and parked
  runners, a runner with a running workflow (waits, then deregisters), a
  runner already deregistered from the SG UI (expected: the reap fails, the
  hook fails and keeps its PVCs).
- Waking after a long park (hours/days).
- Hard kill → scaler drain → reactivate, against real SG/ECS.
- Whether SG resumes workflows it paused while no runner was `ACTIVE`.
- Queue wait after a wake (SG retry interval).
- Whether SG ever lists two container instances for one runner pod (the Go
  scaler tolerates it).
- NetworkPolicy enforcement.
- Unprivileged operation on a real cluster.
- CI on GitHub.
- Multi-node clusters: `local-path`-style node-local PVCs pin a runner to its
  node; a lost node keeps the StatefulSet pod `Terminating` until the node is
  removed.
- Native steps: drift and policy-discovery runs (separate workspace dirs);
  NetworkPolicy for step pods; persistent-disk attach and node pinning on a
  multi-node cluster; node autoscaling sized for steps (the nudge copies only
  the runner's requests).
- Native steps with the real (released) run controller: tested only with the
  broker client overlaid on the QA image.

## Test plans

### 1. End-to-end: chart + Go scaler on QA

```sh
cd k8s && make build build-scaler && make secret up
helm --kube-context orbstack -n sg-runner upgrade sg-runner chart/sg-runner --reuse-values \
  --set scaler.idleSeconds=30 --set scaler.parkTTL=90
kubectl -n sg-runner logs -f deploy/sg-runner-scaler | jq -c 'select(.msg != "loop")'
kubectl -n sg-runner get events -w --field-selector involvedObject.name=sg-runner
kubectl -n sg-runner port-forward deploy/sg-runner-scaler 9090 &
curl -s localhost:9090/metrics | grep '^sg_runner_scaler'
```

Trigger 2–3 workflows. Expect: `ScaledOut` without an extra idle runner
(headroom 0), `Parked` 30s after idle, `Woke` on the next workflow (~8s),
`Reaped` 90s after parking. End with `helm uninstall` (with a runner parked
and one awake) and check SG lists no runners for the group and no PVCs are
left.

### 2. Hard kill (3.2)

With at least two runners awake and idle:

```sh
kubectl -n sg-runner scale sts sg-runner --replicas=1
kubectl -n sg-runner delete pod sg-runner-1 --grace-period=0 --force
kubectl -n sg-runner get pvc state-sg-runner-1 -o jsonpath='{.metadata.annotations}'
```

Expect a `DrainedParkedRunner` event and the
`sg-runner.stackguardian.io/drained-by-scaler` annotation. Trigger a workflow
so it wakes: `Woke`, then `Reactivated`, annotation gone, runner `ACTIVE` in
SG.

### 3. Long parking

Default timers (park TTL 12h). Let the scaler park a runner, leave it
overnight, then trigger workflows so it wakes. Check: the register init
container says "Already registered", the ECS agent restores from its
checkpoint and connects, the runner is `ACTIVE`, a workflow runs on it. If it
fails, the park TTL must stay below the point where reconnecting breaks.

### 4. Restart window

With one runner: `kubectl -n sg-runner delete pod sg-runner-0` and submit a
workflow during the ~10s gap. Does SG resume it once the runner reconnects,
or does it stay paused? Decides between `scaler.min=2`, a PDB only, or
scaler-managed rollouts.

### 5. Queue latency and overshoot

Trigger N workflows that each fill a runner. Measure from submission to
placement on a freshly woken runner, and check the scaler never wakes more
runners than queued work needs. Repeat with `scaler.headroomPct=20`.

### 6. NetworkPolicy

On a cluster with an enforcing CNI, `networkPolicy.enabled=true` with the
cluster's pod/service/node CIDRs. From a workflow step: the Kubernetes API,
another pod and `169.254.169.254` must be unreachable; SG, AWS, VCS and
registries reachable.

### 7. Unprivileged `dockerd`

Real cluster with containerd 2.x or CRI-O. Try `hostUsers: false` with
`procMount: Unmasked` (and Sysbox if installable). The OrbStack spike's
checklist: dockerd starts, nested container with egress, `sg-net` + iptables
rules, `route_localnet`, the 169.254.170.2 → 127.0.0.1:51679 DNAT, a
container mounting docker.sock.

### 8. Native steps end to end (runbook)

Steps run as pods through the step broker
([native-steps.md](native-steps.md), [steps-api.md](steps-api.md)). Until SG
ships a run controller with the broker client, it is tested by overlaying the
client onto the official controller image inside the runner's `dockerd`.

**Setup** (OrbStack, a throwaway runner group in `.env`, nothing else
registered in it):

1. Values file (OrbStack):

   ```yaml
   runner:
     size: custom
     advertise: { cpu: 4, memory: 6144Mi }
     controllerResources:
       limits: { cpu: "2", memory: 2Gi }
     steps:
       schedulingTimeout: 2m
       startTimeout: 5m
       step:
         imagePullPolicy: IfNotPresent   # arm64 only: preloaded amd64 images
     ecsAgent:
       extraEnv:
         - { name: ECS_IMAGE_PULL_BEHAVIOR, value: prefer-cached }
         - { name: ECS_DISABLE_IMAGE_CLEANUP, value: "true" }
     dockerd:
       extraEnv:
         - { name: SG_PRUNE_INTERVAL_SECONDS, value: "0" }
   ```

2. `make build build-scaler && make secret up HELM_ARGS="-f native.yaml"`.
   A runner registered with another size registers again on its own when
   idle (`runner.reregisterOnResize`).
3. Run one workflow so the official controller image is pulled into `dockerd`
   (its `.Config.Image` must be a tag, not a digest). Its steps are refused by
   the guard (scenario 16), which is expected. Then overlay: copy
   `src/run_controller` out of the image, add `external_runner/step_broker.py`
   and the one-line `step_client(...)` change to its `external.py`, and
   commit it under the same tag:

   ```sh
   IMG=<official controller image:tag>
   kubectl -n sg-runner exec sg-runner-0 -c dockerd -- docker tag $IMG $IMG-orig
   tar -C <patched dir> -cf - run_controller | kubectl -n sg-runner exec -i sg-runner-0 -c dockerd -- \
     sh -c "c=\$(docker create $IMG-orig) && docker cp - \$c:/opt/stackguardian/src/ && docker commit \$c $IMG && docker rm \$c"
   ```

   Patch the image's own code, not sg-run-controller's main: the deployed
   controller may differ from main. The overlay lives on the `docker` PVC and
   survives pod restarts, not `make nuke` (`docker save` it first).
4. On arm64 (OrbStack), SG's step images are amd64-only: the kubelet refuses
   to pull them, but runs them under emulation when they are already local.
   Copy each one from `dockerd` into the host image store after a first run:
   `kubectl exec ... -c dockerd -- docker save <image> | docker load`.
5. Two workflows on the runner group: the Terraform one, and the same with a
   custom pre-plan step using public `alpine:3.20` with a command override
   (multi-arch, nothing to preload).

**Watch** during every run:

```sh
kubectl -n sg-runner get pods -l app.kubernetes.io/component=step -L sg-runner.stackguardian.io/outcome -w
kubectl -n sg-runner logs sg-runner-0 -c steps -f
# must stay empty: steps never fall back to dockerd
kubectl -n sg-runner exec sg-runner-0 -c dockerd -- docker ps -a --filter label=wfrunId
```

**Scenarios**

| # | Do | Expect |
|---|---|---|
| 1 | Terraform plan + apply | Each step a pod on the runner's node; run log in the SG UI; COMPLETED |
| 2 | Plan → approval → approve | Plan pod exits 11, run `APPROVAL_REQUIRED`; a new controller resumes (cache restored into the workspace PVC) and runs apply |
| 3 | Alpine: `sh -c 'echo hi; exit 12'` | COMPLETED, later steps skipped, `hi` in the run log even for a 1s step |
| 4 | Alpine: `sh -c 'echo boom >&2; exit 3'` | ERRORED, "failed with exit code: 3", `boom` in the log |
| 5 | Cancel in the UI during a step | Step pod deleted with a 30s grace, run CANCELLED (not ERRORED) |
| 6 | Alpine: `sleep 600`, step timeout 1m | "exceeded timeout of 1.0m", pod stopped, ERRORED, Terraform not run |
| 7 | Alpine image `alpine:does-not-exist` | ERRORED within seconds: "failed to run: ErrImagePull … manifest unknown" |
| 8 | Alpine: `sh -c 'echo "payload=${#SG_WORKFLOW_RUN_PAYLOAD}"; ls /mnt/sg_workspace; id'` | Payload length > 0, workspace listing (`user`, `artifacts`, …), image's own user; COMPLETED |
| 9 | Two **different** workflows at once (SG queues runs of one workflow) | Two controllers and two step pods at once; in one pod, `/var/tmp/workspace` holds only its own run's paths |
| 10 | Drift or policy discovery run | `shared-workspace-drift` / `-discovery` mounts work (not run yet) |
| 11 | `kubectl delete pod sg-runner-0` while a step runs | The broker stays up through the drain, the step finishes in its pod, the run completes, then the runner restarts |
| 12 | Runner pod deleted | Its step pods are deleted with it (ownerReference) |
| 14 | Every run | `docker ps -a --filter label=wfrunId` in `dockerd` stays empty |
| 16 | Any run with the official controller (no broker client) | The step fails at once: "This runner runs workflow steps as Kubernetes pods and needs a run controller with native step support"; nothing runs in `dockerd` |
| 15 | Approval (exit 11) and exit 12 runs | Step pods `Completed`, outcome `approval-required` / `completed-early`, annotation `wrapped: "true"`; env Secret gone, pod kept for `finishedTTL` |

**Known behaviour**: exit 11 and 12 end `Completed` through the step wrapper
(see native-steps.md); a step whose image config the broker can't read runs
unwrapped and shows `Error` for them. A step writing tens of MiB within a
second can lose lines to kubelet log rotation (raise `containerLogMaxSize`).

## Automated checks

```sh
make lint test                                        # shellcheck + bats (176 tests)
(cd k8s/scaler && go vet ./... && go test -race ./...)
helm lint --strict k8s/chart/sg-runner --set credentials.existingSecret=x
.github/scripts/chart-check.sh                        # needs kubeconform on PATH
.github/scripts/kind-smoke.sh run                     # kind cluster, fake API; uses its own kubeconfig; includes the native-steps broker stage
CONTROLLER_REPO=<sg-run-controller checkout> .github/scripts/kind-smoke.sh run   # + the controller client's live test (unit/test_step_broker_live.py) in the broker test pod
```

Trivy (local, last run): the scaler image has 0 CRITICAL; the runner image's
fixable CRITICALs are all in the bundled Docker 27.5.1 binaries.

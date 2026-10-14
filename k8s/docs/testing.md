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

## Automated checks

```sh
make lint test                                        # shellcheck + bats (176 tests)
(cd k8s/scaler && go vet ./... && go test -race ./...)
helm lint --strict k8s/chart/sg-runner --set credentials.existingSecret=x
.github/scripts/chart-check.sh                        # needs kubeconform on PATH
.github/scripts/kind-smoke.sh run                     # kind cluster, fake API; uses its own kubeconfig
```

Trivy (local, last run): the scaler image has 0 CRITICAL; the runner image's
fixable CRITICALs are all in the bundled Docker 27.5.1 binaries.

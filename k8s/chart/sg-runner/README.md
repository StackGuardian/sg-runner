# sg-runner Helm chart (prototype)

> **Status: prototype.** Not supported, not documented for customers.

Runs StackGuardian Private Runners on Kubernetes. Each replica of the runner
StatefulSet is one registered runner; a scaler Deployment wakes, parks and reaps
runners from the runner group's queue. Design and known gaps: [`k8s/README.md`](../../README.md).

## Install

Only the runner group's node token is secret. The organization, runner group
and API URL are plain values (`sg.*`); the chart keeps them in a ConfigMap.

```sh
kubectl create namespace sg-runner
kubectl -n sg-runner create secret generic sg-runner-credentials \
  --from-literal=SG_NODE_TOKEN=...
helm -n sg-runner upgrade --install sg-runner ./k8s/chart/sg-runner \
  --set sg.organization=<org> --set sg.runnerGroup=<runner group> \
  --set credentials.existingSecret=sg-runner-credentials --set runner.size=medium
```

Or let the chart create the Secret too (`credentials.create=true`,
`credentials.nodeToken=...`), with `--create-namespace`: one `helm install`.
The token then also lives in Helm's release record; prefer `existingSecret`
(e.g. filled by External Secrets) outside testing.

Runner pods are privileged (nested Docker). On clusters that enforce Pod
Security, label the namespace first; the chart doesn't create or label it:

```sh
kubectl label namespace sg-runner pod-security.kubernetes.io/enforce=privileged
```

From `k8s/`, `make secret up` does the same against OrbStack.

Release `sg-runner` names the StatefulSet `sg-runner`, so pods `sg-runner-N` and
PVCs `state-sg-runner-N` / `docker-sg-runner-N`. Other release names get
`<release>-sg-runner`. Don't rename an existing install: the runners
registered from the old PVCs would be orphaned.

## Uninstall

```sh
helm -n sg-runner uninstall sg-runner --timeout 30m
kubectl delete namespace sg-runner   # if nothing else lives there
```

`helm uninstall` removes the runners from StackGuardian too. A pre-delete hook
Job (`<release>-uninstall`, the scaler image in `teardown` mode):

1. stops the scaler,
2. parks every runner: each sets itself `DRAINING` and waits for its running
   workflows,
3. deregisters every runner, awake or parked, with a reap Job against its
   state PVC (`runner.sh reap`),
4. deletes the runners' PVCs, which `volumeClaimTemplates` keep out of the
   release.

Running workflows finish first, so give `--timeout` enough for them (Helm's
default is 5m; the Job itself gives up after `uninstall.activeDeadlineSeconds`,
by default `runner.terminationGracePeriodSeconds` + 15 minutes). If Helm times
out, the Job keeps going; running `helm uninstall` again restarts it, and
runners already deregistered are skipped.

If a runner can't be deregistered, the hook fails and keeps that runner's
PVCs, so nothing is orphaned; the release stays. Read
`kubectl -n sg-runner logs job/sg-runner-reap-<n>`, fix the cause, and
uninstall again.

To keep the runners registered instead (parked, PVCs kept, e.g. to reinstall
later): `helm uninstall --no-hooks`, or `uninstall.deregister=false`.

## Runner size

`runner.size` sizes the `dockerd` container, where workflows run. Its limits
are what the runner advertises: CPU = `limits.cpu`, memory = `limits.memory`
minus 256 MiB for dockerd.

| Size | Requests | Limits (advertised) | Default workflows |
|---|---|---|---|
| `small` | 1 CPU / 2Gi | 2 CPU / 4Gi | 2 |
| `medium` | 2 CPU / 4Gi | 4 CPU / 8Gi | 4 |
| `large` | 4 CPU / 8Gi | 8 CPU / 16Gi | 8 |
| `custom` | `runner.resources` | `runner.resources` (limits required) | |

A workflow reserves 0.5 vCPU / 512 MiB for its run controller plus its own
setting (default 0.5 vCPU / 1 GiB): 1 vCPU / 1.5 GiB by default. The runner
must be at least the largest workflow + 0.5 vCPU / 512 MiB, else that workflow
stays queued (the scaler warns).

## Workflow logs

Workflows run inside the nested Docker, so `kubectl logs` doesn't show them.
With `runner.workflowLogs.enabled=true`, a `workflow-logs` container streams
every workflow step's output, one tagged line per output line:

```
2026-10-14T01:20:04Z role=user run=8ebpl0g9j8j6 workflow=simple-ec2 | Initializing the backend...
```

Concurrent runs share the stream, interleaved by line; filter one out:

```sh
kubectl -n sg-runner logs sg-runner-0 -c workflow-logs -f | grep run=8ebpl0g9j8j6
```

- **Steps only**: run controllers (the ECS tasks) are skipped. They relay
  their steps' output for upload, so following them too would print every
  line twice; their own setup lines (health check, storage, VCS checkout) are
  in the SG UI.
- **`[SG_DEBUG]` lines** are dropped unless `runner.workflowLogs.debug=true`.
- **`format: json`** writes the same fields as one JSON object per line, for
  log backends to filter on.
- **Off by default for a reason**: once on stdout, the cluster's log pipeline
  collects the output too, and workflow output can contain secrets. The
  sidecar never reads container env (it holds the run's credentials).
- **Limits**: one stream per runner pod; a container started with `--rm` that
  exits within moments can be gone before it's followed; after a sidecar
  restart, running steps are followed from that point, not replayed.

## Values

| Key | Default | Description |
|---|---|---|
| `nameOverride` / `fullnameOverride` | `""` | Rename resources; `fullnameOverride` also renames the StatefulSet (max 52 chars). |
| `image.repository` / `.tag` / `.pullPolicy` | `sg-runner-k8s` / `dev` / `IfNotPresent` | Runner image; also used by reap Jobs. Empty tag = `appVersion`. |
| `imagePullSecrets` | `[]` | For runner, scaler and reap Job pods. |
| `sg.organization` / `sg.runnerGroup` | `""` | Required: the runner group to register into. In the `<release>-config` ConfigMap. |
| `sg.apiUrl` | `""` | StackGuardian API; empty = `https://api.app.stackguardian.io/api/v1`. |
| `credentials.existingSecret` | `""` | Secret with key `SG_NODE_TOKEN` (the runner group's node token); other keys are ignored. |
| `credentials.create` / `nodeToken` | `false` / `""` | Create that Secret from `nodeToken`. Exactly one of this or `existingSecret`. |
| `runner.replicas` | `1` | Only with `scaler.enabled=false`. |
| `runner.size` | `small` | `small`, `medium`, `large` or `custom`. |
| `runner.resources` | `{}` | dockerd resources for `size=custom`. |
| `runner.workspace.sizeLimit` | `20Gi` | `emptyDir` at `/var/tmp/workspace` on dockerd; exceeding it evicts the pod. |
| `runner.workspace.request` | `2Gi` | `ephemeral-storage` request on dockerd. Empty = none. |
| `runner.storage.state.size` / `.storageClassName` | `1Gi` / `""` | Runner identity PVC. Empty class = cluster default. |
| `runner.storage.docker.size` / `.storageClassName` | `20Gi` / `""` | Docker data root PVC (image cache). |
| `runner.dockerd.securityContext` | `{privileged: true}` | Nested Docker needs privileged for now. |
| `runner.workflowLogs.enabled` | `false` | `workflow-logs` sidecar: every workflow step's output on its stdout ([Workflow logs](#workflow-logs)). |
| `runner.workflowLogs.format` | `text` | `text` (tagged lines) or `json` (one object per line). |
| `runner.workflowLogs.debug` | `false` | Also stream `[SG_DEBUG]` lines. |
| `runner.workflowLogs.resources` | 10m / 32Mi, limit 256Mi | One `docker logs` process per running workflow step. |
| `runner.terminationGracePeriodSeconds` | `3600` | Max wait for running workflows when a runner stops. |
| `runner.podAnnotations` / `podLabels` / `nodeSelector` / `tolerations` / `affinity` | empty | Runner pod scheduling and metadata; `nodeSelector` and `tolerations` also apply to reap Jobs. |
| `scaler.enabled` | `true` | Scaler Deployment + RBAC. When on, the chart leaves the StatefulSet's `replicas` to it. |
| `scaler.image.repository` / `.tag` / `.pullPolicy` | `sg-runner-scaler` / `dev` / `IfNotPresent` | Scaler image (Go, distroless, non-root). Empty repository = the runner image. |
| `scaler.command` | `[]` | Empty = image entrypoint. |
| `scaler.replicas` | `1` | 2 is safe with leader election; > 1 without it fails rendering. |
| `scaler.leaderElection.enabled` | `true` | `SCALER_LEADER_ELECT`; lease `<statefulset>-scaler`. Also switches the rollout to `RollingUpdate`. |
| `scaler.min` | `1` | `SCALER_MIN`, ≥ 1 (SG pauses workflows without an ACTIVE runner). |
| `scaler.max` | `10` | `SCALER_MAX`, also capped by `MaxNumberOfRunners`. |
| `scaler.headroomPct` | `0` | `SCALER_HEADROOM_PCT`: capacity to keep free, 0 = off. |
| `scaler.idleSeconds` | `60` | `SCALER_IDLE_SECONDS`: idle time before parking. |
| `scaler.parkTTL` | `43200` | `SCALER_PARK_TTL`: parked time before reaping (deregister + delete PVCs). |
| `scaler.stuckSeconds` | `180` | `SCALER_STUCK_SECONDS`: queue + idle runner for this long = workflow too big. |
| `scaler.settleTimeout` | `300` | `SCALER_SETTLE_TIMEOUT`: wait for a runner to connect. |
| `scaler.interval` | `15` | `SCALER_INTERVAL`: seconds between decisions. |
| `scaler.nudge.enabled` / `.image` | `true` / `registry.k8s.io/pause:3.10` | `SCALER_NUDGE`: placeholder pods for runners the cluster autoscaler won't add a node for ([Notes](#notes)). |
| `scaler.nudge.cooldownSeconds` | `180` | `SCALER_NUDGE_COOLDOWN`: wait before asking again for a still-Pending runner; must outlast a node's boot. |
| `scaler.extraEnv` | `[]` | Extra env vars for the scaler. |
| `scaler.metrics.port` | `9090` | `SCALER_METRICS_ADDR=:<port>`, container port `metrics`, always on: `/metrics`, `/healthz` (liveness), `/readyz` (readiness). |
| `scaler.metrics.enabled` | `false` | Adds a metrics Service. |
| `scaler.metrics.serviceMonitor.enabled` / `.interval` / `.labels` | `false` / `30s` / `{}` | ServiceMonitor, only if `monitoring.coreos.com/v1` is served. |
| `scaler.resources` | 10m / 32Mi, limit 128Mi | |
| `scaler.podSecurityContext` | non-root 65532, `fsGroup` 65532, seccomp `RuntimeDefault` | `fsGroup` + file mode `0440` let the non-root scaler read the token and runner group. |
| `scaler.securityContext` | read-only root FS, no privilege escalation, drop `ALL` | |
| `scaler.podAnnotations` / `podLabels` / scheduling | empty | |
| `networkPolicy.enabled` | `false` | Egress isolation for runner pods; needs an enforcing CNI. |
| `networkPolicy.clusterCIDRs` | `[]` | Pod, service, node CIDRs (+ API endpoint). IPv4 ones required when enabled; IPv6 ones open IPv6 egress except them. |
| `networkPolicy.blockMetadata` | `true` | Deny `169.254.169.254/32`. |
| `networkPolicy.blockMetadataIPv6` | `false` | Deny `fd00:ec2::254/128`; only matters with IPv6 egress open. |
| `networkPolicy.allowClusterDNS` / `dnsSelector` | `true` / kube-system `k8s-app: kube-dns` | Allow DNS (53/UDP+TCP) to the cluster resolver. |
| `networkPolicy.extraEgress` | `[]` | Extra egress rules, as-is. |
| `podDisruptionBudget.enabled` / `minAvailable` | `false` / `1` | Keep drains from evicting the last runner; with one awake runner it blocks drains, so pair with `scaler.min: 2`. |
| `uninstall.deregister` | `true` | `helm uninstall` deregisters every runner and deletes their PVCs ([Uninstall](#uninstall)). |
| `uninstall.activeDeadlineSeconds` | empty | Upper bound for that cleanup; empty = `runner.terminationGracePeriodSeconds` + 900. |
| `uninstall.resources` | 10m / 32Mi | The cleanup Job's resources. |

## Notes

- **Replicas and the scaler.** With the scaler on, the chart leaves the
  StatefulSet's `replicas` out and Helm upgrades keep the live count. Turning
  the scaler on for an install that had it off removes the field Helm managed,
  which resets the StatefulSet to 1 replica: every other runner parks until the
  scaler wakes them for queued work.
- **Cluster autoscaler and runner volumes.** Some cluster autoscalers (GKE's,
  at least) never add a node for a pod with a persistent disk: a runner that
  needs a new node, new or waking, stays Pending with `NotTriggerScaleUp …
  didn't match Pod's node affinity/selector`, while the same pod without
  volumes scales up. With `scaler.nudge.enabled` (default), the scaler then
  starts a placeholder Job (`<statefulset>-nudge-<n>`, a `pause` container
  with the runner's requests, node selector, tolerations and affinity, no
  volumes). As soon as the autoscaler accepts it (`TriggeredScaleUp`), the
  scaler deletes it, and the runner takes the new node when it joins. A runner
  still Pending after `scaler.nudge.cooldownSeconds` gets another placeholder.
  Events `NudgingAutoscaler`, `NodeRequested`, `ScaleUpBlocked` (the
  autoscaler refused the placeholder too, e.g. the node pool is at its
  maximum, or repeated attempts didn't place the runner); metric
  `sg_runner_scaler_autoscaler_nudges_total`. It only acts after the
  autoscaler's refusal, so autoscalers that scale for runners themselves are
  left alone. Needs read access to pods and events in the namespace.
- **Storage values are fixed after install**: `volumeClaimTemplates` are
  immutable on a StatefulSet.
- **NetworkPolicy** covers runner pods, so workflow containers and agents
  alike (nested traffic leaves through the pod IP), and reap Job pods, which
  the scaler labels `app.kubernetes.io/component: reaper` (`SCALER_REAP_POD_LABELS`).
- **IPv6 gap.** The policy is IPv4: it allows no IPv6 egress unless IPv6
  CIDRs are listed in `clusterCIDRs` (dual stack), which opens `::/0` except
  those and, with `blockMetadataIPv6`, the AWS IPv6 metadata endpoint. Other
  clouds' IPv6 metadata addresses aren't covered.

## Migrating from the raw manifests

The old `k8s/manifests/` used `app: sg-runner` selectors. A StatefulSet's
selector is immutable and Helm won't adopt objects it didn't create, so the
chart can't take over in place. The PVCs carry the runner identities and keep
their names (`state-sg-runner-N`, `docker-sg-runner-N`) as long as the release
is named `sg-runner`, so:

1. Note the current replica count: `kubectl -n sg-runner get sts sg-runner`.
2. Delete the old scaler, then the StatefulSet (runners drain and park; PVCs
   stay): `kubectl -n sg-runner delete deploy/sg-runner-scaler sts/sg-runner`,
   and the old RBAC (`sa`, `role`, `rolebinding` named `sg-runner-scaler`).
3. Install the chart as release `sg-runner` in the same namespace with
   `credentials.existingSecret=sg-runner-credentials` plus `sg.organization`
   and `sg.runnerGroup` (`make up`). Only the Secret's `SG_NODE_TOKEN` key is
   used now.
4. The StatefulSet starts at 1 replica; the scaler wakes the other parked
   runners as work queues (or reaps them after `parkTTL`). Without the
   scaler, set `runner.replicas` to the noted count.

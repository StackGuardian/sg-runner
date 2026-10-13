# sg-runner Helm chart (prototype)

> **Status: prototype.** Not supported, not documented for customers.

Runs StackGuardian Private Runners on Kubernetes. Each replica of the runner
StatefulSet is one registered runner; a scaler Deployment wakes, parks and reaps
runners from the runner group's queue. Design and known gaps: [`k8s/README.md`](../../README.md).

## Install

The namespace must allow privileged pods (nested Docker). The chart doesn't
create it:

```sh
kubectl create namespace sg-runner
kubectl label namespace sg-runner pod-security.kubernetes.io/enforce=privileged
kubectl -n sg-runner create secret generic sg-runner-credentials \
  --from-literal=SG_NODE_TOKEN=... --from-literal=SG_ORGANIZATION=... \
  --from-literal=SG_RUNNER_GROUP=...
helm -n sg-runner upgrade --install sg-runner ./k8s/chart/sg-runner \
  --set credentials.existingSecret=sg-runner-credentials --set runner.size=medium
```

From `k8s/`, `make secret up` does the same against OrbStack.

Release `sg-runner` names the StatefulSet `sg-runner`, so pods `sg-runner-N` and
PVCs `state-sg-runner-N` / `docker-sg-runner-N`. Other release names get
`<release>-sg-runner`. Don't rename an existing install: the runners
registered from the old PVCs would be orphaned.

## Uninstall

PVCs come from `volumeClaimTemplates` and aren't part of the release:
`helm uninstall` parks every runner, and they stay registered in SG (counting
against `MaxNumberOfRunners`). Deregister them first (`make deregister`), then
delete the PVCs.

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

## Values

| Key | Default | Description |
|---|---|---|
| `nameOverride` / `fullnameOverride` | `""` | Rename resources; `fullnameOverride` also renames the StatefulSet (max 52 chars). |
| `image.repository` / `.tag` / `.pullPolicy` | `sg-runner-k8s` / `dev` / `IfNotPresent` | Runner image; also used by reap Jobs. Empty tag = `appVersion`. |
| `imagePullSecrets` | `[]` | For runner, scaler and reap Job pods. |
| `credentials.existingSecret` | `""` | Secret with `SG_NODE_TOKEN`, `SG_ORGANIZATION`, `SG_RUNNER_GROUP`, optional `SG_BASE_API`. |
| `credentials.create` | `false` | Create the Secret from `nodeToken`, `organization`, `runnerGroup`, `apiUrl`. Exactly one of this or `existingSecret`. |
| `runner.replicas` | `1` | Only with `scaler.enabled=false`. |
| `runner.size` | `small` | `small`, `medium`, `large` or `custom`. |
| `runner.resources` | `{}` | dockerd resources for `size=custom`. |
| `runner.workspace.sizeLimit` | `20Gi` | `emptyDir` at `/var/tmp/workspace` on dockerd; exceeding it evicts the pod. |
| `runner.workspace.request` | `2Gi` | `ephemeral-storage` request on dockerd. Empty = none. |
| `runner.storage.state.size` / `.storageClassName` | `1Gi` / `""` | Runner identity PVC. Empty class = cluster default. |
| `runner.storage.docker.size` / `.storageClassName` | `20Gi` / `""` | Docker data root PVC (image cache). |
| `runner.dockerd.securityContext` | `{privileged: true}` | Nested Docker needs privileged for now. |
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
| `scaler.extraEnv` | `[]` | Extra env vars for the scaler. |
| `scaler.metrics.port` | `9090` | `SCALER_METRICS_ADDR=:<port>`, container port `metrics`, always on: `/metrics`, `/healthz` (liveness), `/readyz` (readiness). |
| `scaler.metrics.enabled` | `false` | Adds a metrics Service. |
| `scaler.metrics.serviceMonitor.enabled` / `.interval` / `.labels` | `false` / `30s` / `{}` | ServiceMonitor, only if `monitoring.coreos.com/v1` is served. |
| `scaler.resources` | 10m / 32Mi, limit 128Mi | |
| `scaler.podSecurityContext` | non-root 65532, `fsGroup` 65532, seccomp `RuntimeDefault` | `fsGroup` + Secret mode `0440` let the non-root scaler read the credentials. |
| `scaler.securityContext` | read-only root FS, no privilege escalation, drop `ALL` | |
| `scaler.podAnnotations` / `podLabels` / scheduling | empty | |
| `networkPolicy.enabled` | `false` | Egress isolation for runner pods; needs an enforcing CNI. |
| `networkPolicy.clusterCIDRs` | `[]` | Pod, service, node CIDRs (+ API endpoint). IPv4 ones required when enabled; IPv6 ones open IPv6 egress except them. |
| `networkPolicy.blockMetadata` | `true` | Deny `169.254.169.254/32`. |
| `networkPolicy.blockMetadataIPv6` | `false` | Deny `fd00:ec2::254/128`; only matters with IPv6 egress open. |
| `networkPolicy.allowClusterDNS` / `dnsSelector` | `true` / kube-system `k8s-app: kube-dns` | Allow DNS (53/UDP+TCP) to the cluster resolver. |
| `networkPolicy.extraEgress` | `[]` | Extra egress rules, as-is. |
| `podDisruptionBudget.enabled` / `minAvailable` | `false` / `1` | Keep drains from evicting the last runner; with one awake runner it blocks drains, so pair with `scaler.min: 2`. |

## Notes

- **Replicas and the scaler.** With the scaler on, the chart leaves the
  StatefulSet's `replicas` out and Helm upgrades keep the live count. Turning
  the scaler on for an install that had it off removes the field Helm managed,
  which resets the StatefulSet to 1 replica: every other runner parks until the
  scaler wakes them for queued work.
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
   `credentials.existingSecret=sg-runner-credentials` (`make up`).
4. The StatefulSet starts at 1 replica; the scaler wakes the other parked
   runners as work queues (or reaps them after `parkTTL`). Without the
   scaler, set `runner.replicas` to the noted count.

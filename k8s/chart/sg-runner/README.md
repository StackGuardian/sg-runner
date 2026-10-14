# sg-runner Helm chart (prototype)

> **Status: prototype.** Not supported, not documented for customers.

Runs StackGuardian Private Runners on Kubernetes (≥ 1.29). Each replica of the
runner StatefulSet is one registered runner on a node of its own, running each
workflow step as a pod ([How a runner runs workflows](#how-a-runner-runs-workflows));
a scaler Deployment wakes, parks and reaps runners from the runner group's
queue. Design and known gaps: [`k8s/README.md`](../../README.md).

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

## How a runner runs workflows

Each runner pod takes a node of its own. Its run controllers (the ECS tasks)
run in the pod's nested Docker (`dockerd`); each workflow step runs as a pod
of its own on the runner's node. A `steps` sidecar in the runner pod (the
broker, `/sg-runner-steps` in the scaler image) creates the step pods for the
controllers over a unix socket ([`steps-api.md`](../../docs/steps-api.md)).

- **One runner per node.** A required pod anti-affinity on
  `kubernetes.io/hostname` is appended to `runner.affinity`'s own
  `podAntiAffinity` terms (everything else in `runner.affinity` is kept). Step
  pods are pinned to their runner's node and mount its workspace.
- **The broker is a native sidecar** (an init container with
  `restartPolicy: Always`, hence Kubernetes ≥ 1.29): it starts before
  `dockerd`, once its health check passes, and stops after every other
  container, so it outlives a drain.
- **dockerd is guarded** by the broker: it runs with
  `--authorization-plugin=sg-steps-guard`, the plugin socket on a shared
  `docker-plugins` volume. The guard refuses step containers in dockerd
  (`POST /containers/create` with a `wfrunId` label), so steps can only run as
  pods. It fails closed: `dockerd` doesn't start without the socket (it waits
  up to 60s, then fails), and while the guard isn't answering dockerd refuses
  every API call. So a crash-looping broker blocks the runner.
- **Workspace** is a PVC per pod (`<pod>-workspace`, a generic ephemeral
  volume created and deleted with the pod, `runner.steps.workspace`), mounted
  by the run controllers and the step pods.
- **API access.** The runner pod gets a ServiceAccount (`<statefulset>`) with a
  Role for pods (create, get, list, watch, patch, delete), `pods/log` (get)
  and Secrets (create, delete only: never read back). Pod-level token
  automount stays off; only the `steps` container mounts a token.
- **Logs**: steps are pods, so
  `kubectl logs -l app.kubernetes.io/component=step` shows them. Finished
  step pods stay for `runner.steps.finishedTTL` (1h), labelled with their
  outcome; their Secrets (env, registry credentials) are deleted as soon as
  they finish:
  `kubectl get pods -l app.kubernetes.io/component=step -L sg-runner.stackguardian.io/outcome`.
- **Exit codes 11 and 12** (approval required, completed early) are outcomes,
  not failures: the broker runs each step through a small wrapper (an init
  container from the broker image copies it in) so those pods end
  `Completed`. To wrap a step it reads the image's ENTRYPOINT/CMD from its
  registry (the image config only, no layers). If that fails, the step runs
  unwrapped, and exits 11/12 then show as `Error` (the run's result is the
  same; annotation `sg-runner.stackguardian.io/not-wrapped-reason` says why).
  So the `steps` container calls registries over HTTPS, which the
  NetworkPolicy's egress allows like any other external destination.
  Wrapped step pods pull the broker image with `imagePullSecrets`
  (`BROKER_IMAGE_PULL_SECRETS`).
- **NetworkPolicy** covers step pods too (`app.kubernetes.io/component:
  step`). It also blocks the Kubernetes API, which the broker needs: allow the
  API server's endpoint (`kubectl get endpoints kubernetes`) with
  `networkPolicy.extraEgress`. NetworkPolicy can't tell containers apart, so
  that opens the API endpoint to the whole runner pod (the run controllers
  too, without a token).

## Runner size

`runner.size` sets what the runner advertises to SG for workflows (step pods
and run controllers together), and the resources of the `dockerd` container,
which only holds the run controllers. Nothing is kept back for dockerd.

| Size | Advertised | Controllers (dockerd) requests | limits |
|---|---|---|---|
| `small` | 2 CPU / 4Gi | 500m / 1Gi | 2 / 2Gi |
| `medium` | 4 CPU / 8Gi | 1 / 2Gi | 4 / 4Gi |
| `large` | 8 CPU / 16Gi | 2 / 4Gi | 8 / 8Gi |
| `custom` | `runner.advertise` (required) | `runner.controllerResources` (limits required) | |

A workflow reserves 0.5 vCPU / 512 MiB for its run controller plus its own
setting (default 0.5 vCPU / 1 GiB): 1 vCPU / 1.5 GiB by default. The runner
must be at least the largest workflow + 0.5 vCPU / 512 MiB, else that workflow
stays queued (the scaler warns). Size the controllers' memory limit at ~512Mi
per concurrent workflow run.

The node needs the advertised capacity free for step pods, plus the runner
pod's own requests. The agent can't advertise more than the node has, and
node memory minus the advertised memory must stay under 64 GiB (the agent's
reservation is a uint16 of MiB; the runner refuses to start otherwise).

**Resizing.** ECS keeps a runner's CPU and memory from its first
registration, so a new size alone changes nothing. With
`runner.reregisterOnResize` (default), a runner pod that starts with another
size than its registration (`runner.size` or `runner.advertise` changed)
deregisters and registers again, if nothing runs on it; it gets a new runner
ID in SG. With tasks running or pending it keeps the old size and logs a
warning; restart it once idle. If SG can't be read, the old registration
stays.

## Values

| Key | Default | Description |
|---|---|---|
| `nameOverride` / `fullnameOverride` | `""` | Rename resources; `fullnameOverride` also renames the StatefulSet (max 52 chars). |
| `image.repository` / `.tag` / `.pullPolicy` | `sg-runner-k8s` / `dev` / `IfNotPresent` | Runner image; also used by reap Jobs. Empty tag = `appVersion`. |
| `imagePullSecrets` | `[]` | For runner, scaler and reap Job pods (and native steps' wrapper). Secret names or `{name: ...}` objects, mixed as you like. |
| `sg.organization` / `sg.runnerGroup` | `""` | Required: the runner group to register into. In the `<release>-config` ConfigMap. |
| `sg.apiUrl` | `""` | StackGuardian API; empty = `https://api.app.stackguardian.io/api/v1`. |
| `credentials.existingSecret` | `""` | Secret with key `SG_NODE_TOKEN` (the runner group's node token); other keys are ignored. |
| `credentials.create` / `nodeToken` | `false` / `""` | Create that Secret from `nodeToken`. Exactly one of this or `existingSecret`. |
| `runner.replicas` | `1` | Only with `scaler.enabled=false`. |
| `runner.size` | `small` | `small`, `medium`, `large` or `custom`: what the runner advertises and the controllers' room ([Runner size](#runner-size)). |
| `runner.advertise.cpu` / `.memory` | empty | `size=custom` only, required: what the runner advertises to SG. Whole CPUs; `<n>Mi` or `<n>Gi`. |
| `runner.controllerResources` | `{}` | `size=custom` only, limits required: dockerd resources (run controllers only); ~512Mi per concurrent run. |
| `runner.storage.state.size` / `.storageClassName` | `1Gi` / `""` | Runner identity PVC. Empty class = cluster default. |
| `runner.storage.docker.size` / `.storageClassName` | `20Gi` / `""` | Docker data root PVC (image cache). |
| `runner.dockerd.securityContext` | `{privileged: true}` | Nested Docker needs privileged for now. |
| `runner.dockerd.extraEnv` | `[]` | Extra env vars for the `dockerd` container (advanced/testing, e.g. `SG_PRUNE_INTERVAL_SECONDS=0` turns off the nested Docker prune loop). |
| `runner.ecsAgent.extraEnv` | `[]` | Extra env vars for the `ecs-agent` container (advanced/testing, e.g. `ECS_IMAGE_PULL_BEHAVIOR=prefer-cached`). |
| `runner.steps.workspace.size` / `.storageClassName` / `.accessModes` | `20Gi` / `""` / `[ReadWriteOnce]` | Workspace PVC per pod (`<pod>-workspace`) at `/var/tmp/workspace` on dockerd, mounted by step pods. Empty class = cluster default. |
| `runner.steps.schedulingTimeout` / `startTimeout` / `finishedTTL` | `5m` / `30m` / `1h` | Step pod fails if unschedulable / still pending this long. Finished step pods are kept for `finishedTTL`, then deleted; their Secrets go when they finish. |
| `runner.steps.step.nodeSelector` / `.tolerations` | empty | Step pod scheduling; empty = `runner.nodeSelector` / `runner.tolerations`. |
| `runner.steps.step.imagePullPolicy` | `""` | `STEP_IMAGE_PULL_POLICY`. Empty = automatic (`Always` for `latest` or no tag, else `IfNotPresent`); `IfNotPresent` / `Never` for air-gapped clusters or preloaded images. |
| `runner.steps.broker.image.repository` / `.tag` / `.pullPolicy` | `""` / `""` / `IfNotPresent` | `steps` sidecar image, also the step pods' wrapper init container (`BROKER_IMAGE`, `BROKER_IMAGE_PULL_POLICY`); empty repository = the scaler image. |
| `runner.steps.broker.resources` | 10m / 32Mi, limit 256Mi | |
| `runner.steps.broker.extraEnv` | `[]` | Extra env vars for the broker. |
| `runner.reregisterOnResize` | `true` | `SG_REREGISTER_ON_RESIZE` on the register init container: register an idle runner again when its registered size differs from what it now advertises ([Runner size](#runner-size)). |
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
- **NetworkPolicy** covers runner pods (run controllers and agents alike:
  nested traffic leaves through the pod IP), step pods
  (`app.kubernetes.io/component: step`) and reap Job pods, which the scaler
  labels `app.kubernetes.io/component: reaper` (`SCALER_REAP_POD_LABELS`).
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

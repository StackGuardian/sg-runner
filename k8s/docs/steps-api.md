# Step broker API (v1)

Contract between the run controller (`sg-run-controller`,
`external_runner/step_broker.py`) and the step broker (`sg-runner-steps`, a
container in the runner pod). The broker runs each workflow step as a pod; the
controller only asks it to. See [native-steps.md](native-steps.md) for why.

## Transport and discovery

- HTTP/1.1 with JSON bodies over a unix socket. No authentication: only
  processes that can reach the socket file can call it (run controllers, which
  mount the workspace root; steps mount only their run's directory).
- The broker listens on `SOCKET_PATH` (in its container
  `/run/sg-steps/steps.sock`). The same emptyDir is mounted in the `dockerd`
  container at `/var/tmp/workspace/.sg-runner`, so run controllers see it at
  **`${WORKSPACES_DIR}/.sg-runner/steps.sock`**
  (`/var/tmp/workspace/.sg-runner/steps.sock`).
- The broker removes a stale socket file before listening and makes the
  socket mode 0666.
- The controller uses the broker when that path is a socket
  (`stat.S_ISSOCK`), decided once per run at the first step. It then calls
  `GET /healthz`; any failure or an `api` other than `v1` fails the step. A
  controller that uses the broker never falls back to Docker.

## Errors

Every non-2xx response has a JSON body:

```json
{"reason": "InvalidMount", "message": "mount source /var/tmp/workspace is outside the run's workspace"}
```

| Status | Reasons | Meaning |
|---|---|---|
| 400 | `InvalidRequest`, `InvalidMount`, `InvalidEnv`, `EnvTooLarge` | Fix the request; retrying won't help |
| 404 | `NotFound` | No such step (never existed, or its pod is gone) |
| 500 | `KubernetesError` | The cluster API call failed; the message says which |

## Endpoints

### `GET /healthz`

`200 {"api": "v1"}`.

### `POST /v1/steps`

Creates the step's Secrets and pod. Returns once the pod object exists, not
when it runs.

```json
{
  "name": "example-org-wfgrps-x-wfs-y-wfruns-z-plan-0-1a2b",
  "org": "/orgs/example-org",
  "run": "/wfgrps/x/wfs/y/wfruns/z",
  "stepIdx": 0,
  "image": "registry.example.com/team/image:1.2",
  "args": ["terraform", "plan"],
  "env": {"SG_WORKFLOW_RUN_PAYLOAD": "…", "AWS_SHARED_CREDENTIALS_FILE": "…"},
  "mounts": [
    {"source": "/var/tmp/workspace/orgs/example-org/wfgrps/x/wfs/y/wfruns/z/shared-workspace",
     "target": "/mnt/sg_workspace", "readOnly": false}
  ],
  "cpuShares": 512,
  "memoryMiB": 1024,
  "registryAuth": {"registry": "registry.example.com", "username": "u", "password": "p"},
  "timeoutSeconds": 2100
}
```

| Field | Rules |
|---|---|
| `name` | Docker-style container name the controller built; stored as an annotation only |
| `org`, `run` | The controller's `orgId` and `workflowRunId` (the Docker labels `orgId` / `wfrunId`). Required. The run's workspace is `WORKSPACES_DIR + org + run` |
| `stepIdx` | Integer, for labels and names |
| `image` | Required. Pull policy `Always` when the tag is `latest` or absent, else `IfNotPresent` |
| `args` | Optional. Overrides the image's CMD and keeps its ENTRYPOINT (Docker's `command=`). The broker puts it in the container's `args` and escapes `$` as `$$`, so the kubelet never expands `$(VAR)`. `null`/absent = the image's CMD |
| `env` | Map. Keys must match `[-._a-zA-Z0-9]+` (`InvalidEnv`); total size of keys and values ≤ 1,000,000 bytes (`EnvTooLarge`). Goes into a Secret, loaded with `envFrom` |
| `mounts` | Each `source` must be strictly under the run's workspace after path cleaning (no `..`, not the workspace itself, not the workspace root): `InvalidMount` otherwise. Becomes a `subPath` of the runner's workspace claim at `target` |
| `cpuShares` | Docker CPU shares; CPU **request** = `cpuShares/1024` cores (millicores rounded up, minimum 1m). No CPU limit |
| `memoryMiB` | Memory request = limit |
| `registryAuth` | Optional. Becomes a `kubernetes.io/dockerconfigjson` pull Secret for `registry` (a host, e.g. `123.dkr.ecr.eu-central-1.amazonaws.com`, or `https://index.docker.io/v1/` for Docker Hub) |
| `timeoutSeconds` | The step's own timeout. The pod's `activeDeadlineSeconds` = `timeoutSeconds + START_TIMEOUT + 300` bounds steps whose controller is gone |

`201 {"id": "sg-runner-0-s-7f3k9q2x"}`. The id is the pod name.

### `GET /v1/steps/{id}`

```json
{"id": "sg-runner-0-s-7f3k9q2x", "state": "exited", "exitCode": 11,
 "reason": "Completed", "message": "", "startedAt": "2026-10-14T10:00:00Z",
 "finishedAt": "2026-10-14T10:05:00Z"}
```

| `state` | When | `exitCode` |
|---|---|---|
| `pending` | Scheduling, pulling, creating the container | `null` |
| `running` | Container running | `null` |
| `exited` | Container terminated (any code, including OOMKilled = 137 with reason `OOMKilled`) | int |
| `failed` | The step never ran or was lost; `reason` says why (below) | `null` |

`failed` reasons: `Unschedulable` (longer than `SCHEDULING_TIMEOUT`),
`ImagePullBackOff`, `ErrImagePull` (not found / unauthorized only; otherwise
it stays `pending` until BackOff), `InvalidImageName`, `ErrImageNeverPull`,
`StartTimeout` (pending longer than `START_TIMEOUT`), `Evicted`,
`DeadlineExceeded`, `PodDeleted` (pod deleted without a stop).
`CreateContainerConfigError` is transient (`pending`) until `START_TIMEOUT`.

A terminal state (`exited` or `failed`), once a GET returned it, is the step's
for good, and the broker keeps returning it for 1 hour after the pod is gone.
The pod and its Secrets go `FINISHED_GRACE` (10s) after a GET first returned
that state, or when the step's last open log stream closes after that. Logs
stay readable in the grace, for a log stream that opens late (a step that
ended before it opened) or reconnects; after it they are gone unless a stream
is still open. A stopped step whose pod is
gone before a client got a terminal state returns the last state the broker
saw (`exited`, its code or 137).

The broker keeps all this in memory: after a broker restart a deleted step is
`404`. A client that already got the terminal state keeps it; one that asked
for a stop treats `404` as `exited` with 137; any other treats it as
`failed`/`PodDeleted`.

### `GET /v1/steps/{id}/logs?follow=1[&sinceTime=<RFC3339Nano>]`

`200`, `Content-Type: text/plain`, chunked. Blocks until the container has
started or the step has finished; a step that `failed` before starting ends the
stream with no lines. Each line is `<RFC3339Nano timestamp> <text>\n` (the
kubelet's `timestamps=true` format); the client strips the timestamp and keeps
the last one. The stream ends when the container terminates. A stream that
ends while the step is still `running` was broken: reconnect with
`sinceTime=<last timestamp>` (lines with exactly that timestamp may repeat;
the client drops a repeated first line).

### `POST /v1/steps/{id}/stop`

Body `{"graceSeconds": 30}` (0 = kill now). Records the stop, then deletes the
pod with that grace period: SIGTERM, SIGKILL after the grace. `202`, or `404`.

### `DELETE /v1/steps/{id}`

Best effort cleanup of a step: deletes the pod and its Secrets. `204` (also
when already gone). A finished step's pod goes anyway once a GET returned its
terminal state (see above).

## What the broker creates per step

- Secret `<id>-env` (the env), and `<id>-pull` when `registryAuth` is set,
  created before the pod and owned by the runner pod.
- Pod `<id>` (`<runner pod>-s-<8 random [a-z0-9]>`), owned by the runner pod
  (UID from the downward API, `blockOwnerDeletion` unset), labels from
  `STEP_LABELS` plus `app.kubernetes.io/component: step`,
  `sg-runner.stackguardian.io/runner: <runner pod>` and
  `sg-runner.stackguardian.io/run: <sanitized, ≤63, with a short hash>`;
  annotations with the raw `org`, `run`, `stepIdx` and `name`.
- Pod spec: one container `step`; `restartPolicy: Never`;
  `terminationGracePeriodSeconds: 30`; `automountServiceAccountToken: false`;
  `enableServiceLinks: false`; `seccompProfile: RuntimeDefault`;
  `privileged: false`; required node affinity `matchFields metadata.name =
  NODE_NAME`; `STEP_NODE_SELECTOR` / `STEP_TOLERATIONS`; image pull secrets
  `<id>-pull` when present; volume `workspace` = PVC `WORKSPACE_CLAIM`, one
  `volumeMount` per mount with `subPath = WORKSPACE_SUBPATH_PREFIX +
  (source relative to WORKSPACES_DIR)`.

## Garbage collection

Finished steps go `FINISHED_GRACE` after a client got their terminal state, or
when their last log stream closes after that (see `GET /v1/steps/{id}`). Every minute the broker also:

- deletes step pods (and their Secrets) that are terminal, that no client read
  (their controller is gone), have no open log stream and finished more than
  `FINISHED_TTL` ago, keeping their final state for 1 hour like a read one;
- retries deletions of read steps that failed;
- deletes, by name, the Secrets of steps whose pod went without the broker
  (a stop, or someone else);
- forgets steps gone for over an hour.

It never lists or reads Secrets (that returns their data, and the runner's
node token shares the namespace): step Secrets go by name with their step,
or with the runner pod that owns them (ownerReference), like step pods.

## Broker configuration (env)

| Variable | Default | Meaning |
|---|---|---|
| `SOCKET_PATH` | `/run/sg-steps/steps.sock` | Listen socket |
| `WORKSPACES_DIR` | `/var/tmp/workspace` | The controllers' workspace root (paths in requests) |
| `WORKSPACE_CLAIM` | required | PVC holding `WORKSPACES_DIR` (the runner's ephemeral `<pod>-workspace`) |
| `WORKSPACE_SUBPATH_PREFIX` | empty | Prefix inside the claim (for a shared RWX claim later) |
| `RUNNER_POD_NAME`, `RUNNER_POD_UID`, `NODE_NAME`, `NAMESPACE` | required | Downward API |
| `STEP_LABELS` | `{}` | JSON map of labels for step pods (chart selector labels) |
| `STEP_NODE_SELECTOR` | `{}` | JSON map |
| `STEP_TOLERATIONS` | `[]` | JSON list of tolerations |
| `STEP_IMAGE_PULL_POLICY` | empty | `Always`, `IfNotPresent` or `Never` for every step pod (e.g. images preloaded on the node, air-gapped clusters); empty = `Always` for a `latest` or absent tag, else `IfNotPresent` |
| `SCHEDULING_TIMEOUT` | `5m` | Go duration |
| `START_TIMEOUT` | `30m` | Go duration |
| `FINISHED_TTL` | `10m` | Go duration |
| `FINISHED_GRACE` | `10s` | Go duration, `0` or more: how long a step's pod (and its logs) stays after a GET first returned its terminal state |
| `DRAINED_MARKER` | `/var/run/sg-runner-drained` | File the runner's drain creates when done (see below). The chart mounts the runner's `/var/run` read-only at `/run/sg-runner` in the broker and sets `/run/sg-runner/sg-runner-drained` |

## Lifecycle in the runner pod

The broker must outlive the run controllers during a drain: its preStop is
`sg-runner-steps wait-drained` (polls `DRAINED_MARKER`), and it ignores SIGTERM
until the marker exists. The runner's drain waits for every run controller
container, and controllers wait for their steps.

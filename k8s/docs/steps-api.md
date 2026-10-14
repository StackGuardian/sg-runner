# Step broker API (v1)

Contract between the run controller (`sg-run-controller`,
`external_runner/step_broker.py`) and the step broker (`sg-runner-steps`, a
native sidecar of the runner pod). The broker runs each workflow step as a
pod; the controller only asks it to. The runner runs steps only this way: the
broker's [guard](#guard) keeps dockerd from running them. See
[native-steps.md](native-steps.md) for why.

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
  controller that uses the broker never falls back to Docker; one without
  broker support is stopped by the [guard](#guard).

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
| `args` | Optional. Overrides the image's CMD and keeps its ENTRYPOINT (Docker's `command=`). A wrapped step gets it after the ENTRYPOINT in the container's `command`, an unwrapped one in its `args` (see [Step wrapper](#step-wrapper)); either way `$` is escaped as `$$`, so the kubelet never expands `$(VAR)`. `null`/absent/empty = the image's CMD |
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
| `exited` | Container terminated (any code, including OOMKilled = 137 with reason `OOMKilled`; for a wrapped step 11 and 12 as the step exited, see [Step wrapper](#step-wrapper)) | int |
| `failed` | The step never ran or was lost; `reason` says why (below) | `null` |

`failed` reasons: `Unschedulable` (longer than `SCHEDULING_TIMEOUT`),
`ImagePullBackOff`, `ErrImagePull` (not found / unauthorized only; otherwise
it stays `pending` until BackOff), `InvalidImageName`, `ErrImageNeverPull`,
`StartTimeout` (pending longer than `START_TIMEOUT`), `Evicted`,
`DeadlineExceeded`, `PodDeleted` (pod deleted without a stop).
`CreateContainerConfigError` is transient (`pending`) until `START_TIMEOUT`.

A terminal state (`exited` or `failed`) is the step's for good once the broker
saw it (on a GET, a stop or its sweep): later GETs return it from memory, also
after the pod is gone, for 1 hour after the pod's deletion. The pod itself
stays `FINISHED_TTL` (1h) after it ended, its logs readable, labeled with its
outcome; its Secrets go as soon as it's terminal (see
[Retention](#retention-and-garbage-collection)). A stopped step whose pod is
gone before the broker saw it end returns the last state the broker saw
(`exited`, its code or 137).

The broker keeps all this in memory: after a broker restart a step whose pod
is gone is `404`. A client that already got the terminal state keeps it; one
that asked for a stop treats `404` as `exited` with 137; any other treats it
as `failed`/`PodDeleted`.

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
when already gone). A finished step's pod goes anyway `FINISHED_TTL` after it
ended (see [Retention](#retention-and-garbage-collection)).

## What the broker creates per step

- Secret `<id>-env` (the env), and `<id>-pull` when `registryAuth` is set,
  created before the pod and owned by the runner pod.
- Pod `<id>` (`<runner pod>-s-<8 random [a-z0-9]>`), owned by the runner pod
  (UID from the downward API, `blockOwnerDeletion` unset), labels from
  `STEP_LABELS` plus `app.kubernetes.io/component: step`,
  `sg-runner.stackguardian.io/runner: <runner pod>` and
  `sg-runner.stackguardian.io/run: <sanitized, ≤63, with a short hash>`, and
  once terminal `sg-runner.stackguardian.io/outcome` (below); annotations with
  the raw `org`, `run`, `stepIdx` (`sg-runner.stackguardian.io/step-idx`) and
  `name`, and `sg-runner.stackguardian.io/wrapped: "true"` or `"false"` (then
  with `sg-runner.stackguardian.io/not-wrapped-reason`).
- Pod spec: container `step`; `restartPolicy: Never`;
  `terminationGracePeriodSeconds: 30`; `automountServiceAccountToken: false`;
  `enableServiceLinks: false`; `seccompProfile: RuntimeDefault`;
  `privileged: false`; required node affinity `matchFields metadata.name =
  NODE_NAME`; `STEP_NODE_SELECTOR` / `STEP_TOLERATIONS`; image pull secrets
  `<id>-pull` when present; volume `workspace` = PVC `WORKSPACE_CLAIM`, one
  `volumeMount` per mount with `subPath = WORKSPACE_SUBPATH_PREFIX +
  (source relative to WORKSPACES_DIR)`; termination message
  `/dev/termination-log` (policy `File`).
- A wrapped step also gets the init container `sg-wrapper-install` (image
  `BROKER_IMAGE`, pull policy `BROKER_IMAGE_PULL_POLICY`, command
  `/sg-step-wrapper install /sg-wrapper/sg-step-wrapper`, UID/GID 65532,
  non-root, read-only root filesystem, no privilege escalation, all
  capabilities dropped, requests 10m CPU / 16Mi memory, limit 64Mi), the
  emptyDir `sg-wrapper` (64Mi) mounted read-write there and read-only at
  `/sg-wrapper` in `step`, and `BROKER_IMAGE_PULL_SECRETS` among its image
  pull secrets.

## Step wrapper

A pod whose container exits non-zero ends `Failed`, but StackGuardian steps
exit 11 (approval required) and 12 (finished early) on purpose. So steps run
under `sg-step-wrapper`, an init process (like `tini` / `docker run --init`)
from the broker's image:

- The broker reads the step image's config (the manifest and config blob for
  its own platform, `linux/amd64` or the first linux image of an index
  without it; never the layers) with the request's `registryAuth` when it is
  for the image's registry, else anonymously; 20s timeout, cached 10 minutes
  per image.
- The step's `command` is `["/sg-wrapper/sg-step-wrapper", "--",
  <ENTRYPOINT...>, <args, or the image's CMD when args are absent or
  empty...>]` (no `args`), each element with `$` escaped as `$$`.
- The wrapper runs that as its child (looked up in `PATH`), forwards SIGTERM,
  SIGINT, SIGHUP, SIGQUIT, SIGUSR1 and SIGUSR2, reaps zombies, and leaves
  stdio alone. A child exit of 11 or 12 writes `sg-exit-code=<n>` to
  `/dev/termination-log` and exits 0, so the pod ends `Completed`; any other
  code is its own, a signal 128+n; a command it can't run is 126 or 127.
- `GET` reports a wrapped pod's exit 0 with exactly that termination message
  as `exited` with 11 or 12. Nothing else is read from the message.

A step runs unwrapped, exactly as without the wrapper (its 11 and 12 then end
the pod `Failed`), when `BROKER_IMAGE` is unset, the lookup fails, or neither
the image nor the request has anything to run. The broker logs a warning and
annotates the pod `wrapped: "false"` with the reason (no Event: the broker
can't create Events).

## Retention and garbage collection

A step is finished once the broker sees it terminal (on a GET, a stop's
follow-up, or its sweep every minute). It then, once:

- labels the pod `sg-runner.stackguardian.io/outcome`: `succeeded` (exit 0),
  `approval-required` (11), `completed-early` (12), `failed` (any other code,
  or `failed`), `stopped` (a client stopped it, whatever the code); a pod
  that has the label keeps it;
- deletes its Secrets: they hold credentials, and the container has its env.

Every minute the broker also:

- deletes finished step pods `FINISHED_TTL` (1h) after they ended
  (`finishedAt`, else when the broker first saw them terminal), read or not,
  unless a log stream is open; their final state stays for GETs 1 hour after;
- retries finishing (label, Secrets) that failed;
- deletes, by name, the Secrets of steps whose pod went without the broker
  (a stop, or someone else);
- forgets steps gone for over an hour.

It never lists or reads Secrets (that returns their data, and the runner's
node token shares the namespace): step Secrets go by name with their step,
or with the runner pod that owns them (ownerReference), like step pods.

## Guard

The broker also serves dockerd the authorization plugin `sg-steps-guard`, so
a run controller without broker support (an older one) can't run steps in
dockerd: they would run inside the runner pod, outside every pod limit.

- It listens on `GUARD_SOCKET` (`/run/sg-guard/sg-steps-guard.sock`). The
  chart mounts that directory into `dockerd` at `/run/docker/plugins`, where
  dockerd finds the plugin by its socket name, and starts dockerd with
  `--authorization-plugin=sg-steps-guard`.
- Docker plugin protocol (`application/vnd.docker.plugins.v1.2+json`):
  `POST /Plugin.Activate` answers `{"Implements":["authz"]}`;
  `POST /AuthZPlugin.AuthZReq` decides; `POST /AuthZPlugin.AuthZRes` always
  allows.
- A request is refused (`{"Allow":false,"Msg":"This runner runs workflow
  steps as Kubernetes pods and needs a run controller with native step support
  (step broker client); refusing to start the step in dockerd."}`) when its
  `RequestMethod` is `POST`, the path of its `RequestUri` matches
  `^(/v[0-9.]+)?/containers/create$`, and its JSON body's `Labels` has the key
  `wfrunId` (the run controller's label on step containers). Everything else
  is allowed, the ECS agent creating run controllers (`com.amazonaws.ecs.*`
  labels) included.
- A container create without a body (dockerd sends only JSON bodies, within
  its size limit) or with one it can't parse is allowed, with a warning in the
  broker's log. An unreadable authorization request gets `Err` (dockerd
  refuses the call).
- While the guard doesn't answer, dockerd refuses every API call: the broker
  starts before dockerd (a native sidecar) and stops after it.

## RBAC

The broker's ServiceAccount, in its namespace: pods `create`, `get`, `list`,
`delete`, `patch` (the outcome label); `pods/log` `get`; secrets `create`,
`delete`. The registry lookup needs no RBAC (it uses the request's
`registryAuth`).

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
| `FINISHED_TTL` | `1h` | Go duration: how long a finished step's pod stays after it ended |
| `BROKER_IMAGE` | empty | The broker's own image (has `/sg-step-wrapper`) for the wrapper's init container; empty = steps run unwrapped |
| `BROKER_IMAGE_PULL_POLICY` | empty | `Always`, `IfNotPresent` or `Never` for that init container; empty = the cluster's default |
| `BROKER_IMAGE_PULL_SECRETS` | empty | Comma-separated pull Secrets for `BROKER_IMAGE`, added to wrapped step pods |
| `GUARD_SOCKET` | `/run/sg-guard/sg-steps-guard.sock` | The guard's socket; its directory is dockerd's `/run/docker/plugins`. Must differ from `SOCKET_PATH` |

## Lifecycle in the runner pod

The broker is a native sidecar: an init container with `restartPolicy:
Always`. Kubernetes starts it, and waits for its startup probe, before the
runner's containers (dockerd needs the guard from its first API call, run
controllers the broker), and stops it only after they all exited. So on
SIGTERM it just shuts down: it stops listening and gives open requests up to
10s.

- `sg-runner-steps serve` (the default) runs the broker.
- `sg-runner-steps healthcheck` is its startup and readiness probe (the image
  has no shell): exit 0 when `GET /healthz` on `SOCKET_PATH` answers `api`
  `v1` and `POST /Plugin.Activate` on `GUARD_SOCKET` answers `authz`, else
  1. It reads only those two variables.

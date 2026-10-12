# TODO

## Kubernetes prototype (`k8s/`)

### Workspace volume for the nested Docker daemon

The run controller and every workflow step bind-mount `/var/tmp/workspace` from
the Docker daemon they run on. In the pod that daemon is the `dockerd`
container, and the path isn't backed by a volume, so workspaces land in the
container's writable layer: they count against the node's container storage
and are lost when the container restarts.

- Mount a volume at `/var/tmp/workspace` in the `dockerd` container: an
  `emptyDir` matches VM behavior (scratch space), a PVC only if runs must
  survive a pod restart.
- Size it with `sizeLimit` / storage requests so a large run can't fill the node.

### NetworkPolicy for workflow isolation

Workflow containers can resolve cluster DNS and reach the Kubernetes API
(verified on OrbStack: `kubernetes.default.svc` answered with `401`). The
`DOCKER-USER` DROP rules from `main.sh` don't help: they target `sg-net`, and
the run controller and step containers run on the default bridge.

Nested traffic leaves through the pod IP, so an egress NetworkPolicy on the
runner pod covers workflow containers and the agents alike:

- Allow DNS to the cluster resolver only if workflows need it; otherwise
  resolve via an external resolver.
- Deny the pod, service and node CIDRs (Kubernetes API included) and the
  cloud metadata endpoint (`169.254.169.254`).
- Allow everything else (SG API, AWS endpoints, VCS, registries, workflow
  targets).
- Needs a CNI that enforces NetworkPolicy (Calico, Cilium, ...). Check what
  OrbStack's CNI does before testing there.

### Allow the runner to drain itself (platform IAM)

On every shutdown the drain hook sets the runner's ECS container instance to
`DRAINING`, so no new task lands while running ones finish, and sets it `ACTIVE`
again when a restarted runner comes back. On QA both calls fail:

```
AccessDeniedException: User: arn:aws:sts::<account-id>:assumed-role/ECSAnywhereRole/...
is not authorized to perform: ecs:UpdateContainerInstancesState on resource:
arn:aws:ecs:eu-central-1:<account-id>:container-instance/admin-workflow-qa/...
because no identity-based policy allows the ecs:UpdateContainerInstancesState action
```

`ECSAnywherePolicy` grants the action on `cluster/admin-workflow-qa` only, while
ECS authorizes it against the container-instance ARN. Without it, a busy runner
keeps receiving work while it drains and can hold its pod for the whole grace
period (1h), one pod at a time during a rollout. Prod's policy isn't checked.

- Add `arn:aws:ecs:<region>:<account>:container-instance/<cluster>/*` to that
  statement (or use the `ecs:cluster` condition key). Platform change, not
  something this repo controls.
- Until then the hook logs the failure and only waits for running workflows.

### Drop privileged mode

Spike results on OrbStack (k8s 1.36, cri-dockerd, arm64):

| Option | Result |
|---|---|
| `hostUsers: false` (user namespaces) | Not testable: cri-dockerd doesn't support user namespaces |
| Capabilities only | Works with `SYS_ADMIN`, `NET_ADMIN`, `SYS_RESOURCE`, seccomp/AppArmor `Unconfined` and `mount -o remount,rw` of `/sys/fs/cgroup` and `/proc/sys`. Not a real gain: `CAP_SYS_ADMIN` in the host user namespace with seccomp off is close to privileged |
| Rootless dind | Containers fail to mount `/proc` without `procMount: Unmasked` (needs user namespaces); task-credential DNAT would target the wrong loopback |
| Sysbox | Not tried (needs a node install) |

Next: test `hostUsers: false` (with `procMount: Unmasked`) on containerd 2.x
or CRI-O, kernel 6.3+, and Sysbox on a cluster where it can be installed.
Both keep root inside the pod unprivileged on the node.

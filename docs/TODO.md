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

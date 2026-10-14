# TODO

## Kubernetes prototype (`k8s/`)

### Verify the NetworkPolicy on an enforcing CNI

The chart ships an optional egress NetworkPolicy (`networkPolicy.enabled`) for
runner, step and reap pods: DNS to kube-dns, everything outside `clusterCIDRs`,
no `169.254.169.254`. Not yet tested on a CNI that enforces NetworkPolicy
(Calico, Cilium, the VPC CNI's policy mode):

- Confirm a step pod can't reach the Kubernetes API, other pods or the metadata
  endpoint, and can still reach SG, AWS, VCS and registries.
- The step broker needs the Kubernetes API: today that means an
  `extraEgress` rule for the API endpoint (open to the whole runner pod);
  replace it with a dedicated value.
- Decide whether steps may resolve cluster names at all; if not, give step
  pods their own `dnsConfig` and block cluster DNS.

### Long parking and hard kills against real SG

- Park a runner for 12–24h, wake it, and run a workflow on it.
- Force-delete a runner pod during scale-down and check that the scaler drains
  it in SG and reactivates it on wake.
- Check whether SG resumes workflows paused while no runner was `ACTIVE`.

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

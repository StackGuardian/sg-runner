# sg-runner on Kubernetes (prototype)

> **Status: prototype.** Not supported, not documented for customers.

Runs a Private Runner as a pod. Each StatefulSet replica is one registered
runner: it stands in for the VM that `main.sh register` normally prepares.

## How it maps to a VM

| VM (`main.sh` + `ecs-anywhere-install.sh`) | Pod                                                      |
|--------------------------------------------|----------------------------------------------------------|
| `systemd` + `dockerd`                       | `dockerd` container (privileged, nested Docker)           |
| `amazon-ssm-agent` service                  | `ssm-agent` container                                     |
| `ecs-init` → `ecs-agent` container          | `ecs-agent` container, env loaded from `ecs.config`       |
| `register` (API + SSM activation)           | `register` init container, skipped if state exists        |
| `/etc/ecs`, `/var/lib/ecs`, `/var/lib/amazon/ssm` | `state` PVC: runner identity survives pod restarts  |
| `/root/.aws/credentials` (SSM → agent)      | in-memory `emptyDir` shared by both agents                |
| `configure_local_network` (iptables/sysctl) | same function, run in the pod's network namespace         |

All containers use one image (`Dockerfile`) and `runner.sh`, which sources
`main.sh` for the API, config and network helpers.

## Usage (OrbStack Kubernetes)

```sh
cd k8s
cp .env.example .env   # fill in a throwaway runner group's credentials
make build             # build sg-runner-k8s:dev
make secret            # namespace + credentials Secret
make up                # deploy; first start registers the runner
make logs              # follow all containers
make status            # pod state + ECS agent metadata

make deregister        # SG deregister + wipe identity (reads .env on stdin)
make nuke              # deregister, then delete StatefulSet, PVCs, namespace
```

`make nuke` deregisters first and stops if that fails: deleting the PVC without
deregistering would leave a dead runner in the runner group.

## Known gaps

- **Privileged pod.** Needed for nested Docker; restricted PSA clusters reject it.
- **Network isolation.** The VM rule (`DOCKER-USER` DROP for
  `169.254.169.254,10.0.0.0/24`) doesn't fit a cluster: job containers can
  resolve cluster DNS and reach the Kubernetes API (verified). Needs a
  NetworkPolicy on the runner pod and a CNI that enforces it
  ([`docs/TODO.md`](../docs/TODO.md)).
- **Workspaces in the container layer.** `/var/tmp/workspace`, bind-mounted
  by the run controller and steps, isn't on a volume yet
  ([`docs/TODO.md`](../docs/TODO.md)).
- **Task cgroup limits off** (`ECS_ENABLE_TASK_CPU_MEM_LIMIT=false`): the agent
  can't create task cgroups from its container. Size the pod's resources instead.
- **No proxy support** yet (`--http-proxy` path not wired).
- **Scale-down doesn't deregister.** Removing a replica orphans its runner;
  deregistration is manual.
- **SSM Run Command** lands in the `ssm-agent` container (it has the Docker
  CLI and socket), not on a host. Unverified whether SG relies on it.
- `ecs-init` is bypassed: agent defaults it sets are copied in `runner.sh` and
  may drift with new agent releases.

# sg-runner on Kubernetes: handoff notes

Working notes for whoever continues the Kubernetes runner prototype: what was
built, why, what's verified, what isn't, and what's still open. The
user-facing description lives in [`../README.md`](../README.md) and the chart's
[`README`](../chart/sg-runner/README.md); this folder is the background behind
them.

> No secrets, account IDs or internal hostnames in these files: the repository
> may be public. QA specifics (runner group, API URL, token) live only in the
> gitignored `k8s/.env`.

| File | What's in it |
|---|---|
| [open-items.md](open-items.md) | Everything not done yet, by priority, plus the known caveats |
| [testing.md](testing.md) | What has been verified and how, what still needs testing, step-by-step test plans |
| [decisions.md](decisions.md) | Design decisions with the reasons and rejected alternatives; facts learned from StackGuardian's code and AWS |
| [dev-notes.md](dev-notes.md) | Environment gotchas and working practices for the next session |
| [gke-one-runner-per-node.md](gke-one-runner-per-node.md) | The GKE layout with one runner per node: sizing, how parking and waking behave there, suggested settings |
| [native-steps.md](native-steps.md) | Native steps (opt-in): workflow steps as pods through a step broker in the runner pod; how it works, sizing, known behaviour |
| [steps-api.md](steps-api.md) | The step broker's API (v1): the contract between the run controller and the broker |

## Status

Branch `feat/k8s-prototype`, not pushed. Prototype quality: everything
listed below works, most of it was tested against the QA platform, but it is
not a supported product.

| Area | State |
|---|---|
| Runner pod (`Dockerfile`, `runner.sh`) | Registers, advertises its real size, parks and wakes, drains through SG, prunes its Docker cache. Tested on QA. |
| Scaler (`scaler/`, Go) | Scales out on queue, parks idle runners, reaps long-parked ones, drains hard-killed ones; Events, metrics, leader election, persisted timers. Unit-tested and smoke-tested against a **fake** SG. The rules were validated on QA in the shell version it replaced; **the Go version has not run against real SG yet.** |
| Helm chart (`chart/sg-runner`) | Runner StatefulSet, scaler, credentials, size presets, workspace volume, optional NetworkPolicy and PDB, values schema. `helm lint --strict`, kubeconform, kind install with a fake API. |
| CI (`.github/workflows/k8s.yml`) | Go, chart (Helm 3 and 4), multi-arch image builds, Trivy, kind smoke. Passed locally; **never run on GitHub yet.** |
| Native steps (`runner.nativeSteps`, `scaler/internal/steps`) | Step broker, chart wiring, and the run controller's broker client (sg-run-controller, same branch name). Unit tests, kind smoke stage, and end to end on QA with an overlaid controller (OrbStack). Needs SG to ship the controller change. |
| `main.sh` fixes on this branch | Private-IP detection; error reports no longer retry themselves into a stack overflow. Both also affect VM runners. |

## Picking it up

```sh
cd k8s
cp .env.example .env          # a throwaway QA runner group's credentials
make build build-scaler       # sg-runner-k8s:dev, sg-runner-scaler:dev
make secret up                # OrbStack Kubernetes (kubectl context "orbstack")
kubectl -n sg-runner logs -f deploy/sg-runner-scaler | jq -c 'select(.msg != "loop")'
make nuke                     # always end with this: helm uninstall deregisters every runner
```

First thing to do next: the end-to-end run of the chart with the Go scaler
against QA ([testing.md](testing.md#1-end-to-end-chart--go-scaler-on-qa)).

## History (commits on the branch)

| Step | Commits |
|---|---|
| Runner pod prototype, sizing, graceful drain | `b4faa67`, `76a1595` |
| Parking, drain through SG instead of ECS | `7e07b82` |
| Shell scaler (autoscaling, stuck-queue, settle timeout, headroom) | `76ed5d2`, `9d4fef1` |
| Private-IP fix in `main.sh` | `1464dca` |
| Docker prune, version pins, multi-arch, runner tests | `f58f5a9`, `42579e4`, `2d51eb0` |
| Helm chart | `e0ae7fd`, `02021e6`, `c5c1d5d`, `0087d30` |
| Go scaler | `b23ddfc`, `7352f4f`, `2a2c3e2`, `00e1b30`, `85e0c7f`, `b7f9dd6`, `4949366` |
| Docs | `46a54fa`, `7f1ada4` |
| CI | `29f5873`, `387cb8b` |
| Error-report recursion fix in `main.sh`, Debian updates in the image | `25f059c`, `ef01b6f` |

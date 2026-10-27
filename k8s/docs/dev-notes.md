# Notes for the next session

## Environment (macOS, OrbStack)

- **Tools on PATH**: OrbStack's `docker` and `kubectl` live in
  `/usr/local/bin`, which a non-login shell may not include
  (`export PATH=/usr/local/bin:$PATH`). Helm 4 and kind come from Homebrew.
- **Always pin the kube context.** The Makefile passes `--context orbstack` to
  every command. kind switches (and on delete, unsets) the kubeconfig's
  current context; give kind its own `KUBECONFIG`, as
  `.github/scripts/kind-smoke.sh` does.
- **OrbStack Kubernetes** is single-node, arm64, Docker runtime (cri-dockerd),
  `local-path` storage. It uses local images directly: `imagePullPolicy:
  IfNotPresent` with `:dev` tags, no registry. It can't test user namespaces
  or NetworkPolicy enforcement.
- **ECR Public login**: if a stored `public.ecr.aws` login has expired, pulls
  from there fail. The Dockerfile uses the ECS agent image from Docker Hub
  instead.
- **Shell is zsh** for ad-hoc commands: arrays start at 1, `$var` doesn't
  word-split, `k()` aliases may collide. macOS `head`/`sed` differ from GNU
  (`head -n -1` doesn't exist, `sed -i ''`).
- **Helm 4 upgrades use server-side apply.** A field changed with `kubectl`
  (e.g. `kubectl set env` on the scaler) makes the next `helm upgrade` fail
  with a field-manager conflict, after applying part of the release. Change
  test settings through values (`--set scaler.min=...`), or pass
  `--force-conflicts` to take the fields back.
- **Don't upgrade with `--reuse-values`**: it keeps the *previous* chart's
  defaults, so values a newer chart added are missing (template nil pointer).
  Use `--reset-then-reuse-values`: new chart defaults, then the last
  release's values (the token included), then `-f`/`--set`.
- **Multi-arch builds** need a docker-container buildx builder;
  `make build-multiarch` creates `sg-runner-multiarch` on first use.

## Working with QA

- Use a throwaway runner group; its credentials go in `k8s/.env` (gitignored).
  Registering creates real SSM managed instances and ECS container instances.
- **Always finish with `helm uninstall`** (or `make nuke`): its pre-delete
  hook deregisters every runner, awake or parked, before deleting the PVCs.
  Deleting PVCs or the namespace first orphans runners; so does
  `helm uninstall --no-hooks`.
- The runner group's storage backend must point at a bucket its integration
  role can use, or every workflow fails at the storage check (not a runner
  problem).
- `MaxNumberOfRunners` on the group caps the scaler, and parked runners count
  against it.

## Secrets hygiene (learned the hard way)

Two QA credentials leaked into a transcript during this work. To avoid it:

- Never `cat`, `grep` or `jq .` the runner group API response or `.env`.
  Select only the fields you need with `jq`, or mask values (`sed 's/=.*/=<redacted>/'`).
- Never print `k8s/.env`; check keys with `awk -F= '{print $1, length($2)}'`.
- The Go scaler and the shell code never log response bodies; keep it that
  way (there are tests for it).

## Code conventions

- Shell: `main.sh` style (2-space indent, `#{{{ name ... #}}}: name` folds,
  `[[ ]]`, comments explain why). `make lint` enforces shellcheck plus the
  `[[ ]]` / no-backticks gate on `main.sh` and `k8s/runner.sh`.
- `runner.sh` sources `main.sh` (found next to it in the image, one level up
  in the repo) and has a `BASH_SOURCE` guard so tests can source it.
- Go scaler: rules live in the pure `internal/decide` package; change and
  test them there first. `go vet`, `gofmt`, `go test -race`.
- Chart: values documented in `values.yaml` comments and the chart README;
  the schema (`values.schema.json`) must follow any new value.
- Commit messages: `feat:` / `fix:` / `docs:`, short, plain.

## Parallel work that went well

The hardening round was split across separate worktrees (runtime, chart,
Go scaler, CI, a `main.sh` fix), each with a clear file boundary, then merged
into `feat/k8s-prototype`. What helped:

- Define the interfaces up front (env var names, mounts, RBAC, ports) and
  send changes to every agent they touch.
- Tell agents which namespaces, image tags and kube contexts are off limits
  (a live QA deployment, `:dev` images, the `orbstack` context).
- Review every result yourself before merging (rerun tests, read the diff):
  the CI agent's kind run found a real `main.sh` bug, and a reviewer caught a
  missing RBAC verb and an unimplemented env contract.

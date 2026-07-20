# Tier-3 integration tests (scaffold)

Multi-function `main.sh` flows (register, deregister, clean) driven end to end
with every host-affecting command mocked. This directory is currently a
**scaffold**: the structure, fixtures, and mock-API seam are in place, the
lightweight assertions run for real, and the heavy end-to-end assertions are
marked `skip "scaffold: ... (SG-XXXX)"` so the tier runs green while flagging
what is left to implement.

## Why a Docker image

`preflight()` in `main.sh` `die`s unless `/run/systemd/system` is a directory.
The unit and smoke tiers never reach `preflight` (they call functions directly),
but the integration tier drives whole flows through `main()`, so it has to get
past it.

The trick: `preflight` only checks that the directory *exists* — it never talks
to systemd. So a plain Linux container with

```sh
mkdir -p /run/systemd/system
```

satisfies it. Combined with the `test/mocks/bin` stubs (already first on `PATH`),
every `systemctl` / `docker` / `curl` / `iptables` call is recorded instead of
touching the host. No real systemd, no real docker.

`Dockerfile` bakes all of this in: Debian slim + bash 5 + jq + coreutils, the
repo copied to `/sg-runner`, the `mkdir`, and `PATH` pointed at the mock stubs.

## Build + run

```sh
# from the repo root
docker build -f test/integration/Dockerfile -t sg-runner-itest .

# whole tier (default CMD)
docker run --rm sg-runner-itest

# a single file
docker run --rm sg-runner-itest test/integration/register_flow.bats
```

The tier also runs on the host for everything that does not need `preflight`
(the fixture and `fetch_organization_info` tests); the full-`main` flows stay
`skip`ped off-container:

```sh
./test/lib/bats-core/bin/bats test/integration/
```

## Mock-API approach

No real HTTP server. `main.sh` reaches the API only through `api_call()`, which
shells out to the `curl` stub; the stub echoes `$MOCK_CURL_OUTPUT` and exits
`$MOCK_CURL_EXIT`. So an API response is just a string.

- `fixtures/*.http` — full HTTP response blobs (status line + headers + JSON
  body), the exact shape `api_call` parses (it reads the `HTTP/1.x NNN` status
  line and the JSON body).
- `fixtures/*.json` — the same payloads as clean JSON, handy for `jq` assertions
  on the fixtures themselves.
- `mock_api.bash` — `mock_api_response <file.http>` loads a blob into
  `MOCK_CURL_OUTPUT`; `mock_api_status <code>` forces the curl exit code.

Caveat the flows must design around: `MOCK_CURL_OUTPUT` is a single global, but
`register` curls three different things (the register API, the installer
download, and IMDSv2 probes in `preflight`). Prefer driving the specific
function (e.g. `fetch_organization_info`) over full `main()` for the API
assertions, or stub the installer download separately. See the comments in
`register_flow.bats`.

## Fixtures

| File | Purpose |
| --- | --- |
| `register_response.http` / `.json` | register API success: `RegistrationMetadata[0]` (ECSCluster/AWSDefaultRegion/SSMActivationId/SSMActivationCode), OrgName/OrgId/RunnerId/RunnerGroupId, and a V4 `RunnerGroup` with `DocVersion` + `RunnerGroupSignature`. |
| `deregister_response.http` / `.json` | deregister API success. |
| `ecs-anywhere-install.sh` | installer stub: `#!/bin/bash` shebang (passes `register_instance`'s sanity check) + `exit 0`. |

## Checklist: flows still to implement

- [ ] **register happy path** — drive `register`, assert `${ECS_CONFIG_DIR}/ecs.config`
      rendered (ECS_CLUSTER, AWS_DEFAULT_REGION, V4 `sg_runner_group_signature`),
      assert `docker network create` and the `iptables` DOCKER-USER + 169.254.170.2
      rules. Needs the installer download pointed at the stub and the
      `ecs-agent inspect ... healthy` loop to terminate fast.
- [ ] **register already-healthy short-circuit** — `MOCK_DOCKER_PS_OUTPUT` set +
      inspect `healthy`; assert it exits 0 via the already-registered branch,
      runs `configure_local_network`, and never curls `register/`.
- [ ] **deregister happy path** — seed a V4 `ecs.config`, mock the deregister
      response, assert `curl deregister/`, `docker stop/rm ecs-agent`, and
      `docker network rm sg-net`.
- [ ] **deregister `--force` when config missing** — no `ecs.config`; assert
      `force_exec` lets `clean_local_setup` run anyway.
- [ ] **clean** — `clean_local_setup` removes config and tears down the docker
      network; assert the docker stop/rm + network rm calls.
- [ ] **in-process `fetch_organization_info` globals** — call without `run`,
      assert ECS_CLUSTER / region / SSM id+code / V4 signature globals.

When implementing, replace each `skip` with the real body sketched in the
test's comment, and run the tier inside the image (above).

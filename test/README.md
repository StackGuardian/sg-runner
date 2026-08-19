# `main.sh` test suite

A [bats-core](https://github.com/bats-core/bats-core) suite for `main.sh`, the
StackGuardian private-runner registration CLI. bats-core and its helper
libraries are vendored under `test/lib/` — nothing is downloaded at runtime.

## Layout

```
test/
  lib/                 vendored bats-core, bats-support, bats-assert (do not edit)
  helpers/
    load.bash          single entry point every test sources
    mocks.bash         assertions over the mock call log
  mocks/bin/           stub executables shadowing every external command
  unit/                pure-function tests (one function, no I/O)
  smoke/               CLI-contract tests (main.sh run as a subprocess)
  fixtures/            canned input files
```

## The seam contract

`main.sh` is built to be sourced safely:

- **Side-effect-free sourcing.** `main.sh` only runs `main "$@"` under
  `[[ "${BASH_SOURCE[0]}" == "${0}" ]]`. `source main.sh` therefore defines all
  functions and runs nothing — tests call functions directly.
- **Path overrides via env.** Every path it writes to is overridable:
  `LOG_FILE`, `SG_DIAGNOSTIC_DIR` (`SG_DIAGNOSTIC_FILE` /
  `SG_DIAGNOSTIC_TMP_FILE` derive from it), `ECS_CONFIG_DIR`, `ECS_LOG_DIR`,
  `ECS_DATA_DIR`, `ECS_EXEC_DEPS_DIR`, `REGISTRATION_DIR`. `load.bash` points
  all of these at a per-test temp dir, so a test never touches real system
  paths. This matters most for `ECS_EXEC_DEPS_DIR`: `remove_ecs_exec_deps`
  runs `rm -rf` on it.
- **Root bypass.** `SG_SKIP_ROOT_CHECK=true` makes `is_root()` succeed without
  root. `load.bash` sets it.
- **API + debug.** `SG_BASE_API` overrides the API base; `LOG_DEBUG=true`
  enables debug logging.
- **External commands are stubbed.** `load.bash` prepends `test/mocks/bin` to
  `PATH`, so every `systemctl`, `docker`, `curl`, ... resolves to a stub that
  records its call instead of touching the host.

## Running

bats-core and its helper libs are **git submodules** under `test/lib/`. After a
fresh clone:

```sh
git submodule update --init --recursive
```

The `Makefile` at the repo root wraps the canonical commands:

```sh
make test              # every tier (unit + smoke)
make test-unit         # one tier
make test-smoke
make lint              # shellcheck: correctness + modern-idiom gate
```

Or invoke the vendored runner directly from the repo root:

```sh
BATS=./test/lib/bats-core/bin/bats

# one file
$BATS test/unit/harness.bats

# a whole tier
$BATS --recursive test/unit
$BATS --recursive test/smoke

# everything — scope to the tier dirs, NOT `--recursive test/`
$BATS --recursive test/unit test/smoke
```

Scope to the tier dirs. `--recursive test/` descends into the vendored
libraries' own bats suites under `test/lib/` and errors out.

Requires GNU bash 5+ first on `PATH` (Homebrew `/opt/homebrew/bin/bash` on
macOS). The vendored `bats` runs under `/usr/bin/env bash`.

## Linting & conventions

`make lint` (also a CI job) runs `shellcheck` two ways over `main.sh`, the mock
stubs, and the bash helpers:

1. **Correctness** — the default warning-and-up checks.
2. **Modern-idiom gate** — enforces current Bash conventions regardless of
   severity: `[[ ]]` over `[ ]` (SC2292) and `$(...)` over backticks (SC2006).

Rules live in `.shellcheckrc` at the repo root (`enable=require-double-brackets`,
`enable=deprecate-which`, and `disable=SC2034` for the intentionally-exported
globals), so editors and CI apply the same conventions. `.bats` files are not
shellchecked — their `@test` syntax isn't valid standalone Bash.

## Writing a test

Every test file starts the same way:

```bash
setup() {
  load "${BATS_TEST_DIRNAME}/../helpers/load.bash"
}

@test "what it does" {
  # 1. tweak any MOCK_* / SG_* env vars for this case (optional)
  export MOCK_SYSTEMCTL_IS_ACTIVE="inactive"

  # 2. source main.sh AFTER the env tweaks
  load_main

  # 3. call the function. Use `run` for functions that may call die/exit.
  run some_function arg1 arg2

  # 4. assert on $status / $output and on recorded mock calls
  assert_success
  assert_called systemctl "is-active"
}
```

Order matters: set env, then `load_main`, then exercise. Use `run` whenever the
function under test may call `die` (which exits) so the non-zero exit is
captured instead of aborting the test.

## Mocks

Each file in `test/mocks/bin/` shadows one external command. Every stub appends
one line per invocation to `$MOCK_CALL_LOG` as `"<name> <args...>"`, emits
canned stdout controlled by an env var, and exits with a controllable code.

Set the override env vars **before** calling the function under test. Use
`reset_mocks` between phases of one test when you need a clean log (e.g. two
`curl` calls with different responses).

| Command     | stdout override (default)                                                              | exit override (default)     |
| ----------- | -------------------------------------------------------------------------------------- | --------------------------- |
| `systemctl` | `MOCK_SYSTEMCTL_IS_ACTIVE` (`active`), `MOCK_SYSTEMCTL_IS_ENABLED` (`enabled`)          | `MOCK_SYSTEMCTL_EXIT` (`0`) |
| `docker`    | `MOCK_DOCKER_PS_OUTPUT` (empty), `MOCK_DOCKER_INSPECT_OUTPUT` (`healthy`), `MOCK_DOCKER_SYSTEM_OUTPUT` (`Total reclaimed space: 0B`) | `MOCK_DOCKER_EXIT` (`0`) |
| `curl`      | `MOCK_CURL_OUTPUT` (empty)                                                              | `MOCK_CURL_EXIT` (`0`)      |
| `crontab`   | `MOCK_CRONTAB_LIST` (empty; used by `crontab -l`)                                       | `MOCK_CRONTAB_EXIT` (`0`)   |
| `iptables`  | (no stdout); `MOCK_IPTABLES_CHECK_EXIT` (`1`) is the exit for `-C` rule checks          | `MOCK_IPTABLES_EXIT` (`0`)  |
| `ip`        | `MOCK_IP_ROUTE_OUTPUT` (default route, field 9 = `10.0.0.1`)                            | `MOCK_IP_EXIT` (`0`)        |
| `free`      | `MOCK_FREE_OUTPUT` (a minimal `free -h` table)                                          | `MOCK_FREE_EXIT` (`0`)      |
| `nproc`     | `MOCK_NPROC_OUTPUT` (`4`)                                                               | `MOCK_NPROC_EXIT` (`0`)     |
| `uptime`    | `MOCK_UPTIME_OUTPUT` (a typical `uptime` line with load average)                        | `MOCK_UPTIME_EXIT` (`0`)    |
| `top`       | `MOCK_TOP_OUTPUT` (a `%Cpu(s)` summary line)                                            | `MOCK_TOP_EXIT` (`0`)       |
| `df`        | `MOCK_DF_OUTPUT` (a `df` table ending in a `total` line)                                | `MOCK_DF_EXIT` (`0`)        |
| `sysctl`    | (no stdout)                                                                            | `MOCK_SYSCTL_EXIT` (`0`)    |
| `reboot`    | (no stdout; never reboots)                                                              | `MOCK_REBOOT_EXIT` (`0`)    |
| `grubby`    | (no stdout)                                                                            | `MOCK_GRUBBY_EXIT` (`0`)    |

### Assertion helpers (`mocks.bash`, loaded for you by `load.bash`)

- `assert_called <cmd> [substring]` — fail unless `<cmd>` ran at least once
  (and, if given, an invocation contained `<substring>`).
- `refute_called <cmd>` — fail if `<cmd>` ran at all.
- `mock_calls <cmd>` — echo every recorded invocation of `<cmd>`.
- `reset_mocks` — truncate `$MOCK_CALL_LOG`.

bats-support / bats-assert are also loaded, so `assert_success`,
`assert_failure`, `assert_output`, `assert_line`, etc. are available.

## Tiers

- **unit/** — one pure function, no orchestration. Source `main.sh`, call the
  function, assert on return/output. `harness.bats` lives here as the canary.
- **smoke/** — run `main.sh` as a subprocess and assert its CLI contract (help,
  command validation, required-argument enforcement) — the surface that exits
  before `preflight()`, so it needs no systemd, docker, or root.

## Caveats / known limitations

- `crontab` is invoked two ways in `main.sh`: bare `crontab` (stubbed via
  `PATH`) and absolute `/usr/bin/crontab` (the install step). The absolute path
  bypasses the stub. Tests that need to observe the install call should assert
  on the generated crontab temp file rather than on `assert_called crontab`,
  or skip that step.
- Core text tools (`grep`, `sed`, `awk`, `cat`, `tail`, `cut`, `tr`, `df`'s
  pipeline consumers) are **not** stubbed — they run for real against the
  per-test temp dir. Only host-affecting / network commands are mocked. `tail`
  and `grep` were intentionally left un-stubbed: `main.sh` uses them as plain
  text filters over files we already control, so real binaries give correct,
  simpler behavior than a stub would.

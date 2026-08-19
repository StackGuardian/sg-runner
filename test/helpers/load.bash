# shellcheck shell=bash
#
# load.bash - single entry point every test sources.
#
# Usage (top of every .bats file):
#   load "${BATS_TEST_DIRNAME}/../helpers/load.bash"
#
# It:
#   - Locates the repo root and main.sh independent of CWD.
#   - Redirects every overridable path in main.sh into a per-test temp dir.
#   - Sets SG_SKIP_ROOT_CHECK=true so is_root() succeeds without root.
#   - Prepends the mock bin dir to PATH and creates an empty MOCK_CALL_LOG.
#   - Loads bats-support + bats-assert from the vendored copies under test/lib.
#   - Defines load_main, which sources main.sh on demand.

# Resolve the directory holding THIS file, following symlinks, without relying
# on CWD. BASH_SOURCE[0] is the path to load.bash itself.
_load_self="${BASH_SOURCE[0]}"
while [[ -h "${_load_self}" ]]; do
  _dir="$(cd -P "$(dirname "${_load_self}")" >/dev/null 2>&1 && pwd)"
  _load_self="$(readlink "${_load_self}")"
  [[ "${_load_self}" != /* ]] && _load_self="${_dir}/${_load_self}"
done

# test/helpers/load.bash -> repo root is two levels up.
SG_TEST_HELPERS_DIR="$(cd -P "$(dirname "${_load_self}")" >/dev/null 2>&1 && pwd)"
SG_TEST_DIR="$(cd -P "${SG_TEST_HELPERS_DIR}/.." >/dev/null 2>&1 && pwd)"
SG_REPO_ROOT="$(cd -P "${SG_TEST_DIR}/.." >/dev/null 2>&1 && pwd)"
SG_MAIN_SH="${SG_REPO_ROOT}/main.sh"
export SG_TEST_HELPERS_DIR SG_TEST_DIR SG_REPO_ROOT SG_MAIN_SH
unset _load_self _dir

# Per-test scratch dir. bats sets BATS_TEST_TMPDIR per test; fall back to a
# fresh mktemp dir when sourced outside a running test.
if [[ -n "${BATS_TEST_TMPDIR:-}" ]]; then
  SG_TEST_TMPDIR="${BATS_TEST_TMPDIR}"
else
  SG_TEST_TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/sg-runner-test.XXXXXX")"
fi
export SG_TEST_TMPDIR

# Redirect every path main.sh lets us override into the scratch dir, so a test
# never touches real system paths. main.sh derives SG_DIAGNOSTIC_FILE /
# SG_DIAGNOSTIC_TMP_FILE from SG_DIAGNOSTIC_DIR, so we only set the dir.
export LOG_FILE="${SG_TEST_TMPDIR}/sg_runner.log"
export SG_DIAGNOSTIC_DIR="${SG_TEST_TMPDIR}/sg-runner"
export ECS_CONFIG_DIR="${SG_TEST_TMPDIR}/etc-ecs"
export ECS_LOG_DIR="${SG_TEST_TMPDIR}/var-log-ecs"
export ECS_DATA_DIR="${SG_TEST_TMPDIR}/var-lib-ecs-data"
export ECS_EXEC_DEPS_DIR="${SG_TEST_TMPDIR}/var-lib-ecs-deps/execute-command"
export REGISTRATION_DIR="${SG_TEST_TMPDIR}/registration"

# Bypass the root requirement.
export SG_SKIP_ROOT_CHECK="true"

# Where mock stubs record their invocations. Created empty here so assertions
# work even before any mock runs.
export MOCK_CALL_LOG="${SG_TEST_TMPDIR}/mock_calls.log"
: >"${MOCK_CALL_LOG}"

# Make the mock stubs win over the real binaries.
PATH="${SG_TEST_DIR}/mocks/bin:${PATH}"
export PATH

# Vendored bats helper libraries.
load "${SG_TEST_DIR}/lib/bats-support/load.bash"
load "${SG_TEST_DIR}/lib/bats-assert/load.bash"

# Assertion helpers for the mock call log.
load "${SG_TEST_HELPERS_DIR}/mocks.bash"

# Source main.sh, exposing all of its functions in the current shell. Call this
# AFTER any per-test env tweaks (e.g. flipping a MOCK_* override).
#
# main.sh runs under `set -o pipefail`; sourcing it must not abort the test, so
# we guard the source and surface a clear failure if it errors.
load_main() {
  # shellcheck source=/dev/null
  if ! source "${SG_MAIN_SH}"; then
    echo "load_main: failed to source ${SG_MAIN_SH}" >&2
    return 1
  fi
}

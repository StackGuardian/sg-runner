# shellcheck shell=bash
#
# k8s.bash - extra setup for tests of k8s/runner.sh. Load after load.bash:
#   load "${BATS_TEST_DIRNAME}/../helpers/load.bash"
#   load "${BATS_TEST_DIRNAME}/../helpers/k8s.bash"

SG_RUNNER_SH="${SG_REPO_ROOT}/k8s/runner.sh"
export SG_RUNNER_SH

# Fake /proc files the agent sizing reads, so no test depends on the host.
export PROC_STATUS_FILE="${SG_TEST_TMPDIR}/proc-self-status"
export MEMINFO_FILE="${SG_TEST_TMPDIR}/proc-meminfo"

# Source runner.sh (which sources main.sh from the repo root), exposing its
# functions. Its dispatcher only runs when executed, so nothing starts.
load_runner() {
  # shellcheck source=/dev/null
  if ! source "${SG_RUNNER_SH}"; then
    echo "load_runner: failed to source ${SG_RUNNER_SH}" >&2
    return 1
  fi
}

# Usage: fake_cpus_allowed <list>, e.g. "0-3,8-11"
fake_cpus_allowed() {
  printf 'Name:\tawk\nCpus_allowed:\tff\nCpus_allowed_list:\t%s\nMems_allowed_list:\t0\n' \
    "$1" >"${PROC_STATUS_FILE}"
}

# Usage: fake_mem_total_mib <MiB>
fake_mem_total_mib() {
  printf 'MemTotal:       %d kB\nMemFree:         1024 kB\n' "$(($1 * 1024))" >"${MEMINFO_FILE}"
}

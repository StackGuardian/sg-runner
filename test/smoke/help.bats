#!/usr/bin/env bats
#
# Smoke tests for the help / no-args path of main.sh, invoked as a subprocess.
#
# main() handles help before any other work:
#   [[ "${*}" =~ --help || $# -lt 1 ]] && show_help && exit 0
# so --help anywhere in the args, and the no-args case, print help and exit 0
# without ever reaching is_root, init_args_are_valid, or preflight.

setup() {
  load "${BATS_TEST_DIRNAME}/../helpers/load.bash"
}

@test "--help exits 0 and prints the help banner" {
  run bash "$SG_MAIN_SH" --help
  assert_success
  assert_output --partial "sg-runner"
  assert_output --partial "Available commands"
}

@test "--help lists every documented command" {
  run bash "$SG_MAIN_SH" --help
  assert_success
  assert_output --partial "register"
  assert_output --partial "deregister"
  assert_output --partial "status"
  assert_output --partial "prune"
  assert_output --partial "clean"
}

@test "no args prints help and exits 0" {
  run bash "$SG_MAIN_SH"
  assert_success
  assert_output --partial "sg-runner"
  assert_output --partial "Available commands"
}

@test "--help anywhere in the args short-circuits to help" {
  run bash "$SG_MAIN_SH" register --help
  assert_success
  assert_output --partial "Available commands"
}

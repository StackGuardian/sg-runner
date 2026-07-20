#!/usr/bin/env bats
#
# Smoke tests for the required-flag checks in init_args_are_valid, invoked as a
# subprocess. register and deregister both require --sg-node-token,
# --organization and --runner-group; init_args_are_valid dies if any is absent.
#
# This runs before preflight in main(), so a register/deregister that is
# MISSING a required flag fails with the required-args message rather than the
# systemd message -- the assertions below confirm that boundary holds.

setup() {
  load "${BATS_TEST_DIRNAME}/../helpers/load.bash"
}

@test "register with no flags fails listing the three required flags" {
  run bash "$SG_MAIN_SH" register
  assert_failure
  assert_output --partial "--sg-node-token, --organization, --runner-group"
}

@test "register missing --runner-group fails at init_args_are_valid, not preflight" {
  run bash "$SG_MAIN_SH" register --sg-node-token t --organization o
  assert_failure
  # The required-args check runs before preflight, so we see that message ...
  assert_output --partial "--sg-node-token, --organization, --runner-group"
  # ... and NOT the systemd die from preflight.
  refute_output --partial "systemd-based"
}

@test "deregister missing --sg-node-token fails for the required flags" {
  run bash "$SG_MAIN_SH" deregister --organization o --runner-group g
  assert_failure
  assert_output --partial "--sg-node-token, --organization, --runner-group"
  refute_output --partial "systemd-based"
}

@test "DOCUMENTING: fully-valid subcommands reach preflight (not covered here)" {
  # A register with all required flags passes init_args_are_valid and proceeds
  # to preflight, which hard-dies on any non-systemd host ([[ ! -d
  # /run/systemd/system ]]). On macOS that always fires, so a fully-valid
  # subcommand cannot be exercised end to end by this host-only suite.
  # Likewise status/prune/info/clean pass validation and reach preflight.
  skip "valid subcommands reach preflight; not exercised by the host-only suite"
}

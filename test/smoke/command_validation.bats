#!/usr/bin/env bats
#
# Smoke tests for command validation in init_args_are_valid, invoked as a
# subprocess. init_args_are_valid runs in main() right after is_root and well
# before preflight, so these invalid-command cases die before the systemd
# check, even on a non-systemd host.

setup() {
  load "${BATS_TEST_DIRNAME}/../helpers/load.bash"
}

@test "an unknown command fails as invalid" {
  run bash "$SG_MAIN_SH" bogus
  assert_failure
  assert_output --partial "is invalid"
}

@test "cgroupsv2 without enable|disable fails listing the choices" {
  run bash "$SG_MAIN_SH" cgroupsv2
  assert_failure
  assert_output --partial "enable, disable"
}

@test "cgroupsv2 with an unknown subcommand fails" {
  run bash "$SG_MAIN_SH" cgroupsv2 frobnicate
  assert_failure
  assert_output --partial "enable, disable"
}

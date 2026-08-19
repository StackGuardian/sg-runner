#!/usr/bin/env bats
#
# Unit tests for init_args_are_valid - the first-pass gate on the subcommand
# and its required companion flags, run before parse_arguments.

setup() {
  load "${BATS_TEST_DIRNAME}/../helpers/load.bash"
  load_main
}

@test "init_args_are_valid rejects an unknown subcommand" {
  run init_args_are_valid bogus
  assert_failure
  assert_output --partial "is invalid"
}

@test "init_args_are_valid accepts status with no extra args" {
  run init_args_are_valid status
  assert_success
}

@test "init_args_are_valid accepts info with no extra args" {
  run init_args_are_valid info
  assert_success
}

@test "init_args_are_valid accepts prune with no extra args" {
  run init_args_are_valid prune
  assert_success
}

@test "init_args_are_valid accepts clean with no extra args" {
  run init_args_are_valid clean
  assert_success
}

@test "init_args_are_valid accepts cgroupsv2 enable" {
  run init_args_are_valid cgroupsv2 enable
  assert_success
}

@test "init_args_are_valid accepts cgroupsv2 disable" {
  run init_args_are_valid cgroupsv2 disable
  assert_success
}

@test "init_args_are_valid dies on cgroupsv2 without enable/disable" {
  run init_args_are_valid cgroupsv2
  assert_failure
  assert_output --partial "enable, disable"
}

@test "init_args_are_valid accepts register with all three required flags" {
  run init_args_are_valid register \
    --sg-node-token tok --organization org --runner-group grp
  assert_success
}

@test "init_args_are_valid dies on register missing --runner-group" {
  run init_args_are_valid register --sg-node-token tok --organization org
  assert_failure
  assert_output --partial "--sg-node-token, --organization, --runner-group"
}

@test "init_args_are_valid dies on register with no flags" {
  run init_args_are_valid register
  assert_failure
  assert_output --partial "are required"
}

@test "init_args_are_valid accepts deregister with all three required flags" {
  run init_args_are_valid deregister \
    --sg-node-token tok --organization org --runner-group grp
  assert_success
}

@test "init_args_are_valid dies on deregister missing --organization" {
  run init_args_are_valid deregister --sg-node-token tok --runner-group grp
  assert_failure
  assert_output --partial "are required"
}

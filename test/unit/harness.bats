#!/usr/bin/env bats
#
# Canary test for the test harness itself. Proves:
#   (a) main.sh sources cleanly via load_main,
#   (b) a pure function behaves (validate_runner_id accept/reject),
#   (c) a mock records its invocation and assert_called sees it.

setup() {
  load "${BATS_TEST_DIRNAME}/../helpers/load.bash"
}

@test "main.sh sources cleanly via load_main" {
  run load_main
  assert_success
}

@test "load_main exposes functions in the current shell" {
  load_main
  declare -F validate_runner_id >/dev/null
  declare -F is_root >/dev/null
}

@test "validate_runner_id accepts a well-formed id" {
  load_main
  run validate_runner_id good-id_1
  assert_success
}

@test "validate_runner_id rejects an id with shell metacharacters" {
  load_main
  run validate_runner_id 'bad;id'
  assert_failure
}

@test "invoking a mock records to MOCK_CALL_LOG and assert_called sees it" {
  run systemctl is-active foo
  assert_success
  assert_called systemctl
  assert_called systemctl "is-active foo"
}

@test "refute_called passes for a command that was never invoked" {
  refute_called docker
}

@test "reset_mocks clears the call log" {
  systemctl is-active foo
  assert_called systemctl
  reset_mocks
  refute_called systemctl
}

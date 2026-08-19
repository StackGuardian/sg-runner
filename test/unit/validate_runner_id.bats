#!/usr/bin/env bats
#
# Unit tests for validate_runner_id - allows only [A-Za-z0-9_-], to block
# injection through the runner id.

setup() {
  load "${BATS_TEST_DIRNAME}/../helpers/load.bash"
  load_main
}

@test "validate_runner_id accepts alphanumerics, hyphen, underscore" {
  run validate_runner_id "abc-123_DEF"
  assert_success
}

@test "validate_runner_id rejects shell metacharacters" {
  run validate_runner_id "bad;id"
  assert_failure
  assert_output --partial "Invalid RUNNER_ID format"
}

@test "validate_runner_id rejects whitespace" {
  run validate_runner_id "a b"
  assert_failure
  assert_output --partial "Invalid RUNNER_ID format"
}

@test "validate_runner_id rejects command substitution" {
  run validate_runner_id 'id$(x)'
  assert_failure
  assert_output --partial "Invalid RUNNER_ID format"
}

@test "validate_runner_id rejects path traversal" {
  run validate_runner_id "../x"
  assert_failure
  assert_output --partial "Invalid RUNNER_ID format"
}

@test "validate_runner_id rejects empty input" {
  run validate_runner_id ""
  assert_failure
  assert_output --partial "Invalid RUNNER_ID format"
}

@test "validate_runner_id rejects forward slash" {
  run validate_runner_id "a/b"
  assert_failure
  assert_output --partial "Invalid RUNNER_ID format"
}

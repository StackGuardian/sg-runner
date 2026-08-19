#!/usr/bin/env bats
#
# Unit tests for parse_arguments - the option loop that populates the SG
# identity globals, proxy settings, and behavior flags.
#
# parse_arguments sets GLOBALS as a side effect. `run` would execute it in a
# subshell where those assignments are invisible, so success cases call it
# directly and then assert the global. Dying cases use `run` to capture exit.

setup() {
  load "${BATS_TEST_DIRNAME}/../helpers/load.bash"
  load_main
}

@test "parse_arguments sets SG_NODE_TOKEN from --sg-node-token" {
  parse_arguments --sg-node-token my-token
  assert_equal "$SG_NODE_TOKEN" "my-token"
}

@test "parse_arguments sets ORGANIZATION_ID from --organization" {
  parse_arguments --organization my-org
  assert_equal "$ORGANIZATION_ID" "my-org"
}

@test "parse_arguments sets RUNNER_GROUP_ID from --runner-group" {
  parse_arguments --runner-group my-group
  assert_equal "$RUNNER_GROUP_ID" "my-group"
}

@test "parse_arguments sets all three identity globals together" {
  parse_arguments \
    --sg-node-token tok --organization org --runner-group grp
  assert_equal "$SG_NODE_TOKEN" "tok"
  assert_equal "$ORGANIZATION_ID" "org"
  assert_equal "$RUNNER_GROUP_ID" "grp"
}

@test "parse_arguments sets HTTP_PROXY from a valid --http-proxy" {
  parse_arguments --http-proxy host:80
  assert_equal "$HTTP_PROXY" "host:80"
}

@test "parse_arguments dies on a malformed --http-proxy" {
  run parse_arguments --http-proxy "bad;cmd"
  assert_failure
  assert_output --partial "Invalid proxy format"
}

@test "parse_arguments appends --no-proxy to the default NO_PROXY" {
  # The default NO_PROXY already carries the ECS/SSM bypass addresses; a
  # user-supplied value must be appended (comma-joined), not replace them.
  local before="$NO_PROXY"
  parse_arguments --no-proxy 10.1.2.3
  assert_equal "$NO_PROXY" "${before},10.1.2.3"
}

@test "parse_arguments -f sets FORCE_PASS" {
  parse_arguments -f
  assert_equal "$FORCE_PASS" "true"
}

@test "parse_arguments --force sets FORCE_PASS" {
  parse_arguments --force
  assert_equal "$FORCE_PASS" "true"
}

@test "parse_arguments --no-clean-on-fail sets NO_CLEAN_ON_FAIL" {
  parse_arguments --no-clean-on-fail
  assert_equal "$NO_CLEAN_ON_FAIL" "true"
}

@test "parse_arguments --debug sets LOG_DEBUG" {
  parse_arguments --debug
  assert_equal "$LOG_DEBUG" "true"
}

@test "parse_arguments dies on an unknown argument" {
  run parse_arguments --bogus
  assert_failure
  assert_output --partial "Invalid argument"
}

@test "parse_arguments returns cleanly on an empty arg list" {
  run parse_arguments
  assert_success
}

#!/usr/bin/env bats
#
# Unit tests for the small argument/variable guards:
#   check_arg_value <name> <value>  - rejects --flag-looking and empty values
#   check_sg_args                    - requires the three SG identity globals
#   check_variable_value <name>      - rejects an empty named variable

setup() {
  load "${BATS_TEST_DIRNAME}/../helpers/load.bash"
  load_main
}

# --- check_arg_value -------------------------------------------------------

@test "check_arg_value accepts a normal value" {
  run check_arg_value "--organization" "my-org"
  assert_success
}

@test "check_arg_value rejects a value that looks like a flag" {
  run check_arg_value "--organization" "--runner-group"
  assert_failure
  assert_output --partial "has invalid value"
}

@test "check_arg_value rejects an empty value" {
  run check_arg_value "--organization" ""
  assert_failure
  assert_output --partial "can't be empty"
}

# --- check_sg_args ---------------------------------------------------------

@test "check_sg_args succeeds when all three identity globals are set" {
  SG_NODE_TOKEN="token"
  ORGANIZATION_ID="org"
  RUNNER_GROUP_ID="group"
  run check_sg_args
  assert_success
}

@test "check_sg_args dies when SG_NODE_TOKEN is empty" {
  SG_NODE_TOKEN=""
  ORGANIZATION_ID="org"
  RUNNER_GROUP_ID="group"
  run check_sg_args
  assert_failure
  assert_output --partial "--sg-node-token, --organization, --runner-group"
}

@test "check_sg_args dies when ORGANIZATION_ID is empty" {
  SG_NODE_TOKEN="token"
  ORGANIZATION_ID=""
  RUNNER_GROUP_ID="group"
  run check_sg_args
  assert_failure
  assert_output --partial "are required"
}

@test "check_sg_args dies when RUNNER_GROUP_ID is empty" {
  SG_NODE_TOKEN="token"
  ORGANIZATION_ID="org"
  RUNNER_GROUP_ID=""
  run check_sg_args
  assert_failure
  assert_output --partial "are required"
}

# --- check_variable_value --------------------------------------------------

@test "check_variable_value succeeds when the named var is set" {
  MY_VAR="something"
  run check_variable_value MY_VAR
  assert_success
}

@test "check_variable_value dies when the named var is empty" {
  MY_VAR=""
  run check_variable_value MY_VAR
  assert_failure
  assert_output --partial "Variable can't be empty"
}

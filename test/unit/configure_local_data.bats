#!/usr/bin/env bats
#
# Unit tests for configure_local_data: it writes ${ECS_CONFIG_DIR}/ecs.config
# from a handful of globals. The file is fully deterministic from those inputs
# (no timestamps), so we both diff a V4 golden file and assert the conditional
# branches: the V4-only sg_runner_group_signature attribute, and the optional
# HTTP_PROXY block.

setup() {
  load "${BATS_TEST_DIRNAME}/../helpers/load.bash"
  export ECS_CLUSTER="sg-cluster"
  export LOCAL_AWS_DEFAULT_REGION="us-east-1"
  export ORGANIZATION_NAME="demo-org"
  export RUNNER_ID="runner-1"
  export RUNNER_GROUP_ID="rg-1"
  export SG_RUNNER_GROUP_SIGNATURE="sig-abc"
}

# main.sh assigns NO_PROXY at source time (top-level default), so an env export
# before load_main is clobbered. Set it AFTER load_main when a test needs a
# known value.

config_file() { echo "${ECS_CONFIG_DIR}/ecs.config"; }

@test "V4 config matches the golden file (signature included, no proxy)" {
  export RUNNER_GROUP_DOC_VERSION="V4"
  export HTTP_PROXY=""
  load_main

  configure_local_data

  run diff "${BATS_TEST_DIRNAME}/../fixtures/ecs/ecs.config.v4.golden" "$(config_file)"
  assert_success
}

@test "V4 includes sg_runner_group_signature in ECS_INSTANCE_ATTRIBUTES" {
  export RUNNER_GROUP_DOC_VERSION="V4"
  export HTTP_PROXY=""
  load_main

  configure_local_data

  run grep '^ECS_INSTANCE_ATTRIBUTES=' "$(config_file)"
  assert_output --partial '"sg_runner_group_signature": "sig-abc"'
}

@test "non-V4 omits sg_runner_group_signature" {
  export RUNNER_GROUP_DOC_VERSION="V3"
  export HTTP_PROXY=""
  load_main

  configure_local_data

  run grep '^ECS_INSTANCE_ATTRIBUTES=' "$(config_file)"
  refute_output --partial "sg_runner_group_signature"
  assert_output --partial '"sg_organization": "demo-org"'
  assert_output --partial '"sg_runner_group_id": "rg-1"'
}

@test "core ECS settings are always present" {
  export RUNNER_GROUP_DOC_VERSION="V4"
  export HTTP_PROXY=""
  load_main

  configure_local_data
  local f
  f="$(config_file)"

  assert_equal "$(grep -c '^ECS_CLUSTER=sg-cluster$' "$f")" "1"
  assert_equal "$(grep -c '^AWS_DEFAULT_REGION=us-east-1$' "$f")" "1"
  assert_equal "$(grep -c '^ECS_EXTERNAL=true$' "$f")" "1"
}

@test "HTTP_PROXY set: appends the proxy block" {
  export RUNNER_GROUP_DOC_VERSION="V4"
  export HTTP_PROXY="proxy.local:3128"
  load_main
  NO_PROXY="localhost,127.0.0.1"

  configure_local_data
  local f
  f="$(config_file)"

  assert_equal "$(grep -c '^HTTP_PROXY=proxy.local:3128$' "$f")" "1"
  assert_equal "$(grep -c '^HTTPS_PROXY=proxy.local:3128$' "$f")" "1"
  assert_equal "$(grep -c '^NO_PROXY=localhost,127.0.0.1$' "$f")" "1"
}

@test "HTTP_PROXY unset: no proxy block appended" {
  export RUNNER_GROUP_DOC_VERSION="V4"
  export HTTP_PROXY=""
  load_main

  configure_local_data
  local f
  f="$(config_file)"

  refute [ -n "$(grep '^HTTP_PROXY=' "$f")" ]
  refute [ -n "$(grep '^HTTPS_PROXY=' "$f")" ]
}

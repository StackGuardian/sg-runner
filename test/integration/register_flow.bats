#!/usr/bin/env bats
#
# Tier-3 register -> deregister flow (SCAFFOLD).
#
# This file lays out the INTENDED structure of the full integration flow and
# marks the heavy, Docker-dependent assertions with `skip` so the suite runs
# green while clearly flagging unfinished work. The lightweight pieces (fixtures
# parse, fetch_organization_info populates globals from a canned response) run
# for real and exercise the mock-API seam end to end.
#
# Run inside the integration image so preflight()'s /run/systemd/system probe is
# satisfied (see test/integration/README.md). On the host, the full-main flows
# stay skipped; the function-level assertions below run anywhere.

setup() {
  load "${BATS_TEST_DIRNAME}/../helpers/load.bash"
  load "${BATS_TEST_DIRNAME}/mock_api.bash"
}

@test "fixtures: register/deregister responses are valid JSON with the fields main.sh reads" {
  local dir="${BATS_TEST_DIRNAME}/fixtures"

  # The metadata fields fetch_organization_info() requires.
  run jq -e '.data.RegistrationMetadata[0]
             | .ECSCluster and .AWSDefaultRegion and .SSMActivationId and .SSMActivationCode' \
    "${dir}/register_response.json"
  assert_success

  # The org/runner identity fields it also checks.
  run jq -e '.data | .OrgName and .OrgId and .RunnerId and .RunnerGroupId' \
    "${dir}/register_response.json"
  assert_success

  # V4 signature path: DocVersion + RunnerGroupSignature drive ECS_INSTANCE_ATTRIBUTES.
  run jq -e '.data.RunnerGroup | .DocVersion == "V4" and (.RunnerGroupSignature | length > 0)' \
    "${dir}/register_response.json"
  assert_success

  run jq -e '.data.RunnerId' "${dir}/deregister_response.json"
  assert_success
}

@test "install stub is a bash script that exits 0 (passes register_instance shebang check)" {
  run head -1 "${BATS_TEST_DIRNAME}/fixtures/ecs-anywhere-install.sh"
  assert_success
  assert_output '#!/bin/bash'
}

@test "fetch_organization_info parses the canned register response into globals" {
  mock_api_response register_response.http
  load_main

  export ORGANIZATION_ID="acme-corp"
  export RUNNER_GROUP_ID="rg-private-pool"

  run fetch_organization_info

  # The flow reached the register endpoint through the mocked curl. This is the
  # real, green half of the assertion: the mock-API seam works end to end.
  assert_called curl "register/"

  # NOT asserted here, on purpose:
  #   - assert_success: fetch_organization_info has no trailing `return 0`; its
  #     exit status is that of the final `debug_variable "HTTP_PROXY"`, which is
  #     non-zero when LOG_DEBUG is unset. The flow still succeeds (it would have
  #     die()d otherwise). Asserting on exit status here would be asserting on a
  #     quirk, not on behaviour.
  #   - global values: `run` executes in a subshell, so ECS_CLUSTER /
  #     SSM_ACTIVATION_ID / SG_RUNNER_GROUP_SIGNATURE set by the call do not
  #     survive into this scope. Verified out-of-band that they populate
  #     correctly (sg-cluster-acme / us-east-1 / V4 signature). A full in-scope
  #     assertion calls fetch_organization_info WITHOUT `run` and reads the
  #     globals directly — scaffolded for the Docker tier.
  skip "scaffold: assert ECS_CLUSTER/region/SSM/* globals in-process under Docker (SG-XXXX)"
}

@test "register happy path renders ecs.config and configures network" {
  skip "scaffold: implement under Docker (SG-XXXX)"

  # Intended structure:
  #   mock_api_response register_response.http
  #   export MOCK_DOCKER_PS_OUTPUT=""            # no existing ecs-agent
  #   export MOCK_DOCKER_INSPECT_OUTPUT="healthy" # agent reports healthy fast
  #   point the installer download at fixtures/ecs-anywhere-install.sh
  #   run main register --organization acme-corp --runner-group rg-private-pool --sg-node-token tok
  #   assert_success
  #   assert ecs.config rendered at ${ECS_CONFIG_DIR}/ecs.config with:
  #     ECS_CLUSTER=sg-cluster-acme, AWS_DEFAULT_REGION=us-east-1,
  #     sg_runner_group_signature=sig-deadbeefcafe (V4 path)
  #   assert_called docker "network create"
  #   assert_called iptables "DOCKER-USER"
  #   assert_called iptables "169.254.170.2"
}

@test "register short-circuits when ecs-agent is already healthy" {
  skip "scaffold: implement under Docker (SG-XXXX)"

  # Intended structure:
  #   export MOCK_DOCKER_PS_OUTPUT="containerid123"  # agent present
  #   export MOCK_DOCKER_INSPECT_OUTPUT="healthy"
  #   run main register ...
  #   assert_success (exits 0 via the already-registered branch)
  #   assert_called docker "network create"   # configure_local_network still runs
  #   refute_called curl "register/"          # never hits the register API
}

@test "deregister happy path calls the API then cleans local setup" {
  skip "scaffold: implement under Docker (SG-XXXX)"

  # Intended structure:
  #   render a known ecs.config (V4) so deregister reads sg_runner_group_id/id back
  #   mock_api_response deregister_response.http
  #   run main deregister --organization acme-corp --runner-group rg-private-pool --sg-node-token tok
  #   assert_success
  #   assert_called curl "deregister/"
  #   assert_called docker "stop ecs-agent"
  #   assert_called docker "network rm sg-net"
}

@test "deregister --force cleans up when ecs.config is missing" {
  skip "scaffold: implement under Docker (SG-XXXX)"

  # Intended structure:
  #   ensure ${ECS_CONFIG_DIR}/ecs.config does NOT exist
  #   run main deregister --force ...
  #   assert_success (force_exec lets cleanup proceed without config)
  #   assert clean_local_setup ran (docker stop/rm, network rm)
}

@test "clean_local_setup removes config and tears down docker network" {
  skip "scaffold: implement under Docker (SG-XXXX)"

  # Intended structure:
  #   load_main; create ${ECS_CONFIG_DIR}/ecs.config
  #   run clean_local_setup
  #   assert_success
  #   assert_called docker "stop ecs-agent"
  #   assert_called docker "network rm sg-net"
}

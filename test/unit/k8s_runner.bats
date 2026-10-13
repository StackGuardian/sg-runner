#!/usr/bin/env bats
#
# Unit tests for the pure helpers of k8s/runner.sh: agent sizing (CPU
# affinity, reserved memory) and reading the registration in ecs.config.

setup() {
  load "${BATS_TEST_DIRNAME}/../helpers/load.bash"
  load "${BATS_TEST_DIRNAME}/../helpers/k8s.bash"
  load_runner
  mkdir -p "$ECS_CONFIG_DIR"
}

#{{{ cpu_affinity_list

@test "cpu_affinity_list takes the first n CPUs of a range" {
  fake_cpus_allowed "0-7"
  run cpu_affinity_list 2
  assert_success
  assert_output "0,1"
}

@test "cpu_affinity_list walks split ranges and single CPUs" {
  fake_cpus_allowed "2-3,6,9-11"
  run cpu_affinity_list 5
  assert_success
  assert_output "2,3,6,9,10"
}

@test "cpu_affinity_list prints nothing when n covers every allowed CPU" {
  fake_cpus_allowed "0-3"
  run cpu_affinity_list 4
  assert_success
  assert_output ""

  run cpu_affinity_list 16
  assert_success
  assert_output ""
}

#}}}: cpu_affinity_list

#{{{ size_agent_memory

@test "size_agent_memory leaves the agent alone without a memory limit" {
  fake_mem_total_mib 16384
  unset SG_TASK_MEMORY_LIMIT_MIB ECS_RESERVED_MEMORY
  size_agent_memory
  assert [ -z "${ECS_RESERVED_MEMORY+set}" ]
}

@test "size_agent_memory ignores a non-numeric limit" {
  fake_mem_total_mib 16384
  unset ECS_RESERVED_MEMORY
  SG_TASK_MEMORY_LIMIT_MIB="4Gi" size_agent_memory
  assert [ -z "${ECS_RESERVED_MEMORY+set}" ]
}

@test "size_agent_memory reserves everything but the limit minus dockerd overhead" {
  fake_mem_total_mib 16384
  SG_TASK_MEMORY_LIMIT_MIB=4096
  size_agent_memory >/dev/null
  # 16384 - (4096 - 256)
  assert_equal "$ECS_RESERVED_MEMORY" "12544"

  run size_agent_memory
  assert_output --partial "3840 of 16384"
}

@test "size_agent_memory reserves nothing when the limit exceeds the node" {
  fake_mem_total_mib 2048
  SG_TASK_MEMORY_LIMIT_MIB=4096
  size_agent_memory >/dev/null
  assert_equal "$ECS_RESERVED_MEMORY" "0"
}

@test "size_agent_memory refuses a reservation the agent would read as 0" {
  # 128 GiB node, 4 GiB limit: 127232 MiB doesn't fit the agent's uint16.
  fake_mem_total_mib 131072
  SG_TASK_MEMORY_LIMIT_MIB=4096
  run size_agent_memory
  assert_failure
  assert_output --partial "exceeds 65535MiB"
}

#}}}: size_agent_memory

#{{{ load_ecs_config / configured_runner_id

@test "load_ecs_config exports values with spaces, quotes and = intact" {
  cat >"$ECS_CONFIG_DIR/ecs.config" <<'CFG'
# written by configure_local_data
ECS_CLUSTER=sg-cluster

ECS_INSTANCE_ATTRIBUTES={"sg_runner_id":"runner 1","note":"say \"hi\" a=b"}
CFG
  # No trailing newline on the last line.
  printf 'ECS_LOGLEVEL=info' >>"$ECS_CONFIG_DIR/ecs.config"

  load_ecs_config

  assert_equal "$ECS_CLUSTER" "sg-cluster"
  assert_equal "$ECS_INSTANCE_ATTRIBUTES" '{"sg_runner_id":"runner 1","note":"say \"hi\" a=b"}'
  assert_equal "$(jq -r .note <<<"$ECS_INSTANCE_ATTRIBUTES")" 'say "hi" a=b'
  assert_equal "$ECS_LOGLEVEL" "info"
  assert_equal "$(bash -c 'printf %s "$ECS_CLUSTER"')" "sg-cluster"
}

@test "configured_runner_id reads sg_runner_id from the instance attributes" {
  cat >"$ECS_CONFIG_DIR/ecs.config" <<'CFG'
ECS_CLUSTER=sg-cluster
ECS_INSTANCE_ATTRIBUTES={"sg_organization":"org","sg_runner_id":"abc123-runner"}
CFG
  run configured_runner_id
  assert_success
  assert_output "abc123-runner"
}

@test "configured_runner_id dies when the runner isn't registered" {
  run configured_runner_id
  assert_failure
  assert_output --partial "Not registered"
}

#}}}: load_ecs_config / configured_runner_id

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

#{{{ cmd_reap

@test "cmd_reap succeeds without deregistering a runner that never registered" {
  deregister_runner() { echo "deregister called"; }
  run cmd_reap
  assert_success
  assert_output --partial "nothing to deregister"
  refute_output --partial "deregister called"
}

@test "cmd_reap deregisters a registered runner" {
  echo 'ECS_INSTANCE_ATTRIBUTES={"sg_runner_id":"abc123-runner"}' >"$ECS_CONFIG_DIR/ecs.config"
  deregister_runner() { echo "deregister called"; }
  run cmd_reap
  assert_success
  assert_output "deregister called"
}

#}}}: cmd_reap

#{{{ workflow logs

@test "container_log_tags skips run controllers (ECS tasks)" {
  run container_log_tags "arn:aws:ecs:eu-central-1:111:task/cluster/f6bff787|/var/tmp/workspace "
  assert_failure
  assert_output ""
}

@test "container_log_tags reads a step's run and workflow from its workspace mount" {
  run container_log_tags "| /var/run/docker.sock /var/tmp/workspace/orgs/o/wfgrps/g/wfs/simple-ec2/wfruns/58679q13o963/shared-workspace "
  assert_success
  assert_output "58679q13o963 simple-ec2"
}

@test "container_log_tags leaves unknowns as -" {
  run container_log_tags "|"
  assert_success
  assert_output "- -"
}

@test "format_log_lines tags each line, keeping spaces and pipes in the message" {
  SG_WORKFLOW_LOGS_FORMAT=text
  run format_log_lines r1 wf1 <<<$'2026-10-14T01:00:00.1Z terraform  plan | tee\n2026-10-14T01:00:01.2Z \nno-timestamp'
  assert_success
  assert_line --index 0 "2026-10-14T01:00:00.1Z role=user run=r1 workflow=wf1 | terraform  plan | tee"
  assert_line --index 1 "2026-10-14T01:00:01.2Z role=user run=r1 workflow=wf1 | "
  assert_line --index 2 "- role=user run=r1 workflow=wf1 | no-timestamp"
}

@test "format_log_lines drops [SG_DEBUG] lines unless debug is on" {
  SG_WORKFLOW_LOGS_FORMAT=text
  local input=$'2026-10-14T01:00:00Z [SG_DEBUG] Setting git ssh key\n2026-10-14T01:00:01Z Initializing the backend...'
  run format_log_lines r1 wf1 <<<"$input"
  assert_success
  assert_output "2026-10-14T01:00:01Z role=user run=r1 workflow=wf1 | Initializing the backend..."

  SG_WORKFLOW_LOGS_DEBUG=true run format_log_lines r1 wf1 <<<"$input"
  assert_success
  assert_line --index 0 "2026-10-14T01:00:00Z role=user run=r1 workflow=wf1 | [SG_DEBUG] Setting git ssh key"
}

@test "format_log_lines writes one JSON object per line, debug lines dropped" {
  SG_WORKFLOW_LOGS_FORMAT=json
  run format_log_lines r1 wf1 <<<$'2026-10-14T01:00:00Z say "hi"\n2026-10-14T01:00:01Z [SG_DEBUG] x\nbare'
  assert_success
  assert_line --index 0 '{"time":"2026-10-14T01:00:00Z","msg":"say \"hi\"","role":"user","run":"r1","workflow":"wf1"}'
  assert_line --index 1 '{"time":null,"msg":"bare","role":"user","run":"r1","workflow":"wf1"}'

  SG_WORKFLOW_LOGS_DEBUG=true run format_log_lines r1 wf1 <<<$'2026-10-14T01:00:01Z [SG_DEBUG] x'
  assert_output '{"time":"2026-10-14T01:00:01Z","msg":"[SG_DEBUG] x","role":"user","run":"r1","workflow":"wf1"}'
}

#}}}: workflow logs

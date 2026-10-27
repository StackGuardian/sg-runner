#!/usr/bin/env bats
#
# Unit tests for the pure helpers of k8s/runner.sh: agent sizing (CPU
# affinity, reserved memory), re-registering on a size change, reading the
# registration in ecs.config, and dockerd's authorization plugin.

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

@test "cpu_affinity_list pins to the advertised CPUs out of a whole node" {
  # Native steps: ecs-agent has no CPU limit, so it sees the node's CPUs.
  fake_cpus_allowed "0-15"
  run cpu_affinity_list 4
  assert_success
  assert_output "0,1,2,3"
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

@test "size_agent_memory advertises the native steps capacity in full" {
  # Native steps: advertise 6Gi on a 16 GiB node, nothing kept for dockerd.
  fake_mem_total_mib 16384
  SG_TASK_MEMORY_LIMIT_MIB=6144 SG_DOCKERD_OVERHEAD_MIB=0 size_agent_memory >/dev/null
  assert_equal "$ECS_RESERVED_MEMORY" "10240"

  SG_TASK_MEMORY_LIMIT_MIB=6144 SG_DOCKERD_OVERHEAD_MIB=0 run size_agent_memory
  assert_output --partial "6144 of 16384"
}

@test "size_agent_memory advertises the whole node when native steps ask for more" {
  fake_mem_total_mib 8192
  SG_TASK_MEMORY_LIMIT_MIB=12288 SG_DOCKERD_OVERHEAD_MIB=0 size_agent_memory >/dev/null
  assert_equal "$ECS_RESERVED_MEMORY" "0"
}

@test "size_agent_memory accepts a native steps reservation right at the uint16 limit" {
  # 65535 MiB reserved still fits; one more doesn't.
  fake_mem_total_mib $((65535 + 4096))
  SG_TASK_MEMORY_LIMIT_MIB=4096 SG_DOCKERD_OVERHEAD_MIB=0 size_agent_memory >/dev/null
  assert_equal "$ECS_RESERVED_MEMORY" "65535"

  SG_TASK_MEMORY_LIMIT_MIB=4095 SG_DOCKERD_OVERHEAD_MIB=0 run size_agent_memory
  assert_failure
  assert_output --partial "exceeds 65535MiB"
}

#}}}: size_agent_memory

#{{{ advertised_resources

@test "advertised_resources matches the dockerd limits minus dockerd overhead" {
  # small: 2 CPUs / 4Gi on an 8-CPU 16 GiB node.
  fake_cpus_allowed "0-7"
  fake_mem_total_mib 16384
  SG_TASK_CPU_LIMIT=2 SG_TASK_MEMORY_LIMIT_MIB=4096 run advertised_resources
  assert_success
  assert_output "2048 3840"
}

@test "advertised_resources takes native steps capacity in full" {
  fake_cpus_allowed "0-15"
  fake_mem_total_mib 16384
  SG_TASK_CPU_LIMIT=4 SG_TASK_MEMORY_LIMIT_MIB=6144 SG_DOCKERD_OVERHEAD_MIB=0 run advertised_resources
  assert_success
  assert_output "4096 6144"
}

@test "advertised_resources caps at the node" {
  fake_cpus_allowed "0-1"
  fake_mem_total_mib 2048
  SG_TASK_CPU_LIMIT=4 SG_TASK_MEMORY_LIMIT_MIB=4096 run advertised_resources
  assert_success
  assert_output "2048 2048"
}

@test "advertised_resources without limits is the whole node" {
  fake_cpus_allowed "0-3"
  fake_mem_total_mib 8192
  unset SG_TASK_CPU_LIMIT SG_TASK_MEMORY_LIMIT_MIB
  run advertised_resources
  assert_success
  assert_output "4096 8192"
}

@test "advertised_resources fails where the agent would refuse the reservation" {
  fake_cpus_allowed "0-7"
  fake_mem_total_mib 131072
  SG_TASK_CPU_LIMIT=2 SG_TASK_MEMORY_LIMIT_MIB=4096 run advertised_resources
  assert_failure
}

#}}}: advertised_resources

#{{{ resized_while_idle / cmd_register

# Usage: fake_runner_group <http status> <cpu> <memory> <running> [runner id]
# The runner group as SG returns it: this runner's container instance among
# others, and a secret that must never be printed.
fake_runner_group() {
  local instance
  instance=$(jq -nc --arg r "${5:-abc123-runner}" --argjson cpu "$2" --argjson mem "$3" --argjson run "$4" \
    '{runnerId: $r, status: "ACTIVE", runningTasksCount: $run, pendingTasksCount: 0,
      registeredResources: [{name: "CPU", type: "INTEGER", integerValue: $cpu},
        {name: "MEMORY", type: "INTEGER", integerValue: $mem},
        {name: "PORTS", type: "STRINGSET", stringSetValue: ["22"]}]}')
  export MOCK_CURL_OUTPUT="HTTP/1.1 $1 OK
Content-Type: application/json

{\"msg\":{\"RunnerToken\":\"runner-group-secret-6f1d\",\"ContainerInstances\":[{\"runnerId\":\"other-runner\"},$instance]}}"
}

setup_registered_runner() {
  echo 'ECS_INSTANCE_ATTRIBUTES={"sg_runner_id":"abc123-runner"}' >"$ECS_CONFIG_DIR/ecs.config"
  export SG_NODE_TOKEN=token SG_ORGANIZATION=org SG_RUNNER_GROUP=group
  # Advertises 2048 / 3840 (small on an 8-CPU 16 GiB node).
  fake_cpus_allowed "0-7"
  fake_mem_total_mib 16384
  export SG_TASK_CPU_LIMIT=2 SG_TASK_MEMORY_LIMIT_MIB=4096
  is_registered() { return 0; }
  deregister_runner() { echo "deregister called"; rm -f "$ECS_CONFIG_DIR/ecs.config"; }
  # Stands in for the fresh registration that follows.
  load_sg_credentials() { echo "fresh registration"; exit 0; }
}

@test "cmd_register keeps a registration of the same size" {
  setup_registered_runner
  fake_runner_group 200 2048 3840 0
  run cmd_register
  assert_success
  assert_output --partial "Already registered"
  refute_output --partial "deregister called"
  refute_output --partial "fresh registration"
  refute_output --partial "runner-group-secret"
}

@test "cmd_register registers an idle runner of another size again" {
  setup_registered_runner
  fake_runner_group 200 1024 1792 0
  run cmd_register
  assert_success
  assert_output --partial "Registered CPU/memory 1024/1792, now 2048/3840:"
  assert_output --partial "re-registering"
  assert_output --partial "deregister called"
  assert_output --partial "fresh registration"
  refute_output --partial "runner-group-secret"
}

@test "cmd_register keeps the old size while tasks run" {
  setup_registered_runner
  fake_runner_group 200 1024 1792 2
  run cmd_register
  assert_success
  assert_output --partial "2 task(s) running or pending, keeping the old size"
  refute_output --partial "deregister called"
  refute_output --partial "fresh registration"
}

@test "cmd_register keeps the registration when SG can't be read" {
  setup_registered_runner
  fake_runner_group 500 1024 1792 0
  run cmd_register
  assert_success
  assert_output --partial "failed (500)"
  assert_output --partial "Can't read the registered size from SG"
  refute_output --partial "deregister called"
  refute_output --partial "runner-group-secret"

  export MOCK_CURL_OUTPUT=""
  run cmd_register
  assert_success
  assert_output --partial "Can't read the registered size from SG"
  refute_output --partial "deregister called"
}

@test "cmd_register keeps the registration when its instance isn't listed" {
  setup_registered_runner
  fake_runner_group 200 1024 1792 0 someone-else
  run cmd_register
  assert_success
  assert_output --partial "Can't read the registered size from SG"
  refute_output --partial "deregister called"
}

@test "cmd_register keeps the registration without registered resources" {
  setup_registered_runner
  export MOCK_CURL_OUTPUT='HTTP/1.1 200 OK

{"msg":{"ContainerInstances":[{"runnerId":"abc123-runner","runningTasksCount":0}]}}'
  run cmd_register
  assert_success
  assert_output --partial "Can't read the registered size from SG"
  refute_output --partial "deregister called"
}

@test "cmd_register keeps the registration when deregistering fails" {
  setup_registered_runner
  fake_runner_group 200 1024 1792 0
  deregister_runner() { return 1; }
  run cmd_register
  assert_success
  assert_output --partial "Could not deregister"
  refute_output --partial "fresh registration"
}

@test "cmd_register skips the size check when opted out" {
  setup_registered_runner
  fake_runner_group 200 1024 1792 0
  SG_REREGISTER_ON_RESIZE=false run cmd_register
  assert_success
  assert_output --partial "Already registered"
  refute_output --partial "deregister called"
  assert [ -z "$(mock_calls curl)" ]
}

#}}}: resized_while_idle / cmd_register

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

#{{{ dockerd authorization plugin

# A unix socket at a short path (sun_path is ~104 bytes on macOS).
make_socket() {
  python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$1"
}

@test "dockerd_args turns on the steps broker's authorization plugin" {
  run dockerd_args
  assert_success
  assert_line "--host=unix:///var/run/docker.sock"
  assert_line "--authorization-plugin=sg-steps-guard"
}

@test "wait_for_authz_plugin returns once the plugin socket exists" {
  local dir
  dir=$(mktemp -d /tmp/sg-authz.XXXXXX)
  make_socket "$dir/sg-steps-guard.sock"
  SG_AUTHZ_PLUGIN_SOCKET="$dir/sg-steps-guard.sock" run wait_for_authz_plugin
  rm -rf "$dir"
  assert_success
  assert_output --partial "Authorization plugin"
}

@test "wait_for_authz_plugin dies without the socket: dockerd never starts unguarded" {
  SG_AUTHZ_PLUGIN_SOCKET="$SG_TEST_TMPDIR/missing.sock" SG_AUTHZ_PLUGIN_WAIT_SECONDS=1 \
    SG_AUTHZ_PLUGIN_POLL_SECONDS=0.2 run wait_for_authz_plugin
  assert_failure
  assert_output --partial "not starting dockerd unguarded"
}

@test "wait_for_authz_plugin doesn't take a plain file for the socket" {
  touch "$SG_TEST_TMPDIR/plain.sock"
  SG_AUTHZ_PLUGIN_SOCKET="$SG_TEST_TMPDIR/plain.sock" SG_AUTHZ_PLUGIN_WAIT_SECONDS=1 \
    SG_AUTHZ_PLUGIN_POLL_SECONDS=0.2 run wait_for_authz_plugin
  assert_failure
}

#}}}: dockerd authorization plugin

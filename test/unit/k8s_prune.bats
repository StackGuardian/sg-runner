#!/usr/bin/env bats
#
# Unit tests for the nested Docker cleanup in k8s/runner.sh (prune_loop in
# the dockerd container), which replaces the VM's `main.sh prune` cron.
#
# Same rule as test/unit/prune.bats: no sweep that can remove a container may
# run without the until= age guard, or it races the ECS agent between
# docker create and docker start (CannotStartContainerError).

setup() {
  load "${BATS_TEST_DIRNAME}/../helpers/load.bash"
  load "${BATS_TEST_DIRNAME}/../helpers/k8s.bash"
  load_runner
}

# Fake `df -P` output for the Docker data root at <pct>% used.
disk_at() {
  export MOCK_DF_OUTPUT="Filesystem 1024-blocks Used Available Capacity Mounted on
/dev/vdb 20511312 0 0 $1% /var/lib/docker"
}

prune_calls() {
  mock_calls docker | grep -F "prune" || true
}

#{{{ prune_enabled

@test "prune_enabled defaults to on, every 4 hours" {
  assert_equal "$SG_PRUNE_INTERVAL_SECONDS" "14400"
  run prune_enabled
  assert_success
}

@test "prune_enabled is off at interval 0 or a non-number" {
  SG_PRUNE_INTERVAL_SECONDS=0
  run prune_enabled
  assert_failure

  SG_PRUNE_INTERVAL_SECONDS=4h
  run prune_enabled
  assert_failure
}

#}}}: prune_enabled

#{{{ should_prune_images

@test "should_prune_images keeps the image cache below the threshold" {
  SG_PRUNE_IMAGES_ABOVE_PCT=70
  run should_prune_images 69
  assert_failure
  run should_prune_images 70
  assert_success
}

@test "should_prune_images always prunes at threshold 0" {
  SG_PRUNE_IMAGES_ABOVE_PCT=0
  run should_prune_images 1
  assert_success
}

@test "should_prune_images prunes when disk usage is unknown" {
  run should_prune_images ""
  assert_success
}

@test "docker_disk_used_pct reads Capacity from df" {
  disk_at 42
  run docker_disk_used_pct
  assert_output "42"
  assert_called df "-P /var/lib/docker"
}

#}}}: should_prune_images

#{{{ prune_docker

@test "prune_docker age-guards every sweep that can remove a container" {
  run prune_docker
  assert_success

  assert_called docker "container prune -f --filter until=24h"
  refute [ -n "$(prune_calls | grep -F "system prune")" ]
  refute [ -n "$(prune_calls | grep -E "(container|image|builder) prune" | grep -vF -- "--filter until=")" ]
}

@test "prune_docker reclaims volumes with a volume-only prune" {
  run prune_docker
  assert_success
  assert_called docker "volume prune -f"
}

@test "prune_docker honours SG_PRUNE_UNTIL" {
  SG_PRUNE_UNTIL=6h
  run prune_docker
  assert_called docker "container prune -f --filter until=6h"
  assert_called docker "image prune -f --filter until=6h"
  assert_called docker "builder prune -f --filter until=6h"
}

@test "prune_docker keeps unused images while the disk has room" {
  disk_at 30
  run prune_docker
  assert_called docker "image prune -f --filter until=24h"
  refute [ -n "$(prune_calls | grep -F "image prune -f -a")" ]
}

@test "prune_docker prunes unused images once the disk fills up" {
  disk_at 85
  run prune_docker
  assert_called docker "image prune -f -a --filter until=24h"
  assert_output --partial "unused images too"
}

@test "prune_docker logs what each sweep reclaimed" {
  export MOCK_DOCKER_VOLUME_OUTPUT="Deleted Volumes:
abc

Total reclaimed space: 1.5GB"
  run prune_docker
  assert_success
  assert_output --partial "volumes 1.5GB"
  assert_output --partial "containers 0B"
}

@test "prune_docker carries on and reports a failing sweep" {
  export MOCK_DOCKER_EXIT=1
  run prune_docker
  assert_success
  assert_output --partial "containers failed"
  assert_output --partial "volumes failed"
  assert_called docker "volume prune -f"
}

#}}}: prune_docker

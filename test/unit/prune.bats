#!/usr/bin/env bats
#
# Unit tests for prune(), which the `0 */4 * * *` crontab entry installed by
# setup_cron() invokes on every registered runner.
#
# The container/image sweep is age-guarded with --filter until=4h. The volume
# sweep must never be able to delete a container: an unfiltered
# `docker system prune` removes every non-running container, including one in
# `created` state, which races the ECS agent between docker create and docker
# start and fails the task with CannotStartContainerError / No such container.

setup() {
  load "${BATS_TEST_DIRNAME}/../helpers/load.bash"
  load_main
  CONTAINER_ORCHESTRATOR="docker"
  init_diagnostic_dir
}

# Every recorded `docker ... prune` invocation, one per line.
prune_calls() {
  mock_calls docker | grep -F "prune" || true
}

@test "prune age-guards the container and image sweep" {
  run prune
  assert_success

  assert_called docker "system prune -f --filter until=4h"
}

@test "prune never issues a system prune without an age filter" {
  run prune
  assert_success

  local unguarded
  unguarded="$(prune_calls | grep -F "system prune" | grep -vF -- "--filter" || true)"
  assert_equal "$unguarded" ""
}

@test "prune reclaims volumes without a container-deleting sweep" {
  run prune
  assert_success

  assert_called docker "volume prune"

  local container_deleting
  container_deleting="$(prune_calls | grep -F "system prune --volumes" || true)"
  assert_equal "$container_deleting" ""
}

@test "prune records the filter it actually applied to the guarded sweep" {
  run prune
  assert_success

  assert_equal "$(jq -r '.system.docker.prune_filter' "$SG_DIAGNOSTIC_FILE")" "until=4h"
}

@test "prune records reclaimed space for both sweeps" {
  run prune
  assert_success

  refute [ "$(jq -r '.system.docker.last_prune' "$SG_DIAGNOSTIC_FILE")" = "null" ]
  refute [ "$(jq -r '.system.docker.reclaimed_containers_images' "$SG_DIAGNOSTIC_FILE")" = "null" ]
  refute [ "$(jq -r '.system.docker.reclaimed_volumes' "$SG_DIAGNOSTIC_FILE")" = "null" ]
}

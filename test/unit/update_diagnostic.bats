#!/usr/bin/env bats
#
# Unit tests for init_diagnostic_dir + update_diagnostic. init_diagnostic_dir
# creates SG_DIAGNOSTIC_FILE as `{}` under the temp dir; update_diagnostic sets
# a (possibly nested) key via jq and atomically replaces the file.

setup() {
  load "${BATS_TEST_DIRNAME}/../helpers/load.bash"
}

@test "init_diagnostic_dir creates the dir and an empty JSON object" {
  load_main

  init_diagnostic_dir

  assert [ -d "$SG_DIAGNOSTIC_DIR" ]
  assert [ -f "$SG_DIAGNOSTIC_FILE" ]
  assert_equal "$(cat "$SG_DIAGNOSTIC_FILE")" "{}"
}

@test "update_diagnostic sets a nested key" {
  load_main
  init_diagnostic_dir

  update_diagnostic "health.docker" "active"

  assert_equal "$(jq -r '.health.docker' "$SG_DIAGNOSTIC_FILE")" "active"
}

@test "update_diagnostic accumulates multiple updates" {
  load_main
  init_diagnostic_dir

  update_diagnostic "health.docker" "active"
  update_diagnostic "health.ecs" "inactive"
  update_diagnostic "system.last_check" "now"

  assert_equal "$(jq -r '.health.docker' "$SG_DIAGNOSTIC_FILE")" "active"
  assert_equal "$(jq -r '.health.ecs' "$SG_DIAGNOSTIC_FILE")" "inactive"
  assert_equal "$(jq -r '.system.last_check' "$SG_DIAGNOSTIC_FILE")" "now"
}

@test "update_diagnostic overwrites an existing key" {
  load_main
  init_diagnostic_dir

  update_diagnostic "health.docker" "active"
  update_diagnostic "health.docker" "inactive"

  assert_equal "$(jq -r '.health.docker' "$SG_DIAGNOSTIC_FILE")" "inactive"
}

@test "init_diagnostic_dir does not clobber an existing diagnostic file" {
  load_main
  init_diagnostic_dir
  update_diagnostic "health.docker" "active"

  init_diagnostic_dir

  assert_equal "$(jq -r '.health.docker' "$SG_DIAGNOSTIC_FILE")" "active"
}

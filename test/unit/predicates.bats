#!/usr/bin/env bats
#
# Unit tests for the boolean predicates: is_debug, force_exec, no_clean_on_fail.
# is_debug is case-insensitive (LOG_DEBUG lowercased); force_exec and
# no_clean_on_fail require an exact `true`.

setup() {
  load "${BATS_TEST_DIRNAME}/../helpers/load.bash"
}

# --- is_debug -------------------------------------------------------------

@test "is_debug true when LOG_DEBUG=true" {
  export LOG_DEBUG="true"
  load_main
  run is_debug
  assert_success
}

@test "is_debug true when LOG_DEBUG=TRUE (case-insensitive)" {
  export LOG_DEBUG="TRUE"
  load_main
  run is_debug
  assert_success
}

@test "is_debug false when LOG_DEBUG=false" {
  export LOG_DEBUG="false"
  load_main
  run is_debug
  assert_failure
}

@test "is_debug false when LOG_DEBUG unset/empty" {
  export LOG_DEBUG=""
  load_main
  run is_debug
  assert_failure
}

# --- force_exec -----------------------------------------------------------

@test "force_exec true when FORCE_PASS=true" {
  export FORCE_PASS="true"
  load_main
  run force_exec
  assert_success
}

@test "force_exec false when FORCE_PASS=TRUE (exact match only)" {
  export FORCE_PASS="TRUE"
  load_main
  run force_exec
  assert_failure
}

@test "force_exec false when FORCE_PASS=false" {
  export FORCE_PASS="false"
  load_main
  run force_exec
  assert_failure
}

# --- no_clean_on_fail -----------------------------------------------------

@test "no_clean_on_fail true when NO_CLEAN_ON_FAIL=true" {
  export NO_CLEAN_ON_FAIL="true"
  load_main
  run no_clean_on_fail
  assert_success
}

@test "no_clean_on_fail false when NO_CLEAN_ON_FAIL=false" {
  export NO_CLEAN_ON_FAIL="false"
  load_main
  run no_clean_on_fail
  assert_failure
}

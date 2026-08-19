#!/usr/bin/env bats
#
# Unit tests for patch_json: deep-merges a patch object into a JSON file via
# `jq -s '.[0] * .[1]'`. New file (no existing) -> just the patch; existing
# file -> merged; conflicting key -> patch wins.

setup() {
  load "${BATS_TEST_DIRNAME}/../helpers/load.bash"
  # patch_json opens with a bare `debug` call. Under bats' `set -e`, a non-debug
  # run makes that call return 1 and abort the function before the jq merge
  # (main.sh itself runs without `set -e`, so this only bites under test).
  # Enabling debug makes `debug` return 0, exercising the real merge path.
  export LOG_DEBUG="true"
}

@test "patch_json on a non-existent file writes just the patch" {
  load_main
  local file="${SG_TEST_TMPDIR}/new.json"

  patch_json "$file" '{"a":1,"b":{"c":2}}'

  assert_equal "$(jq -r '.a' "$file")" "1"
  assert_equal "$(jq -r '.b.c' "$file")" "2"
}

@test "patch_json on an empty file writes just the patch" {
  load_main
  local file="${SG_TEST_TMPDIR}/empty.json"
  : >"$file"

  patch_json "$file" '{"x":"y"}'

  assert_equal "$(jq -r '.x' "$file")" "y"
}

@test "patch_json merges new keys into an existing file" {
  load_main
  local file="${SG_TEST_TMPDIR}/existing.json"
  echo '{"keep":"me"}' >"$file"

  patch_json "$file" '{"added":"value"}'

  assert_equal "$(jq -r '.keep' "$file")" "me"
  assert_equal "$(jq -r '.added' "$file")" "value"
}

@test "patch_json deep-merges nested objects" {
  load_main
  local file="${SG_TEST_TMPDIR}/nested.json"
  echo '{"proxies":{"default":{"httpProxy":"old"}}}' >"$file"

  patch_json "$file" '{"proxies":{"default":{"httpsProxy":"new"}}}'

  assert_equal "$(jq -r '.proxies.default.httpProxy' "$file")" "old"
  assert_equal "$(jq -r '.proxies.default.httpsProxy' "$file")" "new"
}

@test "patch_json overwrites a conflicting key with the patch value" {
  load_main
  local file="${SG_TEST_TMPDIR}/conflict.json"
  echo '{"k":"original"}' >"$file"

  patch_json "$file" '{"k":"replaced"}'

  assert_equal "$(jq -r '.k' "$file")" "replaced"
}

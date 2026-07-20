#!/usr/bin/env bats
#
# Unit tests for api_call: status-code parsing, body extraction, and the
# proxy double-status edge case. api_call sets globals (response/status_code/
# message/data) so we call it DIRECTLY (not via `run`) to inspect them, and use
# `run` only for the paths that exit (empty response / missing status line).

setup() {
  load "${BATS_TEST_DIRNAME}/../helpers/load.bash"
  export SG_NODE_TOKEN="test-token"
}

fixture() {
  cat "${BATS_TEST_DIRNAME}/../fixtures/api/$1"
}

@test "api_call 200 parses status_code, message and data" {
  export MOCK_CURL_OUTPUT="$(fixture 200_ok.http)"
  load_main

  api_call "POST" "https://api.example/register/"
  assert_equal "$status_code" "200"
  assert_equal "$message" "registration ok"
  assert_equal "$(echo "$data" | jq -r '.RegistrationMetadata[0]')" "meta-token"
}

@test "api_call 200 returns 0" {
  export MOCK_CURL_OUTPUT="$(fixture 200_ok.http)"
  load_main

  run api_call "POST" "https://api.example/register/"
  assert_success
}

@test "api_call 201 returns 0 with status_code 201" {
  export MOCK_CURL_OUTPUT="$(fixture 201_created.http)"
  load_main

  api_call "POST" "https://api.example/x/"
  assert_equal "$status_code" "201"
  run api_call "POST" "https://api.example/x/"
  assert_success
}

@test "api_call 100 returns 0 with status_code 100" {
  export MOCK_CURL_OUTPUT="$(fixture 100_continue.http)"
  load_main

  api_call "POST" "https://api.example/x/"
  assert_equal "$status_code" "100"
  run api_call "POST" "https://api.example/x/"
  assert_success
}

@test "api_call 400 returns 1 (non-exit) with status_code 400" {
  export MOCK_CURL_OUTPUT="$(fixture 400_bad_request.http)"
  load_main

  run api_call "POST" "https://api.example/x/"
  assert_failure 1

  # Direct call to read the globals; `|| true` keeps the non-zero return
  # (expected for 4xx) from aborting under bats' set -e. Not a subshell, so the
  # globals it sets remain visible.
  api_call "POST" "https://api.example/x/" || true
  assert_equal "$status_code" "400"
  assert_equal "$message" "bad request"
}

@test "api_call 403 returns 1 and reads .message when .msg absent" {
  export MOCK_CURL_OUTPUT="$(fixture 403_forbidden.http)"
  load_main

  run api_call "POST" "https://api.example/x/"
  assert_failure 1

  api_call "POST" "https://api.example/x/" || true
  assert_equal "$status_code" "403"
  assert_equal "$message" "forbidden token"
}

@test "api_call 500 returns 1 with status_code 500" {
  export MOCK_CURL_OUTPUT="$(fixture 500_server_error.http)"
  load_main

  run api_call "POST" "https://api.example/x/"
  assert_failure 1

  api_call "POST" "https://api.example/x/" || true
  assert_equal "$status_code" "500"
}

@test "api_call proxy double-200: last status code wins, returns 0" {
  export MOCK_CURL_OUTPUT="$(fixture proxy_then_200.http)"
  load_main

  api_call "POST" "https://api.example/x/"
  assert_equal "$status_code" "200"
  assert_equal "$message" "real ok"

  run api_call "POST" "https://api.example/x/"
  assert_success
}

@test "api_call proxy 200 then real 403: status_code is 403, returns 1" {
  export MOCK_CURL_OUTPUT="$(fixture proxy_then_403.http)"
  load_main

  api_call "POST" "https://api.example/x/" || true
  assert_equal "$status_code" "403"
  assert_equal "$message" "real forbidden"

  run api_call "POST" "https://api.example/x/"
  assert_failure 1
}

@test "api_call empty response calls err and exits" {
  export MOCK_CURL_OUTPUT=""
  load_main

  run api_call "POST" "https://api.example/x/"
  assert_failure
  assert_output --partial "Empty response"
}

@test "api_call with no status line exits with Unknown status code" {
  export MOCK_CURL_OUTPUT="$(fixture 200_no_status.http)"
  load_main

  run api_call "POST" "https://api.example/x/"
  assert_failure
  assert_output --partial "Unknown status code"
}

@test "api_call without payload does NOT pass -d to curl" {
  export MOCK_CURL_OUTPUT="$(fixture 200_ok.http)"
  load_main

  api_call "POST" "https://api.example/x/"
  assert_called curl "-X POST"
  refute_output_contains_d
}

# Helper: assert no curl invocation carried a -d payload flag.
refute_output_contains_d() {
  local calls
  calls="$(mock_calls curl)"
  if grep -qE -- '(^| )-d( |$)' <<<"$calls"; then
    fail "expected no -d flag in curl calls, got: ${calls}"
  fi
}

@test "api_call with payload passes -d and -X POST to curl" {
  export MOCK_CURL_OUTPUT="$(fixture 201_created.http)"
  load_main

  api_call "POST" "https://api.example/x/" '{"k":"v"}'
  assert_called curl "-X POST"
  assert_called curl "-d {\"k\":\"v\"}"
}

#!/usr/bin/env bats
#
# Unit tests for update_runner_group: error reports are best effort and sent
# once, even when the API is unreachable (api_call reports its own failure
# through err(), which calls update_runner_group again).

setup() {
  load "${BATS_TEST_DIRNAME}/../helpers/load.bash"
  export SG_NODE_TOKEN="test-token"
  export ORGANIZATION_ID="demo-org"
  export RUNNER_GROUP_ID="demo-group"
}

curl_calls() {
  grep -c '^curl ' "${MOCK_CALL_LOG}" || true
}

@test "err with an unreachable API reports once and returns" {
  export MOCK_CURL_OUTPUT=""
  load_main

  run err "Registration failed" "boom"
  assert_success
  assert_output --partial "Registration failed"
  assert_equal "$(curl_calls)" "1"
}

@test "die with an unreachable API exits 1 after a single report" {
  export MOCK_CURL_OUTPUT=""
  load_main

  run die "Could not fetch data from API." "000"
  assert_failure 1
  assert_equal "$(curl_calls)" "1"
}

@test "err reports to the runner group endpoint when the API answers" {
  export MOCK_CURL_OUTPUT="$(cat "${BATS_TEST_DIRNAME}/../fixtures/api/200_ok.http")"
  load_main

  run err "Registration failed" "boom"
  assert_success
  assert_equal "$(curl_calls)" "1"
  # The JSON payload spans lines in the call log, so check method and URL apart.
  run grep -E '^curl .*-X PATCH' "${MOCK_CALL_LOG}"
  assert_success
  run grep -F '/orgs/demo-org/runnergroups/demo-group/' "${MOCK_CALL_LOG}"
  assert_success
}

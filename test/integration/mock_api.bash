# shellcheck shell=bash
#
# mock_api.bash - point main.sh's API calls at canned fixtures.
#
# Chosen approach: NO real HTTP server.
#   main.sh talks to the API exclusively through api_call(), which shells out to
#   the `curl` stub in test/mocks/bin. That stub echoes whatever is in
#   $MOCK_CURL_OUTPUT and exits with $MOCK_CURL_EXIT. So a whole API response is
#   just a string we hand the stub. We keep the canned responses as full HTTP
#   blobs (status line + headers + JSON body) under fixtures/*.http, because
#   api_call parses the `HTTP/1.x NNN` status line and the JSON body out of
#   exactly that shape.
#
#   Standing up a real server (python -m http.server, nc, ...) was rejected: it
#   adds a port/lifecycle to manage, needs the curl mock disabled, and buys
#   nothing — api_call never inspects anything the stub can't reproduce from a
#   fixture string.
#
# Limitation to design around:
#   register hits the API once (register/) but ALSO curls the installer
#   download and IMDSv2 token/role probes (in preflight) through the same stub.
#   $MOCK_CURL_OUTPUT is a single global, so a naive "set output, run flow" gives
#   every curl the register JSON. Two ways to handle it, both fine for the flows:
#     1. Source the relevant function directly (load_main; fetch_organization_info)
#        instead of the whole main(), so only the API curl runs.
#     2. If driving full main(), make MOCK_CURL_OUTPUT robust to being returned
#        for the install download too (the shebang check then fails) — so prefer
#        approach 1 for register, or stub the download separately.
#   The register_flow.bats scaffold documents which path each flow should take.

# integration_fixtures_dir - absolute path to test/integration/fixtures.
integration_fixtures_dir() {
  echo "${BATS_TEST_DIRNAME}/fixtures"
}

# mock_api_response <fixture.http> - load a canned HTTP response blob into the
# curl stub's output knob. Pass a filename relative to fixtures/.
#   e.g. mock_api_response register_response.http
mock_api_response() {
  local fixture="$1"
  export MOCK_CURL_OUTPUT
  MOCK_CURL_OUTPUT="$(cat "$(integration_fixtures_dir)/${fixture}")"
}

# mock_api_status <code> - force the curl exit code (0 = transport ok). The HTTP
# status itself comes from the fixture's status line, not this.
mock_api_status() {
  export MOCK_CURL_EXIT="${1:-0}"
}

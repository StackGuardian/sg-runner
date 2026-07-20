#!/usr/bin/env bats
#
# Unit tests for validate_proxy_format - rejects anything that is not a bare
# hostname:port or IP:port, to block command injection through the proxy arg.

setup() {
  load "${BATS_TEST_DIRNAME}/../helpers/load.bash"
  load_main
}

@test "validate_proxy_format accepts hostname:port" {
  run validate_proxy_format "host:8080"
  assert_success
}

@test "validate_proxy_format accepts IP:port" {
  run validate_proxy_format "10.0.0.1:3128"
  assert_success
}

@test "validate_proxy_format accepts dotted hostname:port" {
  run validate_proxy_format "my-proxy.example.com:80"
  assert_success
}

@test "validate_proxy_format rejects host with no port" {
  run validate_proxy_format "host"
  assert_failure
  assert_output --partial "Invalid proxy format"
}

@test "validate_proxy_format rejects trailing colon with no port" {
  run validate_proxy_format "host:"
  assert_failure
  assert_output --partial "Invalid proxy format"
}

@test "validate_proxy_format rejects non-numeric port" {
  run validate_proxy_format "host:abc"
  assert_failure
  assert_output --partial "Invalid proxy format"
}

@test "validate_proxy_format rejects shell metacharacters in host" {
  run validate_proxy_format "bad;cmd:80"
  assert_failure
  assert_output --partial "Invalid proxy format"
}

@test "validate_proxy_format rejects scheme prefix" {
  run validate_proxy_format "http://host:80"
  assert_failure
  assert_output --partial "Invalid proxy format"
}

@test "validate_proxy_format rejects double port" {
  run validate_proxy_format "host:80:90"
  assert_failure
  assert_output --partial "Invalid proxy format"
}

@test "validate_proxy_format rejects empty input" {
  run validate_proxy_format ""
  assert_failure
  assert_output --partial "Invalid proxy format"
}

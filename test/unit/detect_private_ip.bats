#!/usr/bin/env bats
#
# Unit tests for detect_private_ip - reads the source address of the outbound
# route by name, then falls back to the first global IPv4, then hostname -I.

setup() {
  load "${BATS_TEST_DIRNAME}/../helpers/load.bash"
}

@test "detect_private_ip reads src from a dhcp-style route" {
  export MOCK_IP_ROUTE_GET_OUTPUT="1.1.1.1 via 10.0.0.254 dev eth0 proto dhcp src 10.0.0.1 metric 100 uid 0"
  load_main
  run detect_private_ip
  assert_success
  assert_output "10.0.0.1"
  assert_called ip "-4 route get 1.1.1.1"
}

@test "detect_private_ip reads src behind a static default route" {
  export MOCK_IP_ROUTE_GET_OUTPUT="1.1.1.1 via 10.0.0.1 dev eth0 src 10.0.0.5 uid 0"
  load_main
  run detect_private_ip
  assert_success
  assert_output "10.0.0.5"
}

@test "detect_private_ip reads src in a Kubernetes pod" {
  export MOCK_IP_ROUTE_GET_OUTPUT="1.1.1.1 via 192.168.194.1 dev eth0 src 192.168.194.8 uid 0"
  load_main
  run detect_private_ip
  assert_success
  assert_output "192.168.194.8"
}

@test "detect_private_ip falls back to the first global address when route get fails" {
  export MOCK_IP_ROUTE_GET_OUTPUT=""
  export MOCK_IP_ROUTE_GET_EXIT=2
  export MOCK_IP_ADDR_OUTPUT="2: eth0    inet 172.16.4.20/16 brd 172.16.255.255 scope global eth0
3: eth1    inet 172.17.0.1/16 scope global eth1"
  load_main
  run detect_private_ip
  assert_success
  assert_output "172.16.4.20"
  assert_called ip "-4 -o addr show scope global"
  refute_called hostname
}

@test "detect_private_ip falls back to hostname -I when both ip queries fail" {
  export MOCK_IP_EXIT=1 MOCK_IP_ROUTE_GET_OUTPUT="" MOCK_IP_ADDR_OUTPUT=""
  export MOCK_HOSTNAME_OUTPUT="10.1.2.3 172.17.0.1"
  load_main
  run detect_private_ip
  assert_success
  assert_output "10.1.2.3"
  assert_called hostname "-I"
}

@test "detect_private_ip prints nothing when every source fails" {
  export MOCK_IP_EXIT=1 MOCK_IP_ROUTE_GET_OUTPUT="" MOCK_IP_ADDR_OUTPUT=""
  export MOCK_HOSTNAME_OUTPUT="" MOCK_HOSTNAME_EXIT=1
  load_main
  run detect_private_ip
  assert_success
  assert_output ""
}

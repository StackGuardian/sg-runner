#!/usr/bin/env bats
#
# Unit tests for iptables_ensure: an idempotent insert/append. It first runs a
# `-C` check; if the rule is absent (check exits non-zero) it runs the op
# (-A / -I), otherwise it does nothing further. Covers the -t TABLE branch.

setup() {
  load "${BATS_TEST_DIRNAME}/../helpers/load.bash"
}

@test "rule absent (-C fails): runs the -I insert with the args" {
  export MOCK_IPTABLES_CHECK_EXIT=1
  load_main

  iptables_ensure -I DOCKER-USER -i br-abc -d 169.254.169.254 -j DROP

  assert_called iptables "-C DOCKER-USER -i br-abc -d 169.254.169.254 -j DROP"
  assert_called iptables "-I DOCKER-USER -i br-abc -d 169.254.169.254 -j DROP"
}

@test "rule absent (-C fails): runs the -A append with the args" {
  export MOCK_IPTABLES_CHECK_EXIT=1
  load_main

  iptables_ensure -A FORWARD -j ACCEPT

  assert_called iptables "-C FORWARD -j ACCEPT"
  assert_called iptables "-A FORWARD -j ACCEPT"
}

@test "rule present (-C succeeds): does NOT add, only the check runs" {
  export MOCK_IPTABLES_CHECK_EXIT=0
  load_main

  iptables_ensure -I DOCKER-USER -i br-abc -j DROP

  assert_called iptables "-C DOCKER-USER -i br-abc -j DROP"
  run mock_calls iptables
  refute_line --partial "-I DOCKER-USER"
}

@test "-t nat table arg is threaded into both check and op" {
  export MOCK_IPTABLES_CHECK_EXIT=1
  load_main

  iptables_ensure -A -t nat PREROUTING -p tcp -j DNAT

  assert_called iptables "-t nat -C PREROUTING -p tcp -j DNAT"
  assert_called iptables "-t nat -A PREROUTING -p tcp -j DNAT"
}

@test "-t nat rule present: only the check runs, no append" {
  export MOCK_IPTABLES_CHECK_EXIT=0
  load_main

  iptables_ensure -A -t nat OUTPUT -j REDIRECT

  assert_called iptables "-t nat -C OUTPUT -j REDIRECT"
  run mock_calls iptables
  refute_line --partial "-t nat -A OUTPUT"
}

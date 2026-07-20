#!/usr/bin/env bats
#
# Best-effort unit tests for cgroupsv2. The function prompts via `read -p`, then
# (grubby-present branch) runs `grubby --args=systemd.unified_cgroup_hierarchy=N`
# and `reboot`, then `exit 0`. grubby and reboot are mocked. We feed `Y` on
# stdin to pass the confirmation, and use `run` because the function exits.

setup() {
  load "${BATS_TEST_DIRNAME}/../helpers/load.bash"
}

@test "enable: grubby gets unified_cgroup_hierarchy=1 and reboot is invoked" {
  load_main

  run cgroupsv2 enable <<<"Y"
  assert_success
  assert_called grubby "systemd.unified_cgroup_hierarchy=1"
  assert_called reboot
}

@test "disable: grubby gets unified_cgroup_hierarchy=0 and reboot is invoked" {
  load_main

  run cgroupsv2 disable <<<"Y"
  assert_success
  assert_called grubby "systemd.unified_cgroup_hierarchy=0"
  assert_called reboot
}

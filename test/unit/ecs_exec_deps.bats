#!/usr/bin/env bats
#
# Unit tests for the ECS Exec dependency handling.
#
# StackGuardian never sets enableExecuteCommand on a task, but AWS's
# ecs-anywhere-install.sh stages the SSM session binaries under
# ECS_EXEC_DEPS_DIR unconditionally. Two functions keep them off the runner:
#
#   disable_ecs_exec_setup - rewrites the installer's top-level `exec-setup`
#                            call so the download never happens.
#   remove_ecs_exec_deps   - removes anything that got staged anyway.
#
# load.bash points ECS_EXEC_DEPS_DIR at the per-test tmpdir, so the rm -rf here
# can never reach the real /var/lib/ecs/deps/execute-command.

setup() {
  load "${BATS_TEST_DIRNAME}/../helpers/load.bash"
  INSTALLER="${SG_TEST_TMPDIR}/ecs-anywhere-install.sh"
  cp "${BATS_TEST_DIRNAME}/../fixtures/ecs/ecs-anywhere-install.sh.sample" "$INSTALLER"
}

#{{{ disable_ecs_exec_setup

@test "the unpatched fixture does stage exec dependencies" {
  # Guards the tests below: if upstream's shape changes so the fixture stops
  # exercising exec-setup, this fails first and explains why.
  run bash "$INSTALLER"
  assert_success
  assert_output --partial "Downloading SSM binaries for exec feature"
}

@test "patched installer no longer stages exec dependencies" {
  load_main

  run disable_ecs_exec_setup "$INSTALLER"
  assert_success

  run bash "$INSTALLER"
  assert_success
  refute_output --partial "Downloading SSM binaries for exec feature"
  refute_output --partial "Copying certs for exec feature"
}

@test "patched installer still runs every other install step" {
  load_main

  run disable_ecs_exec_setup "$INSTALLER"
  assert_success

  run bash "$INSTALLER"
  assert_success
  assert_output --partial "install-ssm-agent"
  assert_output --partial "install-docker"
  assert_output --partial "install-ecs-agent"
  assert_output --partial "wait-agent-start"
}

@test "patched installer is still valid bash" {
  load_main

  run disable_ecs_exec_setup "$INSTALLER"
  assert_success

  run bash -n "$INSTALLER"
  assert_success
}

@test "only the top-level call is rewritten, the function stays defined" {
  load_main

  run disable_ecs_exec_setup "$INSTALLER"
  assert_success

  run grep -c '^exec-setup$' "$INSTALLER"
  assert_output "0"

  # The definition and its helpers must survive untouched.
  run grep -q '^exec-setup() {$' "$INSTALLER"
  assert_success
  run grep -q '^download-ssm-binaries-exec() {$' "$INSTALLER"
  assert_success
}

@test "no leftover .patched temp file" {
  load_main

  run disable_ecs_exec_setup "$INSTALLER"
  assert_success

  assert [ ! -e "${INSTALLER}.patched" ]
}

@test "is idempotent: a second run leaves the file unchanged" {
  load_main

  run disable_ecs_exec_setup "$INSTALLER"
  assert_success
  cp "$INSTALLER" "${SG_TEST_TMPDIR}/after-first"
  run disable_ecs_exec_setup "$INSTALLER"
  assert_success

  run diff "${SG_TEST_TMPDIR}/after-first" "$INSTALLER"
  assert_success
}

@test "installer without an exec-setup call is left byte-identical" {
  load_main
  printf '#!/bin/bash\ninstall-ecs-agent\n' >"$INSTALLER"
  cp "$INSTALLER" "${SG_TEST_TMPDIR}/before"

  run disable_ecs_exec_setup "$INSTALLER"
  assert_success

  run diff "${SG_TEST_TMPDIR}/before" "$INSTALLER"
  assert_success
}

@test "an indented or suffixed exec-setup mention is not rewritten" {
  # Only a bare top-level call is a call; anything else is prose or a definition.
  load_main
  printf '#!/bin/bash\n# see exec-setup below\n  exec-setup\nexec-setup() { :; }\n' >"$INSTALLER"
  cp "$INSTALLER" "${SG_TEST_TMPDIR}/before"

  run disable_ecs_exec_setup "$INSTALLER"
  assert_success

  run diff "${SG_TEST_TMPDIR}/before" "$INSTALLER"
  assert_success
}

#}}}: disable_ecs_exec_setup

#{{{ remove_ecs_exec_deps

@test "removes the staged dependency directory" {
  load_main
  mkdir -p "${ECS_EXEC_DEPS_DIR}/bin/3.3.4624.0"
  touch "${ECS_EXEC_DEPS_DIR}/bin/3.3.4624.0/ssm-session-worker"

  run remove_ecs_exec_deps
  assert_success

  assert [ ! -e "$ECS_EXEC_DEPS_DIR" ]
}

@test "succeeds when the directory was never created" {
  load_main
  assert [ ! -e "$ECS_EXEC_DEPS_DIR" ]

  run remove_ecs_exec_deps
  assert_success
}

@test "is idempotent" {
  load_main
  mkdir -p "${ECS_EXEC_DEPS_DIR}/bin"

  run remove_ecs_exec_deps
  assert_success
  run remove_ecs_exec_deps
  assert_success
  assert [ ! -e "$ECS_EXEC_DEPS_DIR" ]
}

@test "leaves sibling ECS state untouched" {
  load_main
  mkdir -p "${ECS_EXEC_DEPS_DIR}/bin" "$ECS_DATA_DIR" "$ECS_CONFIG_DIR"
  touch "${ECS_DATA_DIR}/ecs_agent_data.json" "${ECS_CONFIG_DIR}/ecs.config"

  run remove_ecs_exec_deps
  assert_success

  assert [ -e "${ECS_DATA_DIR}/ecs_agent_data.json" ]
  assert [ -e "${ECS_CONFIG_DIR}/ecs.config" ]
}

#}}}: remove_ecs_exec_deps

#{{{ wiring

@test "ECS_EXEC_DEPS_DIR defaults to the production path" {
  run env -u ECS_EXEC_DEPS_DIR bash -c \
    'source "${SG_MAIN_SH}"; printf "%s" "${ECS_EXEC_DEPS_DIR}"'
  assert_success
  assert_output "/var/lib/ecs/deps/execute-command"
}

@test "register_instance patches the installer and sweeps the deps dir" {
  # No flag gates this: both calls must be present in the registration path.
  run bash -c \
    'sed -n "/^register_instance() {/,/^#}}}: register_instance/p" "${SG_MAIN_SH}"'
  assert_success
  assert_output --partial 'disable_ecs_exec_setup "$ecs_install_script"'
  assert_output --partial "remove_ecs_exec_deps"
}

#}}}: wiring

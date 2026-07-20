# shellcheck shell=bash
#
# mocks.bash - assertions over the mock call log.
#
# Every stub in test/mocks/bin appends one line per invocation to
# $MOCK_CALL_LOG in the form:  "<name> <args...>"
# These helpers read that file. load.bash sources this file for you.

# mock_calls <cmd> - print every recorded invocation of <cmd> (one per line).
mock_calls() {
  local cmd="$1"
  grep -E "^${cmd}( |$)" "${MOCK_CALL_LOG}" 2>/dev/null || true
  return 0
}

# assert_called <cmd> [substring]
#   Passes if <cmd> was invoked at least once. If [substring] is given, at
#   least one invocation of <cmd> must contain it.
assert_called() {
  local cmd="$1"
  local needle="${2:-}"
  local calls
  calls="$(mock_calls "${cmd}")"

  if [[ -z "${calls}" ]]; then
    batslib_print_kv_single 8 "command" "${cmd}" \
      | batslib_decorate "command was not called" \
      | fail
    return 1
  fi

  if [[ -n "${needle}" ]] && ! grep -qF -- "${needle}" <<<"${calls}"; then
    { batslib_print_kv_single 9 "command" "${cmd}" "substring" "${needle}"
      batslib_print_kv_single_or_multi 9 "calls" "${calls}"
    } | batslib_decorate "command not called with substring" \
      | fail
    return 1
  fi
}

# refute_called <cmd> - passes only if <cmd> was never invoked.
refute_called() {
  local cmd="$1"
  local calls
  calls="$(mock_calls "${cmd}")"
  if [[ -n "${calls}" ]]; then
    batslib_print_kv_single_or_multi 6 "calls" "${calls}" \
      | batslib_decorate "command was called but should not have been" \
      | fail
    return 1
  fi
}

# reset_mocks - truncate the call log (e.g. between phases of one test).
reset_mocks() {
  : >"${MOCK_CALL_LOG}"
  return 0
}

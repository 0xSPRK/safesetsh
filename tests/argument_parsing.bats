#!/usr/bin/env bats
# tests/argument_parsing.bats

setup() {
  load 'helpers'
  setup_test_env
}

@test "help and version" {
  run "$SAFESET_BIN" --version
  [ "$status" -eq 0 ]
  [[ "$output" =~ safeset\.sh\ [0-9]+\.[0-9]+\.[0-9]+ ]]

  run "$SAFESET_BIN" --help
  [ "$status" -eq 0 ]
  [[ "$output" =~ USAGE ]]
}

@test "list modules" {
  run "$SAFESET_BIN" --list-modules
  [ "$status" -eq 0 ]
  [[ "$output" =~ packages ]]
  [[ "$output" =~ firewall ]]
  [[ "$output" =~ ssh ]]
}

@test "dry-run with only sysctl does not change system" {
  # The script targets Debian only; detect_os refuses anything else.
  if [[ "$(uname -s)" != "Linux" ]] || ! grep -q '^ID=debian' /etc/os-release 2>/dev/null; then
    skip "requires a Debian host or container"
  fi
  run "$SAFESET_BIN" --dry-run --yes --only sysctl
  [ "$status" -eq 0 ]
  assert_output_contains "sysctl"
}

@test "unknown module fails" {
  run "$SAFESET_BIN" --yes --only foobar
  [ "$status" -ne 0 ]
  assert_output_contains "unknown module"
}

@test "invalid ssh port fails" {
  run "$SAFESET_BIN" --yes --ssh-port 70000
  [ "$status" -ne 0 ]
  assert_output_contains "invalid --ssh-port"
}

@test "unknown option fails" {
  run "$SAFESET_BIN" --yes --definitely-not-an-option
  [ "$status" -ne 0 ]
  assert_output_contains "unknown option"
}

@test "invalid admin ip fails" {
  run "$SAFESET_BIN" --yes --admin-ip "not-an-ip"
  [ "$status" -ne 0 ]
  assert_output_contains "invalid --admin-ip"
}

@test "ssh key without create user fails" {
  run "$SAFESET_BIN" --yes --ssh-key /nonexistent/key.pub
  [ "$status" -ne 0 ]
  assert_output_contains "requires --create-user"
}

@test "config file is parsed as KEY=VALUE only" {
  local cfg="${TEST_TMPDIR}/safeset.conf"
  printf 'SSH_PORT=2222\n$(touch /tmp/safeset-should-not-exist)\n' >"$cfg"
  run "$SAFESET_BIN" --config "$cfg" --dry-run --yes --only sysctl
  [ "$status" -ne 0 ]
  [ ! -e /tmp/safeset-should-not-exist ]
}

@test "missing config file fails" {
  run "$SAFESET_BIN" --config "${TEST_TMPDIR}/does-not-exist.conf" --dry-run --yes
  [ "$status" -ne 0 ]
  assert_output_contains "not readable"
}

@test "unknown config key fails" {
  local cfg="${TEST_TMPDIR}/unknown.conf"
  printf 'NO_SUCH_KEY=1\n' >"$cfg"
  run "$SAFESET_BIN" --config "$cfg" --dry-run --yes
  [ "$status" -ne 0 ]
  assert_output_contains "unknown key"
}

@test "invalid boolean in config file fails" {
  local cfg="${TEST_TMPDIR}/bool.conf"
  printf 'NO_IPV6=maybe\n' >"$cfg"
  run "$SAFESET_BIN" --config "$cfg" --dry-run --yes
  [ "$status" -ne 0 ]
  assert_output_contains "invalid boolean"
}

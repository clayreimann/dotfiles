#!/bin/zsh
set -euo pipefail

readonly AGENT_KEY='~/.ssh/id_ed25519_sign.pub'
readonly PERSONAL_KEY='key::ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJPn+hLDA7eHS1Ef6qjVQycAoAldvPgK7nIpa/bArJOv Github_SSH_Key'

fail() { print -u2 -- "FAIL: $1"; exit 1; }
assert_equal() {
  [[ "$2" == "$3" ]] || fail "$1: expected '$2', got '$3'"
}
read_global() {
  GIT_CONFIG_GLOBAL="$1" git config --global --includes --get "$2" 2>/dev/null || true
}

default_key=$(env -u GIT_CONFIG_GLOBAL -u GIT_CONFIG_COUNT git config --global --get user.signingkey 2>/dev/null || true)
interactive_key=$(read_global "$HOME/.gitconfig-interactive" user.signingkey)
compatibility_key=$(read_global "$HOME/.gitconfig-agent" user.signingkey)

assert_equal "default signing key" "$AGENT_KEY" "$default_key"
assert_equal "interactive signing key" "$PERSONAL_KEY" "$interactive_key"
assert_equal "compatibility signing key" "$AGENT_KEY" "$compatibility_key"

for profile in "$HOME/.gitconfig" "$HOME/.gitconfig-interactive" "$HOME/.gitconfig-agent"; do
  assert_equal "$profile commit signing" true "$(read_global "$profile" commit.gpgsign)"
  assert_equal "$profile tag signing" true "$(read_global "$profile" tag.gpgsign)"
  assert_equal "$profile format" ssh "$(read_global "$profile" gpg.format)"
done

print -- "git signing profiles: PASS"

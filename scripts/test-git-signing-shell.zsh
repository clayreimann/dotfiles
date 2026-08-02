#!/bin/zsh
set -euo pipefail

readonly AGENT_CONFIG="$HOME/.gitconfig"
readonly PERSONAL_KEY='key::ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJPn+hLDA7eHS1Ef6qjVQycAoAldvPgK7nIpa/bArJOv Github_SSH_Key'

fail() { print -u2 -- "FAIL: $1"; exit 1; }
assert_equal() {
  [[ "$2" == "$3" ]] || fail "$1: expected '$2', got '$3'"
}

interactive_key=$(zsh -ic 'git config --global --get user.signingkey' 2>/dev/null | tail -n 1)
assert_equal "interactive shell signing key" "$PERSONAL_KEY" "$interactive_key"

source "$HOME/.config/zsh/functions.zsh"
claude() { print -r -- "$GIT_CONFIG_GLOBAL"; }
codex() { print -r -- "$GIT_CONFIG_GLOBAL"; }
assert_equal "Claude CLI profile" "$AGENT_CONFIG" "$(claude-agent-sign)"
assert_equal "Codex CLI profile" "$AGENT_CONFIG" "$(codex-agent-sign)"

pgrep() { return 1; }
open() { printf '%s\n' "$@"; }
chatgpt_expected=$'-a\nChatGPT\n--env\nGIT_CONFIG_GLOBAL='$HOME'/.gitconfig'
claude_expected=$'-a\nClaude\n--env\nGIT_CONFIG_GLOBAL='$HOME'/.gitconfig'
assert_equal "ChatGPT app profile" "$chatgpt_expected" "$(chatgpt-app-agent-sign)"
assert_equal "Claude app profile" "$claude_expected" "$(claude-app-agent-sign)"

print -- "git signing shell routing: PASS"

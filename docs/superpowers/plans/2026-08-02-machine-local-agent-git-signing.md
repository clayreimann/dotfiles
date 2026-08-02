# Machine-Local Agent Git Signing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the machine-local SSH key Git's default signing identity while interactive Zsh overrides it with Clay's 1Password key and agent launchers deliberately restore the machine identity.

**Architecture:** The chezmoi-managed `~/.gitconfig` is the authoritative default and points at the local machine key. `~/.gitconfig-interactive` includes that baseline and overrides only `user.signingKey`; interactive Zsh selects it with `GIT_CONFIG_GLOBAL`. Agent launchers select `~/.gitconfig` explicitly, while `~/.gitconfig-agent` becomes a compatibility include.

**Tech Stack:** Git SSH signing, Zsh, macOS `open --env`, 1Password SSH agent, chezmoi, GitHub CLI

## Global Constraints

- Every commit and signed tag remains signed; no profile silently falls back to unsigned output.
- Default, GUI, non-interactive, automation, and agent processes use `~/.ssh/id_ed25519_sign.pub`.
- Direct Git commands in interactive Zsh use the existing 1Password public key.
- Codex and Claude launched from interactive Zsh use the machine-local key.
- Private machine keys remain outside chezmoi and have mode `0600`.
- The machine public key is present in GitHub SSH signing keys and `~/.ssh/allowed_signers`.
- Preserve the existing uncommitted desktop app-launch helpers in `private_dot_config/zsh/functions.zsh`.
- Do not modify an application repository.

## File Map

- Create `private_dot_gitconfig-interactive`: interactive profile that includes the default and overrides only the signing key.
- Modify `private_dot_gitconfig`: default machine identity and signed-tag baseline.
- Modify `dot_gitconfig-agent`: compatibility include pointing to the default profile.
- Modify `private_dot_config/zsh/dot_zshrc`: interactive selection of the 1Password profile.
- Modify `private_dot_config/zsh/functions.zsh`: agent launchers explicitly select the default profile.
- Create `scripts/test-git-signing-profiles.zsh`: default, interactive, and compatibility profile assertions.
- Create `scripts/test-git-signing-shell.zsh`: interactive shell and launcher routing assertions.
- Verify `dot_ssh/allowed_signers`; modify it only if the live public key is absent.

---

### Task 1: Make the machine key the default Git identity

**Files:**
- Create: `scripts/test-git-signing-profiles.zsh`
- Create: `private_dot_gitconfig-interactive`
- Modify: `private_dot_gitconfig:6-9,35-41`
- Modify: `dot_gitconfig-agent:1-17`

**Interfaces:**
- Consumes: the current personal public key at `private_dot_gitconfig:9` and machine key path `~/.ssh/id_ed25519_sign.pub`.
- Produces: deterministic default-machine, interactive-personal, and compatibility-machine profiles.

- [ ] **Step 1: Write the failing profile-resolution test**

Create executable `scripts/test-git-signing-profiles.zsh`:

```zsh
#!/bin/zsh
set -euo pipefail

readonly AGENT_KEY="$HOME/.ssh/id_ed25519_sign.pub"
readonly PERSONAL_KEY='key::ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJPn+hLDA7eHS1Ef6qjVQycAoAldvPgK7nIpa/bArJOv Github_SSH_Key'

fail() { print -u2 -- "FAIL: $1"; exit 1; }
assert_equal() {
  [[ "$2" == "$3" ]] || fail "$1: expected '$2', got '$3'"
}
read_global() {
  GIT_CONFIG_GLOBAL="$1" git config --global --get "$2" 2>/dev/null || true
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
```

Run `chmod +x scripts/test-git-signing-profiles.zsh && ./scripts/test-git-signing-profiles.zsh`.

Expected: FAIL on `default signing key`; the current default is still the personal key.

- [ ] **Step 2: Change the default profile**

In `private_dot_gitconfig`, change the signing key and add signed tags while leaving every other setting unchanged:

```gitconfig
[user]
	name = Clay Jensen-Reimann
	email = clayreimann@gmail.com
	signingkey = ~/.ssh/id_ed25519_sign.pub

[commit]
	gpgsign = true
[tag]
	gpgsign = true
```

- [ ] **Step 3: Add the interactive profile**

Create `private_dot_gitconfig-interactive`:

```gitconfig
[include]
	path = ~/.gitconfig

[user]
	signingkey = key::ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJPn+hLDA7eHS1Ef6qjVQycAoAldvPgK7nIpa/bArJOv Github_SSH_Key
```

- [ ] **Step 4: Convert the old agent profile to a compatibility include**

Replace `dot_gitconfig-agent` with:

```gitconfig
[include]
	path = ~/.gitconfig
```

- [ ] **Step 5: Apply and verify the three profiles**

Run:

```bash
chezmoi apply ~/.gitconfig ~/.gitconfig-interactive ~/.gitconfig-agent
./scripts/test-git-signing-profiles.zsh
```

Expected: `git signing profiles: PASS`.

- [ ] **Step 6: Commit the profile boundary**

Do not stage `private_dot_config/zsh/functions.zsh` yet:

```bash
git add private_dot_gitconfig private_dot_gitconfig-interactive dot_gitconfig-agent scripts/test-git-signing-profiles.zsh
GIT_CONFIG_GLOBAL="$HOME/.gitconfig" git commit -m "feat: default Git signing to machine agent key"
```

Expected: a non-interactive machine-key signature.

---

### Task 2: Route interactive shells and agent launchers

**Files:**
- Create: `scripts/test-git-signing-shell.zsh`
- Modify: `private_dot_config/zsh/dot_zshrc:21-23`
- Modify: `private_dot_config/zsh/functions.zsh:29-59`

**Interfaces:**
- Consumes: the profiles from Task 1.
- Produces: personal-key routing for direct interactive Git and machine-key routing for all four agent launchers.

- [ ] **Step 1: Write the failing shell-routing test**

Create executable `scripts/test-git-signing-shell.zsh`:

```zsh
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
```

Run `chmod +x scripts/test-git-signing-shell.zsh && ./scripts/test-git-signing-shell.zsh`.

Expected: FAIL because interactive Zsh does not select the new profile.

- [ ] **Step 2: Select the personal profile in interactive Zsh**

Replace the existing 1Password heading and socket assignment in `private_dot_config/zsh/dot_zshrc` with:

```zsh
# ── Interactive Git identity ──────────────────────────────────────────────────
export SSH_AUTH_SOCK="$HOME/.1password/agent.sock"
export GIT_CONFIG_GLOBAL="$HOME/.gitconfig-interactive"
```

- [ ] **Step 3: Route CLI agents to the default profile**

Update the comment and assignments in `private_dot_config/zsh/functions.zsh`:

```zsh
# Agent commit signing wrappers
# Restore the default machine-local Git identity inherited by non-interactive processes.
claude-agent-sign() {
  GIT_CONFIG_GLOBAL="$HOME/.gitconfig" claude "$@"
}

codex-agent-sign() {
  GIT_CONFIG_GLOBAL="$HOME/.gitconfig" codex "$@"
}
```

- [ ] **Step 4: Route desktop helper launches to the default profile**

Preserve `_agent-app-sign`, its running-process guard, and both app wrapper functions. Change only its `open` line:

```zsh
open -a "$app_name" --env "GIT_CONFIG_GLOBAL=$HOME/.gitconfig"
```

- [ ] **Step 5: Apply and verify shell routing**

Run:

```bash
chezmoi apply ~/.config/zsh/.zshrc ~/.config/zsh/functions.zsh
zsh -n ~/.config/zsh/.zshrc ~/.config/zsh/functions.zsh scripts/test-git-signing-shell.zsh
./scripts/test-git-signing-shell.zsh
```

Expected: syntax checks exit zero and the script prints `git signing shell routing: PASS`.

- [ ] **Step 6: Commit shell routing**

This commit intentionally incorporates the preserved desktop helper work:

```bash
git add private_dot_config/zsh/dot_zshrc private_dot_config/zsh/functions.zsh scripts/test-git-signing-shell.zsh
GIT_CONFIG_GLOBAL="$HOME/.gitconfig" git commit -m "feat: use 1Password signing in interactive Zsh"
```

Expected: a machine-key signature because the command explicitly selects the default profile.

---

### Task 3: Enroll the machine key and verify both identities end to end

**Files:**
- Verify: `~/.ssh/id_ed25519_sign`
- Verify: `~/.ssh/id_ed25519_sign.pub`
- Verify or modify: `dot_ssh/allowed_signers`
- Verify: all Task 1 and Task 2 files

**Interfaces:**
- Consumes: completed profile and shell routing.
- Produces: GitHub-verified machine signing, locally trusted signatures, fail-closed behavior, and source/live parity.

- [ ] **Step 1: Verify the local keypair and permissions**

Run:

```bash
test "$(stat -f '%Lp' ~/.ssh/id_ed25519_sign)" = 600
test "$(stat -f '%Lp' ~/.ssh/id_ed25519_sign.pub)" = 644
diff -u <(ssh-keygen -y -P '' -f ~/.ssh/id_ed25519_sign) <(awk '{print $1, $2}' ~/.ssh/id_ed25519_sign.pub)
```

Expected: every command exits zero; key comparison has no output.

- [ ] **Step 2: Verify local trust registration**

```bash
agent_key_body=$(awk '{print $2}' ~/.ssh/id_ed25519_sign.pub)
awk -v key="$agent_key_body" '$1 == "clayreimann@gmail.com" && $3 == key { found = 1 } END { exit !found }' ~/.ssh/allowed_signers
```

Expected: exit zero. If absent, append one entry with the email, public-key type/body, and machine-specific comment; run `chezmoi add ~/.ssh/allowed_signers`; commit only `dot_ssh/allowed_signers` with `GIT_CONFIG_GLOBAL="$HOME/.gitconfig"`.

- [ ] **Step 3: Verify GitHub signing-key registration**

```bash
agent_key_body=$(awk '{print $2}' ~/.ssh/id_ed25519_sign.pub)
gh api user/ssh_signing_keys --jq '.[].key' | awk -v key="$agent_key_body" '$2 == key { found = 1 } END { exit !found }'
```

Expected: exit zero. If absent, register and re-query:

```bash
gh ssh-key add ~/.ssh/id_ed25519_sign.pub --type signing --title "$(scutil --get ComputerName) agent signing"
gh api user/ssh_signing_keys --jq '.[].key'
```

- [ ] **Step 4: Verify a default machine-key commit**

```bash
agent_repo=$(mktemp -d /tmp/git-agent-signing.XXXXXX)
env -u GIT_CONFIG_GLOBAL -u GIT_CONFIG_COUNT git -C "$agent_repo" init -q
env -u GIT_CONFIG_GLOBAL -u GIT_CONFIG_COUNT git -C "$agent_repo" commit --allow-empty -m "verify machine agent signature"
env -u GIT_CONFIG_GLOBAL -u GIT_CONFIG_COUNT git -C "$agent_repo" verify-commit HEAD
test "$(env -u GIT_CONFIG_GLOBAL -u GIT_CONFIG_COUNT git -C "$agent_repo" log -1 --format='%G?')" = G
```

Expected: no interaction and a good machine-key signature.

- [ ] **Step 5: Verify an interactive 1Password-key commit**

Run with a PTY:

```bash
interactive_repo=$(mktemp -d /tmp/git-interactive-signing.XXXXXX)
git -C "$interactive_repo" init -q
INTERACTIVE_SIGNING_REPO="$interactive_repo" zsh -ic 'git -C "$INTERACTIVE_SIGNING_REPO" commit --allow-empty -m "verify interactive 1Password signature"'
git -C "$interactive_repo" verify-commit HEAD
test "$(git -C "$interactive_repo" log -1 --format='%G?')" = G
agent_fingerprint=$(ssh-keygen -lf ~/.ssh/id_ed25519_sign.pub | awk '{print $2}')
personal_key=$(GIT_CONFIG_GLOBAL="$HOME/.gitconfig-interactive" git config --global --get user.signingkey)
personal_fingerprint=$(print -r -- "${personal_key#key::}" | ssh-keygen -lf - | awk '{print $2}')
commit_fingerprint=$(git -C "$interactive_repo" log -1 --format='%GF')
test "$commit_fingerprint" = "$personal_fingerprint"
test "$commit_fingerprint" != "$agent_fingerprint"
```

Expected: one 1Password approval, a good signature, and a fingerprint different from the machine key.

- [ ] **Step 6: Verify both profiles fail closed**

```bash
missing_repo=$(mktemp -d /tmp/git-missing-signing-key.XXXXXX)
git -C "$missing_repo" init -q
if env -u GIT_CONFIG_GLOBAL git -C "$missing_repo" -c user.signingkey=/tmp/nonexistent-agent-key commit --allow-empty -m "must fail"; then
  echo "default profile unexpectedly committed" >&2
  exit 1
fi
if GIT_CONFIG_GLOBAL="$HOME/.gitconfig-interactive" git -C "$missing_repo" -c user.signingkey=/tmp/nonexistent-personal-key commit --allow-empty -m "must fail"; then
  echo "interactive profile unexpectedly committed" >&2
  exit 1
fi
if git -C "$missing_repo" rev-parse --verify HEAD >/dev/null 2>&1; then
  echo "fail-closed test unexpectedly created HEAD" >&2
  exit 1
fi
```

Expected: both commit attempts fail and no commit exists.

- [ ] **Step 7: Run the complete gate**

```bash
./scripts/test-git-signing-profiles.zsh
./scripts/test-git-signing-shell.zsh
zsh -n ~/.config/zsh/.zshrc ~/.config/zsh/functions.zsh scripts/test-git-signing-profiles.zsh scripts/test-git-signing-shell.zsh
chezmoi diff ~/.gitconfig ~/.gitconfig-interactive ~/.gitconfig-agent ~/.config/zsh/.zshrc ~/.config/zsh/functions.zsh ~/.ssh/allowed_signers
git diff --check
git status --short --branch
git log -5 --show-signature --stat --oneline
git show --check --oneline HEAD
```

Expected: both scripts pass; syntax, parity, and whitespace checks are clean; only planned local commits are ahead of `origin/main`; every new commit has a good signature.

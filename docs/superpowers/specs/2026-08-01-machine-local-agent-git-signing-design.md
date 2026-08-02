# Machine-Local Agent Git Signing Design

**Status:** Approved
**Date:** 2026-08-01

## Purpose

Git commits should be signed by default with a non-interactive, machine-local SSH key intended for software agents. An interactive Zsh session should deliberately override that default with Clay's 1Password-backed SSH signing key so commit signatures distinguish human interactive work from agent work.

## Goals

- Sign commits from GUI applications, non-interactive shells, automation, and agents with a distinct key on each machine.
- Sign direct Git commits from interactive Zsh sessions with the 1Password-backed personal key.
- Ensure Codex and Claude processes launched from an interactive shell switch back to the machine-local agent key.
- Register every machine-local public key with GitHub as a signing key so agent commits display as verified.
- Fail closed when the selected signing key is unavailable; never silently create an unsigned commit or switch identities.
- Keep the configuration durable and synchronized through chezmoi without storing private keys in chezmoi.

## Non-Goals

- Changing Git author name or email between human and agent commits.
- Storing or distributing private signing keys through chezmoi.
- Automatically falling back from the personal identity to the agent identity.
- Modifying SideShelf or any other application repository.

## Configuration Architecture

### Default Git profile

`~/.gitconfig` is the universal baseline and remains the authoritative location for normal Git configuration. Its signing identity is the machine-local public key at `~/.ssh/id_ed25519_sign.pub`. SSH commit signing and automatic commit signing remain enabled. Signed tags remain enabled to preserve the behavior of the existing agent profile.

Processes without a Git environment override use this profile. This includes applications launched from Finder or the Dock, non-interactive shells, cron-like automation, and agent subprocesses launched by desktop applications.

### Interactive Git profile

`~/.gitconfig-interactive` includes `~/.gitconfig` and then overrides only `user.signingKey` with the 1Password public key. It does not duplicate aliases, credential helpers, author identity, signing format, or other Git configuration.

Interactive Zsh exports `GIT_CONFIG_GLOBAL=$HOME/.gitconfig-interactive`. Because `.zshrc` is only evaluated for interactive shells, non-interactive processes do not receive this override. The same shell configuration continues to export the 1Password SSH agent socket required to use the personal key.

### Agent launchers

Codex and Claude CLI launch functions explicitly set `GIT_CONFIG_GLOBAL=$HOME/.gitconfig` before starting the agent. This overrides the interactive profile inherited from the parent terminal and restores the machine-local identity.

ChatGPT and Claude desktop launch helpers do the same when the applications are deliberately launched from an interactive terminal. Normal Finder or Dock launches need no helper because the default profile already selects the machine-local key.

### Compatibility profile

`~/.gitconfig-agent` becomes a compatibility profile that only includes `~/.gitconfig`. It contains no duplicated user, signing, or tag settings. Existing app processes and old launch commands that still reference this path therefore resolve to the new baseline without configuration drift.

## Identity Resolution

| Context | Git global profile | Signing key |
| --- | --- | --- |
| Finder or Dock application | `~/.gitconfig` | Machine-local agent key |
| Non-interactive shell or automation | `~/.gitconfig` | Machine-local agent key |
| Direct Git command in interactive Zsh | `~/.gitconfig-interactive` | 1Password personal key |
| Codex or Claude launched from interactive Zsh | `~/.gitconfig` | Machine-local agent key |
| Desktop app launched with an agent helper | `~/.gitconfig` | Machine-local agent key |
| Legacy process referencing `.gitconfig-agent` | Compatibility include to `~/.gitconfig` | Machine-local agent key |

## Machine Enrollment

Each machine has an independent Ed25519 keypair at:

- Private key: `~/.ssh/id_ed25519_sign`, mode `0600`
- Public key: `~/.ssh/id_ed25519_sign.pub`, mode `0644`

The private key is intentionally unencrypted so agents can sign without an approval prompt. It is protected by the local user account, filesystem permissions, and device security. The private key is never committed to chezmoi.

Each public key is:

1. Given a machine-specific comment and GitHub title.
2. Added to GitHub as an SSH signing key.
3. Added to the chezmoi-managed `~/.ssh/allowed_signers` file under Clay's Git email.

Public keys are not secret and may be stored in the dotfiles repository. Losing or retiring a machine requires removing its signing key from GitHub and, when appropriate, from `allowed_signers`.

## Failure Behavior

- If the machine-local private key is missing or unreadable, agent/default commits fail because automatic signing is required.
- If 1Password or its SSH agent is unavailable, interactive commits fail rather than falling back to the machine-local identity.
- Neither profile disables signing or silently creates unsigned commits.
- Selecting the other identity is always explicit: enter an interactive shell for the personal identity, or use an agent launcher/default environment for the machine identity.

## Migration

1. Record the currently resolved default and interactive signing identities.
2. Change the default signing key in the chezmoi-managed `.gitconfig` to the machine-local public-key path and preserve signed commits and tags.
3. Add the chezmoi-managed interactive profile that includes the default and overrides the signing key.
4. Export the interactive profile from `.zshrc` after configuring the 1Password SSH agent socket.
5. Update CLI and desktop agent launchers to select the default `.gitconfig` explicitly.
6. Convert `.gitconfig-agent` into the compatibility include.
7. Register the current machine public key with GitHub if it is not already registered and confirm its `allowed_signers` entry.
8. Apply the chezmoi source and verify source/live-file parity.

The pre-existing uncommitted desktop app-launch helper changes in `private_dot_config/zsh/functions.zsh` must be preserved and committed separately from this design document.

## Verification

All commit tests use disposable repositories and do not alter application history.

1. **Default identity:** In an environment without `GIT_CONFIG_GLOBAL`, confirm Git resolves `~/.ssh/id_ed25519_sign.pub`, creates a signed commit without interaction, and reports a good signature from the machine key.
2. **Interactive identity:** In interactive Zsh, confirm Git resolves the 1Password public key. Create one disposable commit and approve the intentional 1Password prompt to verify the signature end to end.
3. **Terminal-launched agents:** From interactive Zsh, replace the Codex or Claude executable with a harmless probe and confirm the launcher resolves the machine-local key.
4. **Desktop launch helpers:** Probe the `open --env` arguments and confirm they set `GIT_CONFIG_GLOBAL` to the default profile.
5. **Fail closed:** Temporarily point each profile at a nonexistent key in a disposable command scope and verify commit creation fails without producing a commit.
6. **GitHub registration:** Confirm the current machine public key appears among the account's SSH signing keys.
7. **Local trust:** Confirm the machine public key appears in `allowed_signers` and `git log --show-signature` reports it as trusted.
8. **Configuration integrity:** Run Zsh syntax checks, Git config-origin checks, `chezmoi diff`, and source/live-file comparisons.

## Security and Operational Notes

The signature identifies which credential approved a commit, not whether the change was reviewed. The personal 1Password key remains the stronger signal for direct interactive work because its use requires approval. Machine-local keys are intentionally lower-friction and should be revoked promptly if a device is lost or compromised.

The design keeps the identity distinction at the Git configuration boundary. Repositories do not need local signing overrides, and agents do not need special commit syntax.

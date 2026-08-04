# Tea Forgejo Tooling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an ephemeral Connect-backed Tea adapter plus the narrow required-check and stack-deployment policy commands.

**Architecture:** `tea_session.py` owns temporary Tea authentication and process execution. `forgejo_policy.py` owns only the Forgejo 14 Actions parsing, polling, and infra deployment validation. The existing CLI and small executable launchers expose those components without embedding secrets or implementing a second HTTP client.

**Tech Stack:** Python 3.12 standard library, Tea 0.14.2+, 1Password Connect, unittest.

## Global Constraints

- Tea is the engine; authenticated Forgejo calls use `tea` or `tea api`, never `urllib`, `curl`, or a new SDK.
- The token is read from Connect item `yznfzgoql7jl4oa6spa7vm3644`, field `api_token`, and is never placed in argv, output, diagnostics, or the caller environment.
- General Tea commands may target arbitrary repository slugs on the pinned Forgejo server.
- Homelab policy commands are pinned to the exact values in `/Users/clay/Code/homelab/infra/config/mac-agent/credential-map.json`.
- The policy helper may not merge, approve a PR, approve a production environment, manage Forgejo secrets, or mutate a host directly. General Tea remains account-authorized and is intentionally not a policy sandbox.
- Use TDD and preserve all existing 120 passing tests.

---

### Task 1: Parse the extended public configuration

**Files:**
- Modify: `dot_local/lib/homelab_agent/models.py`
- Modify: `dot_local/lib/homelab_agent/config.py`
- Modify: `dot_local/lib/homelab_agent/doctor.py`
- Modify: `tests/test_homelab_agent_config.py`
- Modify: `tests/test_homelab_agent_commands.py`

**Interfaces:**
- Produces: immutable Forgejo API metadata and `ForgejoAutomation` on `AgentConfig`.

- [ ] **Step 1: Write failing config and doctor tests**

Require exact API URL/user/token-field metadata, exact automation values, and
Tea in the tool check. Mutate every new pinned value and assert fail-closed
`ConfigError` behavior.

- [ ] **Step 2: Run focused tests and confirm RED**

Run:

```bash
/opt/homebrew/bin/python3.12 -m unittest tests.test_homelab_agent_config tests.test_homelab_agent_commands -v
```

- [ ] **Step 3: Implement immutable models and strict parsing**

Introduce a Forgejo API-aware identity model and `ForgejoAutomation` with
repository, required workflow tuple, deploy workflow, deploy ref, and deploy
target tuple. Add Tea at `/opt/homebrew/bin/tea` to doctor tool discovery.

- [ ] **Step 4: Run focused tests and confirm GREEN**

Run the Step 2 command; expect all focused tests to pass.

- [ ] **Step 5: Commit**

```bash
git add dot_local/lib/homelab_agent/models.py dot_local/lib/homelab_agent/config.py dot_local/lib/homelab_agent/doctor.py tests
git commit -m "feat: load Tea Forgejo policy"
```

### Task 2: Add the ephemeral general Tea adapter

**Files:**
- Create: `dot_local/lib/homelab_agent/tea_session.py`
- Create: `dot_local/bin/executable_homelab-agent-tea`
- Modify: `dot_local/lib/homelab_agent/cli.py`
- Modify: `tests/test_homelab_agent_commands.py`
- Create: `tests/test_homelab_agent_tea.py`

**Interfaces:**
- Consumes: Forgejo API metadata from Task 1 and `ConnectClient.get_string_field`.
- Produces: `TeaSession`, `run_tea(arguments, ...)`, and CLI grammar `tea -- TEA_ARGS...`.

- [ ] **Step 1: Write failing session and CLI tests**

Cover exact `--` grammar, arbitrary `--repo owner/repo` pass-through, Tea
0.14.2 minimum check, child-only `GITEA_SERVER_TOKEN`, caller environment
scrubbing, mode-0700 temporary config root, `tea api /user` identity check,
exit-code/output forwarding, redacted setup errors, and cleanup after success,
failure, and `KeyboardInterrupt`.

- [ ] **Step 2: Run focused tests and confirm RED**

Run:

```bash
/opt/homebrew/bin/python3.12 -m unittest tests.test_homelab_agent_tea -v
```

- [ ] **Step 3: Implement the minimum Tea session**

Use `tempfile.TemporaryDirectory`, child environment copies, and injected
process executors. Create the login with `GITEA_SERVER_URL`,
`GITEA_SERVER_USER`, and `GITEA_SERVER_TOKEN`; remove those variables before
the caller command. Verify `/user` returns login `claude`. Forward caller
arguments unchanged after the wrapper's `--` separator.

- [ ] **Step 4: Run focused and regression tests**

Run:

```bash
/opt/homebrew/bin/python3.12 -m unittest tests.test_homelab_agent_tea tests.test_homelab_agent_commands -v
```

- [ ] **Step 5: Commit**

```bash
git add dot_local/bin/executable_homelab-agent-tea dot_local/lib/homelab_agent tests
git commit -m "feat: add ephemeral Tea credential adapter"
```

### Task 3: Support the staged version-1 to version-2 map rollout

**Files:**
- Modify: `dot_local/lib/homelab_agent/models.py`
- Modify: `dot_local/lib/homelab_agent/config.py`
- Modify: `tests/test_homelab_agent_config.py`
- Modify: `tests/test_homelab_agent_tea.py`

**Interfaces:**
- Consumes: the legacy onboarding version-1 map and the Tea policy version-2 map.
- Produces: existing commands that work with either map and Tea commands that fail closed with a public upgrade message until version 2 is installed.

- [ ] **Step 1: Write failing transition tests**

Use the exact pre-Tea version-1 map shape and prove `doctor`, Git, SSH, and OP
configuration still loads. Prove Tea setup stops before Keychain/Connect with
`Tea workflow policy requires credential map version 2`. Keep all exact-key
and pin tests for version 2.

- [ ] **Step 2: Run focused tests and confirm RED**

Run:

```bash
/opt/homebrew/bin/python3.12 -m unittest tests.test_homelab_agent_config tests.test_homelab_agent_tea -v
```

- [ ] **Step 3: Implement the compatibility window**

Parse version 1 with its original exact top-level, Forgejo, and tool keys.
Represent API identity and automation policy as unavailable for that version.
Parse version 2 with the new exact fields and pins. Existing non-Tea commands
may use either. Tea and Forgejo policy commands require version 2 before any
secret access. Do not infer API fields or automation defaults into version 1.

- [ ] **Step 4: Run focused tests and commit**

Run the Step 2 command, then commit as
`fix: support staged Tea policy rollout`.

### Task 4: Add homelab-specific checks and deploy policy

**Files:**
- Create: `dot_local/lib/homelab_agent/forgejo_policy.py`
- Create: `dot_local/bin/executable_homelab-agent-forgejo`
- Modify: `dot_local/lib/homelab_agent/cli.py`
- Modify: `tests/test_homelab_agent_commands.py`
- Create: `tests/test_homelab_agent_forgejo.py`

**Interfaces:**
- Consumes: `TeaSession.api_json`, `ForgejoAutomation`, and the exact Forgejo 14 response fields `workflow_runs`, `workflow_id`, `id`, `status`, `html_url`, `commit_sha`, `created`, and dispatch `id`.
- Produces: `checks status`, `checks wait`, `deploy stacks`, `deploy status`, and `deploy wait`.

- [ ] **Step 1: Write failing policy tests**

Cover newest-run-per-workflow selection, missing/pending/success/failure state
aggregation, timeout, malformed JSON, unexpected fields/types, redacted Tea
errors, and public status output. For deploy, reject unapproved repos,
workflows, refs, hosts, empty reasons, invalid stack CSV, unknown flags, and
caller-controlled `confirm`; assert the only dispatch body uses `main`,
`return_run_info: true`, `confirm: apply`, and the approved inputs. Prove
`blocked` reports the production approval gate without approving it.

- [ ] **Step 2: Run focused tests and confirm RED**

Run:

```bash
/opt/homebrew/bin/python3.12 -m unittest tests.test_homelab_agent_forgejo -v
```

- [ ] **Step 3: Implement parsing, polling, and dispatch**

Use `tea api` only through `TeaSession`. Poll at a bounded interval with an
injectable clock/sleeper. Return nonzero for terminal failures and timeout;
return a distinct public waiting result for a blocked deployment. Do not add
merge, approval, secret, workflow-management, or arbitrary API commands.

- [ ] **Step 4: Run the full suite and diff check**

Run:

```bash
/opt/homebrew/bin/python3.12 -m unittest discover -s tests -v
git diff --check
```

Expected: all tests pass except the established opt-in Keychain integration
skip, and the diff check is silent.

- [ ] **Step 5: Commit**

```bash
git add dot_local/bin/executable_homelab-agent-forgejo dot_local/lib/homelab_agent tests docs/superpowers/plans/2026-08-04-tea-forgejo-tooling.md
git commit -m "feat: add gated Forgejo workflow commands"
```

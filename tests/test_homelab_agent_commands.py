"""Tests for the deliberately narrow 1Password command wrapper."""
from __future__ import annotations

import io
import os
import subprocess
import sys
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "dot_local" / "lib"))

from homelab_agent.op_command import UsageError, run_op, validate_op_argv
from homelab_agent.process import AgentError, Runner, Secret
from homelab_agent.models import Repository


TOKEN = "token-value"
EDIT_ITEM_ID = "yznfzgoql7jl4oa6spa7vm3644"


class FakeKeychain:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def local_account(self) -> str:
        self.calls.append(("local_account",))
        return "test-mac"

    def read(self, service: str, account: str) -> Secret:
        self.calls.append(("read", service, account))
        return Secret(TOKEN)


def completed(stdout: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(("/opt/homebrew/bin/op",), 0, stdout=stdout, stderr="secret")


class FakeRunner:
    def __init__(self, responses: list[subprocess.CompletedProcess[str]] | None = None) -> None:
        self.calls: list[object] = []
        self.responses = list(responses or [])

    def run(self, spec: object) -> subprocess.CompletedProcess[str]:
        self.calls.append(spec)
        if self.responses:
            return self.responses.pop(0)
        return completed()


class EnvironmentCapturingProcess:
    def __init__(self, stdout: str = "") -> None:
        self.stdout = stdout
        self.calls: list[dict[str, Any]] = []

    def __call__(self, argv: tuple[str, ...], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append({"argv": argv, **kwargs})
        return subprocess.CompletedProcess(argv, 0, stdout=self.stdout, stderr="secret")


class FakeRoute:
    def __init__(self) -> None:
        self.opened_with: list[object] = []

    @contextmanager
    def open(self, config: object):
        self.opened_with.append(config)
        yield "http://approved-connect.example:8080"


def config() -> SimpleNamespace:
    return SimpleNamespace(
        connect_keychain_service="connect-service",
        vault_name="Homelab Secrets",
    )


class OpCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.keychain = FakeKeychain()
        self.runner = FakeRunner()
        self.route = FakeRoute()
        self.output = io.StringIO()

    def run_command(
        self,
        argv: list[str],
        stdin: str = "{}",
        *,
        runner: Runner | FakeRunner | None = None,
    ) -> int:
        return run_op(
            argv,
            load=config,
            keychain_factory=lambda: self.keychain,
            route_factory=lambda **_kwargs: self.route,
            runner=runner or self.runner,
            stdin=io.StringIO(stdin),
            output=self.output,
        )

    def test_item_delete_is_rejected_before_keychain_access(self) -> None:
        with self.assertRaisesRegex(UsageError, "operation is not supported"):
            self.run_command(["item", "delete", "abc"])

        self.assertEqual([], self.keychain.calls)

    def test_rejects_disallowed_forms_before_keychain_access(self) -> None:
        cases = (
            [],
            ["item", "get", "abc", "--connect-host", "http://other"],
            ["item", "get", "abc", "--template", "item.json"],
            ["item", "get", "abc", "password=visible"],
            ["item", "get", "abc", "--vault", "Homelab Secrets"],
            ["item", "get", "abc", "OP_CONNECT_TOKEN=override"],
            ["item", "get", "abc", "--reveal"],
            ["item", "list", "--account", "personal"],
        )

        for argv in cases:
            with self.subTest(argv=argv):
                with self.assertRaises(UsageError):
                    self.run_command(list(argv))

        self.assertEqual([], self.keychain.calls)

    def test_allowed_read_has_child_only_connect_environment(self) -> None:
        previous_host = os.environ.get("OP_CONNECT_HOST")
        previous_token = os.environ.get("OP_CONNECT_TOKEN")
        os.environ.pop("OP_CONNECT_HOST", None)
        os.environ.pop("OP_CONNECT_TOKEN", None)
        try:
            self.run_command(["item", "get", "item-id"])
        finally:
            if previous_host is not None:
                os.environ["OP_CONNECT_HOST"] = previous_host
            if previous_token is not None:
                os.environ["OP_CONNECT_TOKEN"] = previous_token

        call = self.runner.calls[-1]
        self.assertEqual("token-value", call.env_overlay["OP_CONNECT_TOKEN"])  # type: ignore[attr-defined]
        self.assertEqual(
            "http://approved-connect.example:8080",
            call.env_overlay["OP_CONNECT_HOST"],  # type: ignore[attr-defined]
        )
        self.assertIn("OP_CONNECT_HOST", call.unset_env)  # type: ignore[attr-defined]
        self.assertIn("OP_CONNECT_TOKEN", call.unset_env)  # type: ignore[attr-defined]
        self.assertNotIn("OP_CONNECT_TOKEN", os.environ)
        self.assertNotIn("OP_CONNECT_HOST", os.environ)

    def test_create_requires_stdin_template_marker(self) -> None:
        with self.assertRaisesRegex(UsageError, "item create requires JSON on stdin"):
            self.run_command(["item", "create", "password=visible-in-process-list"])

        self.assertEqual([], self.keychain.calls)

    def test_create_forwards_json_only_on_stdin(self) -> None:
        self.run_command(["item", "create", "-"], '{"title": "Router password"}')

        call = self.runner.calls[-1]
        self.assertEqual(
            ("/opt/homebrew/bin/op", "item", "create", "-", "--vault", "Homelab Secrets"),
            call.argv,  # type: ignore[attr-defined]
        )
        self.assertIsInstance(call.stdin, Secret)  # type: ignore[attr-defined]
        self.assertEqual('{"title": "Router password"}', call.stdin.reveal())  # type: ignore[attr-defined]

    def test_field_deletion_is_rejected_before_keychain_access(self) -> None:
        with self.assertRaisesRegex(UsageError, "field deletion is not supported"):
            self.run_command(["item", "edit", EDIT_ITEM_ID, "section.field[delete]"])

        self.assertEqual([], self.keychain.calls)

    def test_mutations_reject_all_caller_arguments_beyond_the_exact_stdin_shape(self) -> None:
        cases = (
            ["item", "create", "-", "--title", "Router"],
            ["item", "create", "-", "--url", "https://router.example"],
            ["item", "create", "-", "--tags", "homelab"],
            ["item", "create", "-", "--generate-password"],
            ["item", "create", "-", "password=visible"],
            ["item", "create", "-", "--template", "item.json"],
            ["item", "edit", EDIT_ITEM_ID, "trailing-argument"],
        )

        for argv in cases:
            with self.subTest(argv=argv):
                with self.assertRaisesRegex(UsageError, "exact stdin-only form"):
                    self.run_command(list(argv))

        self.assertEqual([], self.keychain.calls)

    def test_edit_requires_a_26_character_item_id_and_json_stdin(self) -> None:
        with self.assertRaisesRegex(UsageError, "26-character item UUID"):
            self.run_command(["item", "edit", "not-an-item-id"])
        self.assertEqual([], self.keychain.calls)

        with self.assertRaisesRegex(UsageError, "item edit requires JSON on stdin"):
            self.run_command(["item", "edit", EDIT_ITEM_ID], "not json")
        self.assertEqual([], self.keychain.calls)

    def test_edit_forwards_json_only_on_stdin(self) -> None:
        self.run_command(["item", "edit", EDIT_ITEM_ID], '{"fields": []}')

        call = self.runner.calls[-1]
        self.assertEqual(
            ("/opt/homebrew/bin/op", "item", "edit", EDIT_ITEM_ID, "--vault", "Homelab Secrets"),
            call.argv,  # type: ignore[attr-defined]
        )
        self.assertIsInstance(call.stdin, Secret)  # type: ignore[attr-defined]
        self.assertEqual('{"fields": []}', call.stdin.reveal())  # type: ignore[attr-defined]

    def test_validation_appends_the_only_allowed_vault_to_item_operations(self) -> None:
        self.assertEqual(
            ("item", "list", "--vault", "Homelab Secrets"),
            validate_op_argv(["item", "list"]),
        )

    def test_vault_and_read_commands_preserve_their_vault_scoped_cli_syntax(self) -> None:
        self.assertEqual(
            ("vault", "get", "Homelab Secrets", "--format", "json"),
            validate_op_argv(["vault", "list"]),
        )
        self.assertEqual(
            ("vault", "get", "Homelab Secrets"),
            validate_op_argv(["vault", "get", "Homelab Secrets"]),
        )
        self.assertEqual(
            ("read", "op://Homelab Secrets/router/password"),
            validate_op_argv(["read", "op://Homelab Secrets/router/password"]),
        )

    def test_read_rejects_a_reference_outside_homelab_secrets_before_keychain(self) -> None:
        with self.assertRaisesRegex(UsageError, "only the Homelab Secrets vault"):
            self.run_command(["read", "op://Personal/router/password"])

        self.assertEqual([], self.keychain.calls)

    def test_each_read_operation_forwards_successful_child_stdout(self) -> None:
        cases = (
            ["vault", "get", "Homelab Secrets"],
            ["item", "list"],
            ["item", "get", "item-id"],
            ["read", "op://Homelab Secrets/router/password"],
        )

        for argv in cases:
            with self.subTest(argv=argv):
                output = io.StringIO()
                runner = FakeRunner([completed("allowed child output\n")])
                rc = run_op(
                    argv,
                    load=config,
                    keychain_factory=lambda: self.keychain,
                    route_factory=lambda **_kwargs: self.route,
                    runner=runner,
                    stdin=io.StringIO(),
                    output=output,
                )
                self.assertEqual(0, rc)
                self.assertEqual("allowed child output\n", output.getvalue())

    def test_create_and_edit_forward_successful_child_stdout(self) -> None:
        cases = (
            (["item", "create", "-"], '{"title": "Router"}'),
            (["item", "edit", EDIT_ITEM_ID], '{"fields": []}'),
        )

        for argv, stdin in cases:
            with self.subTest(argv=argv):
                output = io.StringIO()
                runner = FakeRunner([completed("mutation result\n")])
                rc = run_op(
                    argv,
                    load=config,
                    keychain_factory=lambda: self.keychain,
                    route_factory=lambda **_kwargs: self.route,
                    runner=runner,
                    stdin=io.StringIO(stdin),
                    output=output,
                )
                self.assertEqual(0, rc)
                self.assertEqual("mutation result\n", output.getvalue())

    def test_vault_list_uses_confined_get_and_emits_a_list_shaped_response(self) -> None:
        self.runner = FakeRunner(
            [
                completed(
                    '{"id":"homelab-id","name":"Homelab Secrets"}'
                )
            ]
        )

        self.run_command(["vault", "list"])

        call = self.runner.calls[-1]
        self.assertEqual(
            (
                "/opt/homebrew/bin/op",
                "vault",
                "get",
                "Homelab Secrets",
                "--format",
                "json",
            ),
            call.argv,  # type: ignore[attr-defined]
        )
        self.assertEqual(
            '[{"id": "homelab-id", "name": "Homelab Secrets"}]\n',
            self.output.getvalue(),
        )

    def test_vault_list_fails_closed_for_invalid_or_mismatched_metadata(self) -> None:
        payloads = (
            "not-json",
            '[{"id":"homelab-id","name":"Homelab Secrets"}]',
            '{"id":"personal-id","name":"Personal"}',
        )

        for payload in payloads:
            with self.subTest(payload=payload):
                output = io.StringIO()
                runner = FakeRunner([completed(payload)])
                with self.assertRaisesRegex(AgentError, "exact Homelab Secrets vault metadata"):
                    run_op(
                        ["vault", "list"],
                        load=config,
                        keychain_factory=lambda: self.keychain,
                        route_factory=lambda **_kwargs: self.route,
                        runner=runner,
                        stdin=io.StringIO(),
                        output=output,
                    )
                self.assertEqual("", output.getvalue())

    def test_unapproved_operation_flags_are_rejected_before_keychain_access(self) -> None:
        cases = (
            ["vault", "list", "--format", "json"],
            ["vault", "get", "Homelab Secrets", "--format", "json"],
            ["item", "list", "--format", "json"],
            ["item", "get", "item-id", "--format", "json"],
            ["read", "op://Homelab Secrets/router/password", "--no-newline"],
            ["--format", "json", "item", "list"],
        )

        for argv in cases:
            with self.subTest(argv=argv):
                with self.assertRaises(UsageError):
                    self.run_command(list(argv))

        self.assertEqual([], self.keychain.calls)

    def test_child_scrubs_every_inherited_op_variable_and_preserves_parent_environment(self) -> None:
        executor = EnvironmentCapturingProcess("item output\n")
        inherited = {
            "OP_ACCOUNT": "personal",
            "OP_CONFIG_DIR": "/tmp/unapproved-op-config",
            "OP_SERVICE_ACCOUNT_TOKEN": "service-token",
            "OP_SESSION_personal": "session-token",
            "OP_CONNECT_HOST": "http://unapproved-connect.example",
            "OP_CONNECT_TOKEN": "unapproved-connect-token",
            "OP_FORMAT": "json",
        }

        with patch.dict(os.environ, inherited, clear=False):
            self.run_command(["item", "get", "item-id"], runner=Runner(executor))
            self.assertEqual(inherited, {name: os.environ[name] for name in inherited})

        child_environment = executor.calls[-1]["env"]
        self.assertEqual(
            "http://approved-connect.example:8080",
            child_environment["OP_CONNECT_HOST"],
        )
        self.assertEqual(TOKEN, child_environment["OP_CONNECT_TOKEN"])
        for name in inherited:
            if name not in {"OP_CONNECT_HOST", "OP_CONNECT_TOKEN"}:
                self.assertNotIn(name, child_environment)

    def test_edit_rejects_an_uppercase_26_character_item_id_before_keychain(self) -> None:
        with self.assertRaisesRegex(UsageError, "26-character item UUID"):
            self.run_command(["item", "edit", "YZNFZGOQL7JL4OA6SPA7VM3644"])

        self.assertEqual([], self.keychain.calls)

    def test_cli_dispatches_op_to_the_scoped_wrapper(self) -> None:
        from homelab_agent import cli

        observed: list[tuple[str, ...]] = []
        rc = cli.main(
            ["op", "item", "list"],
            op_runner=lambda argv: observed.append(tuple(argv)) or 7,
        )

        self.assertEqual(7, rc)
        self.assertEqual([("item", "list")], observed)


class GitCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        from homelab_agent.git_command import SSH_COMMAND

        self.runner = FakeRunner()
        self.ssh_command = SSH_COMMAND
        self.repositories = (
            Repository(
                "infra",
                "ssh://git@git.4406.madtown.cloud:2222/homelab/infra.git",
                Path("/Users/clay/Code/homelab/infra"),
            ),
            Repository(
                "platform-deploy",
                "ssh://git@git.4406.madtown.cloud:2222/homelab/platform-deploy.git",
                Path("/Users/clay/Code/homelab/platform-deploy"),
            ),
            Repository(
                "observability",
                "ssh://git@git.4406.madtown.cloud:2222/homelab/observability.git",
                Path("/Users/clay/Code/homelab/observability"),
            ),
        )
        self.config = SimpleNamespace(repositories=self.repositories)

    def test_unknown_name_is_rejected_before_runner_calls(self) -> None:
        from homelab_agent.git_command import UsageError as GitUsageError, run_git

        with self.assertRaisesRegex(GitUsageError, "unknown repository"):
            run_git(["clone", "unknown"], load=lambda: self.config, runner=self.runner)

        self.assertEqual([], self.runner.calls)

    def test_initial_clone_uses_helper_and_sets_local_transport(self) -> None:
        from homelab_agent.git_command import clone_repository

        repository = self.repositories[0]
        with patch.object(Path, "exists", return_value=False):
            clone_repository(repository, runner=self.runner)

        calls = [call.argv for call in self.runner.calls]  # type: ignore[attr-defined]
        self.assertIn(
            (
                "/usr/bin/git",
                "-c",
                f"core.sshCommand={self.ssh_command}",
                "clone",
                repository.remote,
                str(repository.path),
            ),
            calls,
        )
        self.assertIn(
            (
                "/usr/bin/git",
                "-C",
                str(repository.path),
                "config",
                "--local",
                "core.sshCommand",
                self.ssh_command,
            ),
            calls,
        )
        self.assertFalse(any("--global" in call for call in calls))

    def test_existing_non_repository_directory_is_refused(self) -> None:
        from homelab_agent.git_command import GitError, clone_repository

        repository = self.repositories[0]
        with patch.object(Path, "exists", return_value=True), patch.object(
            Path, "is_dir", return_value=True
        ):
            with self.assertRaisesRegex(GitError, "not an approved Git worktree"):
                clone_repository(repository, runner=self.runner)

        self.assertEqual(1, len(self.runner.calls))
        self.assertEqual(
            ("/usr/bin/git", "-C", str(repository.path), "rev-parse", "--is-inside-work-tree"),
            self.runner.calls[0].argv,  # type: ignore[attr-defined]
        )

    def test_existing_correct_worktree_is_idempotent(self) -> None:
        from homelab_agent.git_command import clone_repository

        repository = self.repositories[0]
        self.runner = FakeRunner(
            [
                completed("true\n"),
                completed(str(repository.path) + "\n"),
                completed(repository.remote + "/\n"),
            ]
        )
        with patch.object(Path, "exists", return_value=True), patch.object(
            Path, "is_dir", return_value=True
        ):
            clone_repository(repository, runner=self.runner)

        calls = [call.argv for call in self.runner.calls]  # type: ignore[attr-defined]
        self.assertFalse(any("clone" in call for call in calls))
        self.assertFalse(any("remote" in call and "set-url" in call for call in calls))
        self.assertIn(
            ("/usr/bin/git", "-C", str(repository.path), "config", "--local", "core.sshCommand", self.ssh_command),
            calls,
        )

    def test_existing_wrong_origin_is_refused_without_repair(self) -> None:
        from homelab_agent.git_command import GitError, clone_repository

        repository = self.repositories[0]
        self.runner = FakeRunner(
            [
                completed("true\n"),
                completed(str(repository.path) + "\n"),
                completed("ssh://git@elsewhere:2222/homelab/infra.git\n"),
            ]
        )
        with patch.object(Path, "exists", return_value=True), patch.object(
            Path, "is_dir", return_value=True
        ):
            with self.assertRaisesRegex(GitError, "origin does not match"):
                clone_repository(repository, runner=self.runner)

        calls = [call.argv for call in self.runner.calls]  # type: ignore[attr-defined]
        self.assertFalse(any("set-url" in call for call in calls))

    def test_clone_foundation_preserves_declared_order(self) -> None:
        from homelab_agent.git_command import clone_foundation

        with patch.object(Path, "exists", return_value=False):
            clone_foundation(load=lambda: self.config, runner=self.runner)

        clone_remotes = [call.argv[4] for call in self.runner.calls if call.argv[3] == "clone"]  # type: ignore[attr-defined]
        self.assertEqual([repository.remote for repository in self.repositories], clone_remotes)

    def test_fetch_validates_origin_then_uses_local_helper_config(self) -> None:
        from homelab_agent.git_command import run_git

        repository = self.repositories[0]
        self.runner = FakeRunner(
            [
                completed("true\n"),
                completed(str(repository.path) + "\n"),
                completed(repository.remote + "\n"),
            ]
        )
        with patch.object(Path, "exists", return_value=True), patch.object(
            Path, "is_dir", return_value=True
        ):
            run_git(["fetch", "infra"], load=lambda: self.config, runner=self.runner)

        self.assertEqual(
            ("/usr/bin/git", "-C", str(repository.path), "fetch"),
            self.runner.calls[-1].argv,  # type: ignore[attr-defined]
        )

    def test_configure_refuses_paths_outside_declared_destinations(self) -> None:
        from homelab_agent.git_command import UsageError as GitUsageError, run_git

        with self.assertRaisesRegex(GitUsageError, "configured repository destination"):
            run_git(
                ["configure", "/Users/clay/Code/elsewhere"],
                load=lambda: self.config,
                runner=self.runner,
            )

        self.assertEqual([], self.runner.calls)

    def test_cli_dispatches_git_without_connect_or_keychain(self) -> None:
        from homelab_agent import cli

        observed: list[tuple[str, ...]] = []
        rc = cli.main(
            ["git", "clone", "infra"],
            git_runner=lambda argv: observed.append(tuple(argv)) or 9,
        )

        self.assertEqual(9, rc)
        self.assertEqual([("clone", "infra")], observed)

    def test_subdirectory_of_a_matching_worktree_is_refused(self) -> None:
        from homelab_agent.git_command import GitError, clone_repository

        repository = self.repositories[0]
        self.runner = FakeRunner(
            [
                completed("true\n"),
                completed(str(repository.path / "nested") + "\n"),
            ]
        )
        with patch.object(Path, "exists", return_value=True), patch.object(
            Path, "is_dir", return_value=True
        ):
            with self.assertRaisesRegex(GitError, "top-level Git worktree"):
                clone_repository(repository, runner=self.runner)

        self.assertEqual(2, len(self.runner.calls))

    def test_every_git_child_scrubs_inherited_git_controls_and_parent_stays_unchanged(self) -> None:
        from homelab_agent.git_command import clone_repository, run_git

        inherited = {
            "GIT_SSH_COMMAND": "ssh -o ProxyCommand=unapproved",
            "GIT_SSH": "/tmp/unapproved-ssh",
            "GIT_DIR": "/tmp/unapproved-dir",
            "GIT_WORK_TREE": "/tmp/unapproved-worktree",
            "GIT_COMMON_DIR": "/tmp/unapproved-common",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.sshCommand",
            "GIT_CONFIG_VALUE_0": "ssh unapproved",
        }
        executor = EnvironmentCapturingProcess()
        repository = self.repositories[0]

        with patch.dict(os.environ, inherited, clear=False), patch.object(
            Path, "exists", return_value=False
        ):
            clone_repository(repository, runner=Runner(executor))
            self.assertEqual(inherited, {name: os.environ[name] for name in inherited})

        for call in executor.calls:
            for name in inherited:
                self.assertNotIn(name, call["env"])

        self.runner = FakeRunner(
            [
                completed("true\n"),
                completed(str(repository.path) + "\n"),
                completed(repository.remote + "\n"),
            ]
        )
        with patch.dict(os.environ, inherited, clear=False), patch.object(
            Path, "exists", return_value=True
        ), patch.object(Path, "is_dir", return_value=True):
            run_git(["fetch", "infra"], load=lambda: self.config, runner=self.runner)
            self.assertEqual(inherited, {name: os.environ[name] for name in inherited})

        for call in self.runner.calls:
            self.assertTrue(set(inherited).issubset(set(call.unset_env)))  # type: ignore[attr-defined]

    def test_cli_reports_git_usage_errors_without_keychain_or_connect(self) -> None:
        from homelab_agent import cli
        from homelab_agent.git_command import run_git

        for argv in (
            ["git", "clone", "unknown"],
            ["git", "configure", "/Users/clay/Code/elsewhere"],
        ):
            with self.subTest(argv=argv), patch("sys.stderr", new_callable=io.StringIO) as stderr:
                rc = cli.main(
                    argv,
                    keychain_factory=lambda: self.fail("Git must not read Keychain"),
                    connect_factory=lambda *_args, **_kwargs: self.fail("Git must not connect"),
                    git_runner=lambda arguments: run_git(
                        arguments, load=lambda: self.config, runner=self.runner
                    ),
                )

            self.assertEqual(1, rc)
            self.assertIn("homelab-agent:", stderr.getvalue())
            self.assertEqual([], self.runner.calls)


if __name__ == "__main__":
    unittest.main()

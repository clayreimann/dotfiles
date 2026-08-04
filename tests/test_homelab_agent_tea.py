"""Behavioral coverage for the ephemeral Tea credential adapter."""
from __future__ import annotations

import io
import os
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "dot_local" / "lib"))


TEA = "/opt/homebrew/bin/tea"
TOKEN = "api-token-fixture"
LEGACY_MAP_PATH = Path(__file__).with_name("fixtures") / "credential-map-v1.json"


class FakeConnectClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def get_string_field(self, item_id: str, label: str):
        from homelab_agent.process import Secret

        self.calls.append((item_id, label))
        return Secret(TOKEN)


class RecordingExecutor:
    def __init__(self, responses: list[object]) -> None:
        self.calls: list[dict[str, Any]] = []
        self.responses = list(responses)

    def __call__(self, argv: tuple[str, ...], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        config_root = Path(kwargs["env"]["XDG_CONFIG_HOME"])
        self.calls.append(
            {
                "argv": argv,
                "config_root_mode": config_root.stat().st_mode & 0o777,
                **kwargs,
            }
        )
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        assert isinstance(response, subprocess.CompletedProcess)
        return response


def completed(
    returncode: int = 0, *, stdout: str = "", stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess((TEA,), returncode, stdout=stdout, stderr=stderr)


def config(api_user: str = "claude") -> SimpleNamespace:
    return SimpleNamespace(
        version=2,
        forgejo=SimpleNamespace(
            api_url="https://git.4406.madtown.cloud",
            api_user=api_user,
            credential_item_id="yznfzgoql7jl4oa6spa7vm3644",
            api_token_field="api_token",
        )
    )


class TeaSessionTests(unittest.TestCase):
    """The session must leave no usable Forgejo credential beyond its context."""

    def run_tea(self, responses: list[object], arguments: list[str], **kwargs: Any):
        try:
            from homelab_agent.tea_session import run_tea
        except ModuleNotFoundError:
            self.fail("Tea credential adapter is not implemented")
        executor = RecordingExecutor(responses)
        client = FakeConnectClient()
        output = io.StringIO()
        error_output = io.StringIO()
        result = run_tea(
            arguments,
            load=config,
            client=client,
            executor=executor,
            environ=kwargs.pop("environ", {"KEEP": "value"}),
            output=output,
            error_output=error_output,
            **kwargs,
        )
        return result, executor, client, output, error_output

    def test_authenticated_command_preserves_arbitrary_arguments_and_secret_boundaries(self) -> None:
        inherited = {
            "KEEP": "value",
            "GITEA_SERVER_URL": "https://attacker.example",
            "GITEA_SERVER_USER": "attacker",
            "GITEA_SERVER_TOKEN": "attacker-token",
            "GITEA_SERVER_PASSWORD": "attacker-password",
            "XDG_CONFIG_HOME": "/tmp/attacker-config",
        }
        arguments = ["api", "/repos/{owner}/{repo}/issues", "--repo", "owner/repo"]
        result, executor, client, output, error_output = self.run_tea(
            [
                completed(stdout="Version: 0.14.2\n"),
                completed(),
                completed(stdout='{"login":"claude"}\n'),
                completed(stdout="issue list\n", stderr="Tea warning\n"),
            ],
            arguments,
            environ=inherited,
        )

        self.assertEqual(0, result)
        self.assertEqual("", output.getvalue())
        self.assertEqual("", error_output.getvalue())
        self.assertEqual(
            [("yznfzgoql7jl4oa6spa7vm3644", "api_token")], client.calls
        )
        self.assertEqual((TEA, "--version"), executor.calls[0]["argv"])
        self.assertEqual((TEA, "logins", "add", "--name", "homelab-agent"), executor.calls[1]["argv"])
        self.assertEqual((TEA, "api", "/user", "--login", "homelab-agent"), executor.calls[2]["argv"])
        self.assertEqual((TEA, *arguments), executor.calls[3]["argv"])
        self.assertEqual("https://git.4406.madtown.cloud", executor.calls[1]["env"]["GITEA_SERVER_URL"])
        self.assertEqual("claude", executor.calls[1]["env"]["GITEA_SERVER_USER"])
        self.assertEqual(TOKEN, executor.calls[1]["env"]["GITEA_SERVER_TOKEN"])
        for call in (executor.calls[0], executor.calls[2], executor.calls[3]):
            for name in (
                "GITEA_SERVER_URL",
                "GITEA_SERVER_USER",
                "GITEA_SERVER_TOKEN",
                "GITEA_SERVER_PASSWORD",
            ):
                self.assertNotIn(name, call["env"])
        self.assertEqual(inherited, {
            name: value for name, value in inherited.items()
        })

    def test_session_uses_a_private_temporary_config_root_and_removes_it_after_success(self) -> None:
        result, executor, _client, _output, _error_output = self.run_tea(
            [
                completed(stdout="tea version 0.15.1\n"),
                completed(),
                completed(stdout='{"login":"claude"}'),
                completed(),
            ],
            ["issues", "list"],
        )

        self.assertEqual(0, result)
        roots = {Path(call["env"]["XDG_CONFIG_HOME"]) for call in executor.calls}
        self.assertEqual(1, len(roots))
        root = roots.pop()
        self.assertFalse(root.exists())
        self.assertEqual(0o700, executor.calls[1]["config_root_mode"])

    def test_rejects_tea_versions_older_than_0_14_2_before_connect_access(self) -> None:
        try:
            from homelab_agent.process import AgentError
            from homelab_agent.tea_session import run_tea
        except ModuleNotFoundError:
            self.fail("Tea credential adapter is not implemented")
        executor = RecordingExecutor([completed(stdout="Version: 0.14.1\n")])
        client = FakeConnectClient()

        with self.assertRaisesRegex(AgentError, "Tea 0.14.2 or newer is required"):
            run_tea(
                ["issues", "list"],
                load=config,
                client=client,
                executor=executor,
                environ={},
                output=io.StringIO(),
                error_output=io.StringIO(),
            )

        self.assertEqual([], client.calls)
        self.assertEqual(1, len(executor.calls))

    def test_rejects_a_legacy_credential_map_before_keychain_or_connect_access(self) -> None:
        from homelab_agent.config import load_config
        from homelab_agent.process import AgentError
        from homelab_agent.tea_session import run_tea

        legacy_config = load_config(LEGACY_MAP_PATH)

        def unexpected_keychain():
            self.fail("legacy Tea policy must not read Keychain")

        def unexpected_route(**_kwargs: Any):
            self.fail("legacy Tea policy must not open Connect")

        def unexpected_client(*_args: Any, **_kwargs: Any):
            self.fail("legacy Tea policy must not create a Connect client")

        def unexpected_tea(*_args: Any, **_kwargs: Any):
            self.fail("legacy Tea policy must not start Tea")

        with self.assertRaisesRegex(
            AgentError, "Tea workflow policy requires credential map version 2"
        ):
            run_tea(
                ["issues", "list"],
                load=lambda: legacy_config,
                keychain_factory=unexpected_keychain,
                route_factory=unexpected_route,
                connect_factory=unexpected_client,
                executor=unexpected_tea,
            )

    def test_accepts_the_installed_tea_version_format_with_terminal_color_escapes(self) -> None:
        try:
            result, _executor, _client, _output, _error_output = self.run_tea(
                [
                    completed(stdout="Version: \x1b[1m0.15.1\x1b[0m\tgolang: 1.26.5\n"),
                    completed(),
                    completed(stdout='{"login":"claude"}'),
                    completed(),
                ],
                ["issues", "list"],
            )
        except Exception as error:
            self.fail(f"valid Tea version rejected: {error}")

        self.assertEqual(0, result)

    def test_rejects_an_unexpected_authenticated_identity_without_running_the_caller_command(self) -> None:
        try:
            from homelab_agent.process import AgentError
            from homelab_agent.tea_session import run_tea
        except ModuleNotFoundError:
            self.fail("Tea credential adapter is not implemented")
        executor = RecordingExecutor(
            [
                completed(stdout="Version: 0.14.2\n"),
                completed(),
                completed(stdout='{"login":"attacker"}'),
            ]
        )

        with self.assertRaisesRegex(AgentError, "Tea identity verification failed"):
            run_tea(
                ["issues", "list"],
                load=config,
                client=FakeConnectClient(),
                executor=executor,
                environ={},
                output=io.StringIO(),
                error_output=io.StringIO(),
            )

        self.assertEqual(3, len(executor.calls))

    def test_forwards_caller_exit_code_with_inherited_terminal_streams(self) -> None:
        result, executor, _client, output, error_output = self.run_tea(
            [
                completed(stdout="Version: 0.14.2\n"),
                completed(),
                completed(stdout='{"login":"claude"}'),
                completed(23, stdout="buffered stdout must not replay\n", stderr="buffered stderr must not replay\n"),
            ],
            ["issues", "list"],
        )

        self.assertEqual(23, result)
        self.assertNotIn("capture_output", executor.calls[-1])
        self.assertNotIn("stdin", executor.calls[-1])
        self.assertNotIn("stdout", executor.calls[-1])
        self.assertNotIn("stderr", executor.calls[-1])
        self.assertEqual("", output.getvalue())
        self.assertEqual("", error_output.getvalue())

    def test_forged_config_identity_cannot_weaken_the_claude_invariant(self) -> None:
        from homelab_agent.process import AgentError
        from homelab_agent.tea_session import TeaSession

        executor = RecordingExecutor(
            [
                completed(stdout="Version: 0.14.2\n"),
                completed(),
                completed(stdout='{"login":"attacker"}'),
            ]
        )
        session = TeaSession(
            config(api_user="attacker").forgejo,
            FakeConnectClient(),
            executor=executor,
            environ={},
        )

        with self.assertRaisesRegex(AgentError, "Tea identity verification failed"):
            with session:
                pass

        self.assertEqual(3, len(executor.calls))

    def test_session_api_json_uses_tea_and_returns_the_decoded_response(self) -> None:
        from homelab_agent.tea_session import TeaSession

        executor = RecordingExecutor(
            [
                completed(stdout="Version: 0.14.2\n"),
                completed(),
                completed(stdout='{"login":"claude"}'),
                completed(stdout='{"workflow_runs":[]}'),
            ]
        )
        session = TeaSession(config().forgejo, FakeConnectClient(), executor=executor, environ={})
        with session:
            try:
                response = session.api_json(["/repos/homelab/infra/actions/runs"])
            except AttributeError:
                self.fail("TeaSession does not expose api_json")

        self.assertEqual({"workflow_runs": []}, response)
        self.assertEqual(
            (TEA, "api", "/repos/homelab/infra/actions/runs"), executor.calls[-1]["argv"]
        )

    def test_setup_errors_are_redacted_and_cleanup_the_temporary_root_after_failure(self) -> None:
        try:
            from homelab_agent.process import AgentError
            from homelab_agent.tea_session import run_tea
        except ModuleNotFoundError:
            self.fail("Tea credential adapter is not implemented")
        executor = RecordingExecutor(
            [completed(stdout="Version: 0.14.2\n"), completed(1, stderr=TOKEN)]
        )
        roots: list[Path] = []

        def observe_root(argv: tuple[str, ...], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            roots.append(Path(kwargs["env"]["XDG_CONFIG_HOME"]))
            return executor(argv, **kwargs)

        with self.assertRaisesRegex(AgentError, "Tea login setup failed") as caught:
            run_tea(
                ["issues", "list"],
                load=config,
                client=FakeConnectClient(),
                executor=observe_root,
                environ={},
                output=io.StringIO(),
                error_output=io.StringIO(),
            )

        self.assertNotIn(TOKEN, str(caught.exception))
        self.assertTrue(roots)
        self.assertFalse(roots[-1].exists())

    def test_temporary_config_setup_errors_are_redacted(self) -> None:
        from homelab_agent.process import AgentError
        from homelab_agent.tea_session import TeaSession

        session = TeaSession(config().forgejo, FakeConnectClient(), environ={})
        with patch(
            "homelab_agent.tea_session.tempfile.TemporaryDirectory",
            side_effect=OSError(TOKEN),
        ):
            try:
                with session:
                    self.fail("temporary configuration setup must not succeed")
            except OSError as error:
                self.fail(f"temporary configuration error leaked: {error}")
            except AgentError as error:
                caught = error

        self.assertEqual("Tea temporary configuration setup failed", str(caught))
        self.assertNotIn(TOKEN, str(caught))

    def test_keyboard_interrupt_cleans_up_the_temporary_root(self) -> None:
        try:
            from homelab_agent.tea_session import run_tea
        except ModuleNotFoundError:
            self.fail("Tea credential adapter is not implemented")
        executor = RecordingExecutor(
            [
                completed(stdout="Version: 0.14.2\n"),
                completed(),
                completed(stdout='{"login":"claude"}'),
                KeyboardInterrupt(),
            ]
        )
        roots: list[Path] = []

        def observe_root(argv: tuple[str, ...], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            roots.append(Path(kwargs["env"]["XDG_CONFIG_HOME"]))
            return executor(argv, **kwargs)

        with self.assertRaises(KeyboardInterrupt):
            run_tea(
                ["issues", "list"],
                load=config,
                client=FakeConnectClient(),
                executor=observe_root,
                environ={},
                output=io.StringIO(),
                error_output=io.StringIO(),
            )

        self.assertTrue(roots)
        self.assertFalse(roots[-1].exists())


if __name__ == "__main__":
    unittest.main()

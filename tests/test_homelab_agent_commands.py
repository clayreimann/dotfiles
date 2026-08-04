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


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "dot_local" / "lib"))

from homelab_agent.op_command import UsageError, run_op, validate_op_argv
from homelab_agent.process import Secret


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


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[object] = []

    def run(self, spec: object) -> subprocess.CompletedProcess[str]:
        self.calls.append(spec)
        return subprocess.CompletedProcess(("/opt/homebrew/bin/op",), 0)


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

    def run_command(self, argv: list[str], stdin: str = "{}") -> int:
        return run_op(
            argv,
            load=config,
            keychain_factory=lambda: self.keychain,
            route_factory=lambda **_kwargs: self.route,
            runner=self.runner,
            stdin=io.StringIO(stdin),
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
            ["item", "get", "abc", "--vault", "Personal"],
            ["item", "get", "abc", "OP_CONNECT_TOKEN=override"],
            ["item", "get", "abc", "--reveal"],
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
            self.run_command(["item", "get", "item-id", "--vault", "Homelab Secrets"])
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
        self.assertEqual(("OP_CONNECT_HOST", "OP_CONNECT_TOKEN"), call.unset_env)  # type: ignore[attr-defined]
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

    def test_validation_appends_the_only_allowed_vault(self) -> None:
        self.assertEqual(
            ("item", "list", "--vault", "Homelab Secrets"),
            validate_op_argv(["item", "list"]),
        )

    def test_vault_and_read_commands_preserve_their_vault_scoped_cli_syntax(self) -> None:
        self.assertEqual(("vault", "list"), validate_op_argv(["vault", "list"]))
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


if __name__ == "__main__":
    unittest.main()

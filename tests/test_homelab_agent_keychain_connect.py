"""Regression tests for redacted Keychain and 1Password Connect clients."""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any
from urllib.error import URLError


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "dot_local" / "lib"))

from homelab_agent.connect import ConnectClient
from homelab_agent.keychain import Keychain
from homelab_agent.process import AgentError, ProcessSpec, Runner, Secret


TOKEN = "token-value"
PRIVATE_FIELD_VALUE = "-----BEGIN PRIVATE KEY-----\nnot-for-logs\n-----END PRIVATE KEY-----"
ITEM_ID = "yznfzgoql7jl4oa6spa7vm3644"


class FakeProcess:
    """Records a subprocess boundary without executing a child process."""

    def __init__(self, responses: list[subprocess.CompletedProcess[str]]) -> None:
        self.responses = responses
        self.calls: list[dict[str, object]] = []

    def __call__(self, argv: tuple[str, ...], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append({"argv": argv, **kwargs})
        return self.responses.pop(0)


class FakeResponse:
    def __init__(self, payload: object) -> None:
        import json

        self.payload = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self.payload

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None


class RecordedRequest:
    def __init__(self, request: object, timeout: float) -> None:
        self.path = request.selector  # type: ignore[attr-defined]
        self.url = request.full_url  # type: ignore[attr-defined]
        self.headers = dict(request.header_items())  # type: ignore[attr-defined]
        self.timeout = timeout


class FakeHttp:
    """A small HTTP transport fake which only returns explicit responses."""

    def __init__(self, responses: list[object]) -> None:
        self.responses = responses
        self.requests: list[RecordedRequest] = []

    def open(self, request: object, *, timeout: float) -> FakeResponse:
        self.requests.append(RecordedRequest(request, timeout))
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return FakeResponse(response)


def completed(argv: tuple[str, ...], stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr="sensitive stderr")


def vaults() -> list[dict[str, str]]:
    return [{"id": "vault-id", "name": "Homelab Secrets"}]


class RunnerTests(unittest.TestCase):
    def test_runner_sends_secret_only_on_stdin_and_redacts_failure(self) -> None:
        fake_process = FakeProcess([completed(("tool",), returncode=9)])
        runner = Runner(fake_process)

        with self.assertRaisesRegex(AgentError, "credential lookup failed with exit status 9") as caught:
            runner.run(
                ProcessSpec(
                    argv=("tool", "public-argument"),
                    stdin=Secret(TOKEN),
                    env_overlay={"PUBLIC_MODE": "test"},
                    pass_fds=(7,),
                    display_name="credential lookup",
                )
            )

        call = fake_process.calls[0]
        self.assertEqual(("tool", "public-argument"), call["argv"])
        self.assertEqual(TOKEN, call["input"])
        self.assertEqual((7,), call["pass_fds"])
        self.assertEqual("test", call["env"]["PUBLIC_MODE"])  # type: ignore[index]
        self.assertNotIn(TOKEN, str(caught.exception))
        self.assertNotIn("sensitive stderr", str(caught.exception))

    def test_secret_never_formats_its_value(self) -> None:
        secret = Secret(TOKEN)

        self.assertEqual("<redacted>", str(secret))
        self.assertEqual("Secret(<redacted>)", repr(secret))
        self.assertEqual(TOKEN, secret.reveal())

    def test_runner_redacts_unexpected_executor_errors(self) -> None:
        def failing_executor(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
            raise ValueError(TOKEN)

        with self.assertRaises(AgentError) as caught:
            Runner(failing_executor).run(ProcessSpec(argv=("tool",), display_name="credential lookup"))

        self.assertEqual("credential lookup could not be started", str(caught.exception))
        self.assertNotIn(TOKEN, str(caught.exception))


class KeychainTests(unittest.TestCase):
    def test_keychain_reads_local_hostname_then_looks_up_service_and_account(self) -> None:
        fake_process = FakeProcess(
            [
                completed(("/usr/sbin/scutil",), stdout="mac-mini\n"),
                completed(("/usr/bin/security",), stdout=f"{TOKEN}\n"),
            ]
        )
        keychain = Keychain(Runner(fake_process))

        account = keychain.local_account()
        secret = keychain.read("com.example.connect", account)

        self.assertEqual("mac-mini", account)
        self.assertEqual(TOKEN, secret.reveal())
        self.assertEqual(
            (
                "/usr/bin/security",
                "find-generic-password",
                "-w",
                "-s",
                "com.example.connect",
                "-a",
                "mac-mini",
            ),
            fake_process.calls[-1]["argv"],
        )
        self.assertNotIn(TOKEN, str(fake_process.calls[-1]["argv"]))

    def test_keychain_enrollment_prompts_without_placing_secret_in_argv(self) -> None:
        fake_process = FakeProcess([completed(("/usr/bin/security",))])
        keychain = Keychain(Runner(fake_process))

        keychain.enroll("com.example.connect", "mac-mini")

        argv = fake_process.calls[0]["argv"]
        self.assertEqual(
            (
                "/usr/bin/security",
                "add-generic-password",
                "-U",
                "-a",
                "mac-mini",
                "-s",
                "com.example.connect",
                "-T",
                "/usr/bin/security",
                "-w",
            ),
            argv,
        )
        self.assertEqual("-w", argv[-1])


class ConnectClientTests(unittest.TestCase):
    def test_health_uses_bearer_header_and_never_puts_token_in_url(self) -> None:
        fake_http = FakeHttp([{}])
        client = ConnectClient("http://127.0.0.1:18080", Secret(TOKEN), fake_http)

        client.health()

        request = fake_http.requests[0]
        self.assertEqual("/health", request.path)
        self.assertEqual("Bearer token-value", request.headers["Authorization"])
        self.assertNotIn(TOKEN, request.url)
        self.assertEqual(20, request.timeout)

    def test_connect_gets_item_by_uuid_not_title(self) -> None:
        fake_http = FakeHttp([vaults(), {"id": ITEM_ID, "title": "Forgejo agent key", "fields": []}])
        client = ConnectClient("http://127.0.0.1:18080", Secret(TOKEN), fake_http)

        client.get_item(ITEM_ID)

        self.assertEqual(f"/v1/vaults/vault-id/items/{ITEM_ID}", fake_http.requests[-1].path)

    def test_connect_caches_discovered_vault_id(self) -> None:
        fake_http = FakeHttp(
            [
                vaults(),
                {"id": "first", "fields": []},
                {"id": "second", "fields": []},
            ]
        )
        client = ConnectClient("http://127.0.0.1:18080", Secret(TOKEN), fake_http)

        client.get_item("first")
        client.get_item("second")

        self.assertEqual(3, len(fake_http.requests))
        self.assertEqual("/v1/vaults/vault-id/items/second", fake_http.requests[-1].path)

    def test_connect_rejects_missing_exact_vault(self) -> None:
        fake_http = FakeHttp([[{"id": "vault-id", "name": "Other vault"}]])
        client = ConnectClient("http://127.0.0.1:18080", Secret(TOKEN), fake_http)

        with self.assertRaisesRegex(AgentError, "configured vault is unavailable"):
            client.get_item(ITEM_ID)

    def test_connect_rejects_duplicate_exact_vaults(self) -> None:
        fake_http = FakeHttp([[*vaults(), {"id": "other", "name": "Homelab Secrets"}]])
        client = ConnectClient("http://127.0.0.1:18080", Secret(TOKEN), fake_http)

        with self.assertRaisesRegex(AgentError, "configured vault is ambiguous"):
            client.get_item(ITEM_ID)

    def test_string_field_returns_secret_for_one_string_value(self) -> None:
        fake_http = FakeHttp(
            [
                vaults(),
                {"id": ITEM_ID, "fields": [{"label": "private_key", "value": PRIVATE_FIELD_VALUE}]},
            ]
        )
        client = ConnectClient("http://127.0.0.1:18080", Secret(TOKEN), fake_http)

        secret = client.get_string_field(ITEM_ID, "private_key")

        self.assertEqual(PRIVATE_FIELD_VALUE, secret.reveal())
        self.assertEqual("<redacted>", str(secret))

    def test_string_field_fails_closed_for_missing_duplicate_or_non_string_values(self) -> None:
        cases = {
            "missing": [],
            "duplicate": [
                {"label": "private_key", "value": PRIVATE_FIELD_VALUE},
                {"label": "private_key", "value": PRIVATE_FIELD_VALUE},
            ],
            "non-string": [{"label": "private_key", "value": 42}],
        }
        for name, fields in cases.items():
            with self.subTest(name=name):
                fake_http = FakeHttp([vaults(), {"id": ITEM_ID, "fields": fields}])
                client = ConnectClient("http://127.0.0.1:18080", Secret(TOKEN), fake_http)

                with self.assertRaises(AgentError) as caught:
                    client.get_string_field(ITEM_ID, "private_key")

                self.assertNotIn(PRIVATE_FIELD_VALUE, str(caught.exception))

    def test_error_redacts_token(self) -> None:
        fake_http = FakeHttp([URLError("token-value")])
        client = ConnectClient("http://127.0.0.1:18080", Secret(TOKEN), fake_http)

        with self.assertRaises(AgentError) as caught:
            client.health()

        self.assertNotIn(TOKEN, str(caught.exception))

    def test_connect_redacts_unexpected_transport_errors(self) -> None:
        for secret_value in (TOKEN, PRIVATE_FIELD_VALUE):
            with self.subTest(secret_value=secret_value):
                fake_http = FakeHttp([ValueError(secret_value)])
                client = ConnectClient("http://127.0.0.1:18080", Secret(TOKEN), fake_http)

                with self.assertRaises(AgentError) as caught:
                    client.health()

                self.assertNotIn(secret_value, str(caught.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""Regression tests for ephemeral, pinned Forgejo SSH sessions."""
from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "dot_local" / "lib"))

from homelab_agent.models import SshIdentity
from homelab_agent.process import AgentError, Runner, Secret
from homelab_agent.ssh_session import EphemeralAgent, run_pinned_ssh


PRIVATE_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret-line-one\nsecret-line-two\n-----END OPENSSH PRIVATE KEY-----\n"
PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestPublicKey forgejo-agent\n"
FINGERPRINT = "SHA256:verified-agent-key"


def identity() -> SshIdentity:
    return SshIdentity(
        host="git.4406.madtown.cloud",
        port=2222,
        user="git",
        credential_item_id="item-id",
        private_field="private_key",
        expected_fingerprint=FINGERPRINT,
        known_host="[git.4406.madtown.cloud]:2222 ssh-ed25519 AAAAC3NzaPinnedHostKey",
    )


def completed(argv: tuple[str, ...], stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr="secret stderr")


class FakeProcess:
    """A deterministic subprocess replacement that records complete boundaries."""

    def __init__(self, responses: list[object]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, object]] = []

    def __call__(self, argv: tuple[str, ...], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append({"argv": argv, **kwargs})
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        assert isinstance(response, subprocess.CompletedProcess)
        return response


class FakeConnect:
    def __init__(self, value: str = PRIVATE_KEY) -> None:
        self.value = value
        self.calls: list[tuple[str, str]] = []

    def get_string_field(self, item_id: str, field: str) -> Secret:
        self.calls.append((item_id, field))
        return Secret(self.value)


def agent_responses(*, fingerprint: str = FINGERPRINT) -> list[subprocess.CompletedProcess[str]]:
    return [
        completed(
            ("/usr/bin/ssh-agent", "-s"),
            "SSH_AUTH_SOCK=/private/tmp/agent.sock; export SSH_AUTH_SOCK;\n"
            "SSH_AGENT_PID=4242; export SSH_AGENT_PID;\n",
        ),
        completed(("/usr/bin/ssh-add", "-")),
        completed(("/usr/bin/ssh-add", "-L"), PUBLIC_KEY),
        completed(("/usr/bin/ssh-keygen", "-lf", "-", "-E", "sha256"), f"256 {fingerprint} forgejo-agent (ED25519)\n"),
        completed(("/usr/bin/ssh-agent", "-k")),
    ]


class EphemeralAgentTests(unittest.TestCase):
    def test_identity_does_not_clean_up_when_startup_output_is_invalid(self) -> None:
        fake_process = FakeProcess(
            [
                completed(("/usr/bin/ssh-agent", "-s"), "not an ssh-agent environment\n"),
            ]
        )

        with patch.dict(
            os.environ,
            {"SSH_AUTH_SOCK": "/tmp/caller-agent.sock", "SSH_AGENT_PID": "999"},
        ):
            with self.assertRaisesRegex(AgentError, "temporary SSH agent returned invalid environment"):
                with EphemeralAgent(FakeConnect(), Runner(fake_process)).identity(
                    "item-id", "private_key", FINGERPRINT
                ):
                    self.fail("invalid agent output must not yield a usable agent")

        self.assertEqual(1, len(fake_process.calls))
        self.assertEqual(("/usr/bin/ssh-agent", "-s"), fake_process.calls[0]["argv"])
        self.assertNotIn("SSH_AUTH_SOCK", fake_process.calls[0]["env"])
        self.assertNotIn("SSH_AGENT_PID", fake_process.calls[0]["env"])

    def test_identity_scrubs_caller_agent_environment_from_every_agent_child(self) -> None:
        fake_process = FakeProcess(agent_responses())

        with patch.dict(
            os.environ,
            {"SSH_AUTH_SOCK": "/tmp/caller-agent.sock", "SSH_AGENT_PID": "999"},
        ):
            with EphemeralAgent(FakeConnect(), Runner(fake_process)).identity(
                "item-id", "private_key", FINGERPRINT
            ):
                pass

        self.assertNotIn("SSH_AUTH_SOCK", fake_process.calls[0]["env"])
        self.assertNotIn("SSH_AGENT_PID", fake_process.calls[0]["env"])
        for call in fake_process.calls[1:]:
            self.assertEqual("/private/tmp/agent.sock", call["env"]["SSH_AUTH_SOCK"])
            self.assertEqual("4242", call["env"]["SSH_AGENT_PID"])

    def test_identity_loads_raw_multiline_key_and_verifies_the_only_public_key(self) -> None:
        fake_process = FakeProcess(agent_responses())
        fake_connect = FakeConnect()
        agent = EphemeralAgent(fake_connect, Runner(fake_process))

        with agent.identity("item-id", "private_key", FINGERPRINT) as socket:
            self.assertEqual("/private/tmp/agent.sock", socket.socket_path)
            self.assertEqual(4242, socket.pid)

        self.assertEqual([("item-id", "private_key")], fake_connect.calls)
        self.assertEqual(("/usr/bin/ssh-add", "-"), fake_process.calls[1]["argv"])
        self.assertEqual(PRIVATE_KEY, fake_process.calls[1]["input"])
        self.assertNotIn(PRIVATE_KEY, str(fake_process.calls[1]["argv"]))
        self.assertEqual(PUBLIC_KEY.rstrip("\n"), fake_process.calls[3]["input"])
        self.assertEqual(("/usr/bin/ssh-agent", "-k"), fake_process.calls[-1]["argv"])

    def test_identity_rejects_a_fingerprint_mismatch_without_exposing_the_private_key(self) -> None:
        fake_process = FakeProcess(agent_responses(fingerprint="SHA256:wrong-key"))
        agent = EphemeralAgent(FakeConnect(), Runner(fake_process))

        with self.assertRaisesRegex(AgentError, "loaded SSH key fingerprint does not match") as caught:
            with agent.identity("item-id", "private_key", FINGERPRINT):
                self.fail("mismatched keys must not yield a usable agent")

        self.assertNotIn(PRIVATE_KEY, str(caught.exception))
        self.assertEqual(("/usr/bin/ssh-agent", "-k"), fake_process.calls[-1]["argv"])

    def test_identity_rejects_multiple_loaded_public_keys(self) -> None:
        responses = agent_responses()
        responses[2] = completed(("/usr/bin/ssh-add", "-L"), PUBLIC_KEY + "ssh-rsa AAAA other\n")
        fake_process = FakeProcess(responses)

        with self.assertRaisesRegex(AgentError, "exactly one public key"):
            with EphemeralAgent(FakeConnect(), Runner(fake_process)).identity(
                "item-id", "private_key", FINGERPRINT
            ):
                self.fail("multiple keys must not yield a usable agent")

        self.assertEqual(("/usr/bin/ssh-agent", "-k"), fake_process.calls[-1]["argv"])


class PinnedForgejoSshTests(unittest.TestCase):
    def test_wrong_destination_user_stops_before_starting_an_agent_or_ssh(self) -> None:
        fake_process = FakeProcess([])
        ssh_calls: list[tuple[str, ...]] = []

        with self.assertRaisesRegex(AgentError, "SSH destination does not match configured identity"):
            run_pinned_ssh(
                identity(),
                ["otheruser@git.4406.madtown.cloud", "git-upload-pack 'homelab/infra.git'"],
                agent=EphemeralAgent(FakeConnect(), Runner(fake_process)),
                ssh_executor=lambda argv: ssh_calls.append(argv),  # type: ignore[return-value]
            )

        self.assertEqual([], fake_process.calls)
        self.assertEqual([], ssh_calls)

    def test_wrong_destination_host_stops_before_starting_an_agent_or_ssh(self) -> None:
        fake_process = FakeProcess([])
        ssh_calls: list[tuple[str, ...]] = []

        with self.assertRaisesRegex(AgentError, "SSH destination does not match configured identity"):
            run_pinned_ssh(
                identity(),
                ["git@other.example", "git-upload-pack 'homelab/infra.git'"],
                agent=EphemeralAgent(FakeConnect(), Runner(fake_process)),
                ssh_executor=lambda argv: ssh_calls.append(argv),  # type: ignore[return-value]
            )

        self.assertEqual([], fake_process.calls)
        self.assertEqual([], ssh_calls)

    def test_loaded_agent_key_is_actually_offered(self) -> None:
        fake_process = FakeProcess(agent_responses())
        observed: dict[str, object] = {}
        git_args = [
            "-o",
            "SendEnv=GIT_PROTOCOL",
            "-vv",
            "git@git.4406.madtown.cloud",
            "git-upload-pack 'homelab/infra.git'",
        ]

        def ssh_executor(argv: tuple[str, ...], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            observed["argv"] = argv
            known_hosts = next(arg.removeprefix("UserKnownHostsFile=") for arg in argv if arg.startswith("UserKnownHostsFile="))
            observed["known_hosts"] = Path(known_hosts).read_text(encoding="utf-8")
            observed["known_hosts_mode"] = stat.S_IMODE(Path(known_hosts).stat().st_mode)
            return completed(argv)

        rc = run_pinned_ssh(
            identity(),
            git_args,
            agent=EphemeralAgent(FakeConnect(), Runner(fake_process)),
            ssh_executor=ssh_executor,
        )

        argv = observed["argv"]
        assert isinstance(argv, tuple)
        self.assertEqual(0, rc)
        self.assertIn("IdentitiesOnly=no", argv)
        self.assertIn("IdentityFile=none", argv)
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertTrue(any(arg.startswith("IdentityAgent=") for arg in argv))
        self.assertIn("-p", argv)
        self.assertEqual("2222", argv[argv.index("-p") + 1])
        self.assertEqual("/dev/null", argv[argv.index("-F") + 1])
        self.assertEqual(
            git_args,
            list(argv[-len(git_args):]),
        )
        self.assertEqual(identity().known_host + "\n", observed["known_hosts"])
        self.assertEqual(0o600, observed["known_hosts_mode"])
        self.assertEqual(("/usr/bin/ssh-agent", "-k"), fake_process.calls[-1]["argv"])

    def test_child_nonzero_status_returns_to_git_and_still_cleans_up_agent(self) -> None:
        fake_process = FakeProcess(agent_responses())

        def ssh_executor(argv: tuple[str, ...], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            return completed(argv, returncode=128)

        rc = run_pinned_ssh(
            identity(),
            ["git@git.4406.madtown.cloud", "git-receive-pack 'homelab/infra.git'"],
            agent=EphemeralAgent(FakeConnect(), Runner(fake_process)),
            ssh_executor=ssh_executor,
        )

        self.assertEqual(128, rc)
        self.assertEqual(("/usr/bin/ssh-agent", "-k"), fake_process.calls[-1]["argv"])

    def test_keyboard_interrupt_cleans_up_agent_and_known_hosts_file(self) -> None:
        fake_process = FakeProcess(agent_responses())
        observed: dict[str, Path] = {}

        def ssh_executor(argv: tuple[str, ...], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            observed["known_hosts"] = Path(
                next(arg.removeprefix("UserKnownHostsFile=") for arg in argv if arg.startswith("UserKnownHostsFile="))
            )
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            run_pinned_ssh(
                identity(),
                ["git@git.4406.madtown.cloud", "git-upload-pack 'homelab/infra.git'"],
                agent=EphemeralAgent(FakeConnect(), Runner(fake_process)),
                ssh_executor=ssh_executor,
            )

        self.assertFalse(observed["known_hosts"].exists())
        self.assertEqual(("/usr/bin/ssh-agent", "-k"), fake_process.calls[-1]["argv"])

    def test_fingerprint_mismatch_stops_before_ssh_and_does_not_leak_secret(self) -> None:
        fake_process = FakeProcess(agent_responses(fingerprint="SHA256:wrong-key"))
        ssh_calls: list[tuple[str, ...]] = []

        def ssh_executor(argv: tuple[str, ...], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            ssh_calls.append(argv)
            return completed(argv)

        with self.assertRaises(AgentError) as caught:
            run_pinned_ssh(
                identity(),
                ["git@git.4406.madtown.cloud", "git-upload-pack 'homelab/infra.git'"],
                agent=EphemeralAgent(FakeConnect(), Runner(fake_process)),
                ssh_executor=ssh_executor,
            )

        self.assertEqual([], ssh_calls)
        self.assertNotIn(PRIVATE_KEY, str(caught.exception))
        for call in fake_process.calls:
            self.assertNotIn(PRIVATE_KEY, str(call["argv"]))


class CliTests(unittest.TestCase):
    def test_cli_uses_approved_direct_or_tunnel_url_and_preserves_git_args(self) -> None:
        from homelab_agent import cli

        config = SimpleNamespace(
            direct_connect_url="http://direct.example:8080",
            tunnel_connect_url="http://127.0.0.1:18080",
            connect_keychain_service="connect-service",
            vault_name="Homelab Secrets",
            forgejo=identity(),
        )
        keychain = SimpleNamespace(
            local_account=lambda: "mac-mini",
            read=lambda service, account: Secret("connect-token"),
        )
        observed: dict[str, object] = {}

        class FakeConnectClient:
            def __init__(self, url: str, token: Secret, *, vault_name: str) -> None:
                observed["url"] = url
                observed["token"] = token
                observed["vault_name"] = vault_name

        def transport(ssh_identity: SshIdentity, remote_args: list[str], **kwargs: object) -> int:
            observed["identity"] = ssh_identity
            observed["remote_args"] = remote_args
            observed["agent"] = kwargs["agent"]
            return 17

        with patch.object(cli, "EphemeralAgent", lambda client: ("agent", client)):
            rc = cli.main(
                ["forgejo-ssh", "--", "git@git.4406.madtown.cloud", "git-upload-pack 'homelab/infra.git'"],
                load= lambda: config,
                keychain_factory=lambda: keychain,
                connect_factory=FakeConnectClient,
                transport=transport,
            )

        self.assertEqual(17, rc)
        self.assertEqual("http://direct.example:8080", observed["url"])
        self.assertEqual(identity(), observed["identity"])
        self.assertEqual(
            ["git@git.4406.madtown.cloud", "git-upload-pack 'homelab/infra.git'"],
            observed["remote_args"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

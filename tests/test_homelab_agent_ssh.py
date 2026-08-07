"""Regression tests for ephemeral, pinned Forgejo SSH sessions."""
from __future__ import annotations

import os
import io
import signal
import stat
import subprocess
import sys
import unittest
from contextlib import contextmanager
from collections import deque
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "dot_local" / "lib"))

from homelab_agent.config import ConfigError, load_config
from homelab_agent.models import Bastion, ManagedTarget, SshIdentity
from homelab_agent.process import AgentError, Runner, Secret
from homelab_agent import ssh_session
from homelab_agent.ssh_session import EphemeralAgent, run_pinned_ssh


PRIVATE_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret-line-one\nsecret-line-two\n-----END OPENSSH PRIVATE KEY-----\n"
PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestPublicKey forgejo-agent\n"
FINGERPRINT = "SHA256:verified-agent-key"
LEGACY_MAP_PATH = Path(__file__).with_name("fixtures") / "credential-map-v1.json"


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


def target(*, route: str = "direct") -> ManagedTarget:
    return ManagedTarget(
        alias="monitor01",
        route=route,  # type: ignore[arg-type]
        host="monitor01",
        port=22,
        user="ubuntu",
        credential_item_id="target-item-id",
        private_field="private_key",
        expected_fingerprint=FINGERPRINT,
        known_host="monitor01 ssh-ed25519 AAAAC3NzaTargetHostKey",
    )


def bastion() -> Bastion:
    return Bastion(
        host="bastion.example",
        port=22,
        user="clay",
        encrypted_key_path=Path("/Users/clay/.ssh/homelab_bastion_bootstrap"),
        known_host="bastion.example ssh-ed25519 AAAAC3NzaBastionHostKey",
    )


def route_config() -> SimpleNamespace:
    return SimpleNamespace(
        direct_connect_url="http://192.168.42.253:8080",
        tunnel_connect_url="http://127.0.0.1:18080",
        connect_keychain_service="connect-service",
        bastion_keychain_service="bastion-service",
        vault_name="Homelab Secrets",
        bastion=bastion(),
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


class FakeKeychain:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def local_account(self) -> str:
        self.calls.append(("local_account",))
        return "test-mac"

    def read(self, service: str, account: str) -> Secret:
        self.calls.append(("read", service, account))
        values = {
            "connect-service": "connect-token",
            "bastion-service": "bastion-passphrase",
        }
        return Secret(values[service])


class FakeTunnelProcess:
    def __init__(self, *, returncode: int | None = None, pid: int = 6060) -> None:
        self.returncode = returncode
        self.pid = pid
        self.terminated = False
        self.killed = False
        self.waited = False

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = 0

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        self.waited = True
        return 0 if self.returncode is None else self.returncode


class FakePopen:
    def __init__(self, responses: list[object]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, object]] = []

    def __call__(self, argv: tuple[str, ...], **kwargs: Any) -> FakeTunnelProcess:
        self.calls.append({"argv": argv, **kwargs})
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        assert isinstance(response, FakeTunnelProcess)
        return response


class FakeHealthFactory:
    def __init__(self, outcomes: dict[str, list[object]]) -> None:
        self.outcomes = {url: deque(values) for url, values in outcomes.items()}
        self.calls: list[tuple[str, Secret, str]] = []
        self.health_calls: list[str] = []

    def __call__(self, url: str, token: Secret, *, vault_name: str) -> object:
        self.calls.append((url, token, vault_name))
        outcomes = self.outcomes[url]

        class Client:
            def health(self) -> None:
                self_factory.health_calls.append(url)
                outcome = outcomes.popleft()
                if isinstance(outcome, BaseException):
                    raise outcome

        self_factory = self
        return Client()


class FakeAgentSession:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []
        self.exited = False

    @contextmanager
    def identity(self, item_id: str, field: str, fingerprint: str):
        self.calls.append((item_id, field, fingerprint))
        try:
            yield SimpleNamespace(socket_path="/private/tmp/target-agent.sock", pid=8181)
        finally:
            self.exited = True


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


def assert_publickey_only(
    case: unittest.TestCase, argv: tuple[str, ...], *, batch_mode: str
) -> None:
    for option in (
        "PreferredAuthentications=publickey",
        "PasswordAuthentication=no",
        "KbdInteractiveAuthentication=no",
        "ChallengeResponseAuthentication=no",
        f"BatchMode={batch_mode}",
    ):
        case.assertIn(option, argv)


def ignore_group_signal(_process_group: int, _sent: signal.Signals) -> None:
    pass


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

    def test_identity_appends_only_a_missing_terminal_newline_before_ssh_add(self) -> None:
        missing_newline = PRIVATE_KEY.rstrip("\n")
        fake_process = FakeProcess(agent_responses())
        agent = EphemeralAgent(FakeConnect(missing_newline), Runner(fake_process))

        with agent.identity("item-id", "private_key", FINGERPRINT):
            pass

        self.assertEqual(PRIVATE_KEY, fake_process.calls[1]["input"])
        self.assertNotIn(missing_newline, str(fake_process.calls[1]["argv"]))

    def test_missing_terminal_newline_ssh_add_failure_stays_redacted_and_cleans_up(self) -> None:
        missing_newline = PRIVATE_KEY.rstrip("\n")
        responses = agent_responses()
        responses[1] = completed(("/usr/bin/ssh-add", "-"), returncode=1)
        responses = [responses[0], responses[1], responses[-1]]
        fake_process = FakeProcess(responses)

        with self.assertRaises(AgentError) as caught:
            with EphemeralAgent(FakeConnect(missing_newline), Runner(fake_process)).identity(
                "item-id", "private_key", FINGERPRINT
            ):
                self.fail("failed ssh-add must not yield an identity")

        self.assertNotIn(missing_newline, str(caught.exception))
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
    def test_separated_hostname_option_stops_before_starting_an_agent_or_ssh(self) -> None:
        fake_process = FakeProcess([])
        ssh_calls: list[tuple[str, ...]] = []

        with self.assertRaisesRegex(AgentError, "SSH destination does not match configured identity"):
            run_pinned_ssh(
                identity(),
                ["-o", "hOsTnAmE other.example", "git@git.4406.madtown.cloud", "git-upload-pack 'homelab/infra.git'"],
                agent=EphemeralAgent(FakeConnect(), Runner(fake_process)),
                ssh_executor=lambda argv: ssh_calls.append(argv),  # type: ignore[return-value]
            )

        self.assertEqual([], fake_process.calls)
        self.assertEqual([], ssh_calls)

    def test_separated_user_option_stops_before_starting_an_agent_or_ssh(self) -> None:
        fake_process = FakeProcess([])
        ssh_calls: list[tuple[str, ...]] = []

        with self.assertRaisesRegex(AgentError, "SSH destination does not match configured identity"):
            run_pinned_ssh(
                identity(),
                ["-o", "User otheruser", "git@git.4406.madtown.cloud", "git-upload-pack 'homelab/infra.git'"],
                agent=EphemeralAgent(FakeConnect(), Runner(fake_process)),
                ssh_executor=lambda argv: ssh_calls.append(argv),  # type: ignore[return-value]
            )

        self.assertEqual([], fake_process.calls)
        self.assertEqual([], ssh_calls)

    def test_pinned_security_option_overrides_stop_before_starting_an_agent_or_ssh(self) -> None:
        overrides = {
            "attached identity agent": ["-oiDeNtItYaGeNt=/tmp/other-agent.sock"],
            "separate identity file": ["-o", "IdentityFile=/tmp/other-key"],
            "space identities only": ["-o", "IdentitiesOnly yes"],
            "attached strict host checking": ["-oStrictHostKeyChecking=no"],
            "space user known hosts": ["-o", "UserKnownHostsFile /tmp/other-known-hosts"],
        }
        for name, options in overrides.items():
            with self.subTest(name=name):
                fake_process = FakeProcess([])
                ssh_calls: list[tuple[str, ...]] = []

                with self.assertRaisesRegex(AgentError, "SSH invocation overrides pinned security settings"):
                    run_pinned_ssh(
                        identity(),
                        [*options, "git@git.4406.madtown.cloud", "git-upload-pack 'homelab/infra.git'"],
                        agent=EphemeralAgent(FakeConnect(), Runner(fake_process)),
                        ssh_executor=lambda argv: ssh_calls.append(argv),  # type: ignore[return-value]
                    )

                self.assertEqual([], fake_process.calls)
                self.assertEqual([], ssh_calls)

    def test_host_trust_option_overrides_stop_before_starting_an_agent_or_ssh(self) -> None:
        overrides = {
            "attached known-hosts command equals": ["-oKnownHostsCommand=/tmp/other-known-hosts"],
            "separate known-hosts command space": ["-o", "KnownHostsCommand /tmp/other-known-hosts"],
            "separate DNS verification equals": ["-o", "VerifyHostKeyDNS=yes"],
            "attached DNS verification space": ["-oVerifyHostKeyDNS yes"],
        }
        for name, options in overrides.items():
            with self.subTest(name=name):
                fake_process = FakeProcess([])
                ssh_calls: list[tuple[str, ...]] = []

                with self.assertRaisesRegex(AgentError, "SSH invocation overrides pinned security settings"):
                    run_pinned_ssh(
                        identity(),
                        [*options, "git@git.4406.madtown.cloud", "git-upload-pack 'homelab/infra.git'"],
                        agent=EphemeralAgent(FakeConnect(), Runner(fake_process)),
                        ssh_executor=lambda argv: ssh_calls.append(argv),  # type: ignore[return-value]
                    )

                self.assertEqual([], fake_process.calls)
                self.assertEqual([], ssh_calls)

    def test_login_and_port_overrides_stop_before_starting_an_agent_or_ssh(self) -> None:
        overrides = {
            "separate login": ["-l", "otheruser"],
            "attached login": ["-lotheruser"],
            "separate port": ["-p", "2200"],
            "attached port": ["-p2200"],
        }
        for name, options in overrides.items():
            with self.subTest(name=name):
                fake_process = FakeProcess([])

                with self.assertRaisesRegex(AgentError, "SSH destination does not match configured identity"):
                    run_pinned_ssh(
                        identity(),
                        [*options, "git@git.4406.madtown.cloud", "git-upload-pack 'homelab/infra.git'"],
                        agent=EphemeralAgent(FakeConnect(), Runner(fake_process)),
                    )

                self.assertEqual([], fake_process.calls)

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

    def test_identity_proxy_and_forwarding_options_stop_before_starting_an_agent_or_ssh(self) -> None:
        blocked = {
            "separate identity file": ["-i", "/tmp/other-key"],
            "attached identity file": ["-i/tmp/other-key"],
            "separate PKCS11 provider": ["-I", "/tmp/provider"],
            "attached PKCS11 provider": ["-I/tmp/provider"],
            "separate proxy jump": ["-J", "jump.example"],
            "attached proxy jump": ["-Jjump.example"],
            "separate local forward": ["-L", "10022:git.example:22"],
            "attached local forward": ["-L10022:git.example:22"],
            "separate remote forward": ["-R", "10022:git.example:22"],
            "attached remote forward": ["-R10022:git.example:22"],
            "separate dynamic forward": ["-D", "10022"],
            "attached dynamic forward": ["-D10022"],
            "separate stdio forward": ["-W", "git.example:22"],
            "attached stdio forward": ["-Wgit.example:22"],
        }
        for name, options in blocked.items():
            with self.subTest(name=name):
                fake_process = FakeProcess([])
                ssh_calls: list[tuple[str, ...]] = []

                with self.assertRaisesRegex(AgentError, "forbidden credential, proxy, or forwarding option"):
                    run_pinned_ssh(
                        identity(),
                        [*options, "git@git.4406.madtown.cloud", "git-upload-pack 'homelab/infra.git'"],
                        agent=EphemeralAgent(FakeConnect(), Runner(fake_process)),
                        ssh_executor=lambda argv: ssh_calls.append(argv),  # type: ignore[return-value]
                    )

                self.assertEqual([], fake_process.calls)
                self.assertEqual([], ssh_calls)

    def test_identity_proxy_and_forwarding_o_options_stop_before_starting_an_agent_or_ssh(self) -> None:
        blocked = {
            "attached identity provider": ["-oPKCS11Provider=/tmp/provider"],
            "separate security key provider": ["-o", "SecurityKeyProvider /tmp/provider"],
            "attached proxy command": ["-oProxyCommand=/usr/bin/false"],
            "separate proxy jump": ["-o", "ProxyJump jump.example"],
            "attached proxy file descriptor": ["-oProxyUseFdpass=yes"],
            "separate local forward": ["-o", "LocalForward 10022 git.example:22"],
            "attached remote forward": ["-oRemoteForward=10022:git.example:22"],
            "separate dynamic forward": ["-o", "DynamicForward 10022"],
            "attached stdio forward": ["-oStdioForward=git.example:22"],
            "separate agent forward": ["-o", "ForwardAgent yes"],
        }
        for name, options in blocked.items():
            with self.subTest(name=name):
                fake_process = FakeProcess([])
                ssh_calls: list[tuple[str, ...]] = []

                with self.assertRaisesRegex(AgentError, "forbidden credential, proxy, or forwarding option"):
                    run_pinned_ssh(
                        identity(),
                        [*options, "git@git.4406.madtown.cloud", "git-upload-pack 'homelab/infra.git'"],
                        agent=EphemeralAgent(FakeConnect(), Runner(fake_process)),
                        ssh_executor=lambda argv: ssh_calls.append(argv),  # type: ignore[return-value]
                    )

                self.assertEqual([], fake_process.calls)
                self.assertEqual([], ssh_calls)

    def test_final_ssh_receives_only_git_protocol_from_the_ambient_environment(self) -> None:
        fake_process = FakeProcess(agent_responses())
        observed: dict[str, object] = {}

        def ssh_executor(argv: tuple[str, ...], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            observed["environment"] = kwargs["env"]
            return completed(argv)

        with patch.dict(
            os.environ,
            {
                "GIT_PROTOCOL": "version=2",
                "HOME": "/Users/clay",
                "SSH_AUTH_SOCK": "/tmp/personal-agent.sock",
                "SSH_ASKPASS": "/tmp/personal-askpass",
            },
            clear=True,
        ):
            rc = run_pinned_ssh(
                identity(),
                ["git@git.4406.madtown.cloud", "git-upload-pack 'homelab/infra.git'"],
                agent=EphemeralAgent(FakeConnect(), Runner(fake_process)),
                ssh_executor=ssh_executor,
            )

        self.assertEqual(0, rc)
        self.assertEqual({"GIT_PROTOCOL": "version=2"}, observed["environment"])

    def test_loaded_agent_key_is_actually_offered(self) -> None:
        fake_process = FakeProcess(agent_responses())
        observed: dict[str, object] = {}
        git_args = [
            "-o",
            "SendEnv GIT_PROTOCOL",
            "-o",
            "SendEnv=GIT_PROTOCOL",
            "-oSendEnv=GIT_PROTOCOL",
            "-l",
            "git",
            "-p2222",
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
            [
                "-o", "SendEnv=GIT_PROTOCOL",
                "-o", "SendEnv=GIT_PROTOCOL",
                "-o", "SendEnv=GIT_PROTOCOL",
                "-vv",
                "git@git.4406.madtown.cloud",
                "git-upload-pack 'homelab/infra.git'",
            ],
            list(argv[-9:]),
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


class ConnectRouteTests(unittest.TestCase):
    def test_direct_health_success_never_reads_bastion_passphrase_or_starts_ssh(self) -> None:
        keychain = FakeKeychain()
        connect = FakeHealthFactory(
            {"http://192.168.42.253:8080": [None]}
        )
        popen = FakePopen([])
        route = ssh_session.ConnectRoute(
            keychain=keychain,
            connect_factory=connect,
            popen_executor=popen,
            group_signaler=ignore_group_signal,
            control_ready=lambda _bastion, _path: True,
            sleeper=lambda _seconds: None,
        )

        with route.open(route_config()) as url:
            self.assertEqual("http://192.168.42.253:8080", url)

        self.assertEqual(
            [
                ("local_account",),
                ("read", "connect-service", "test-mac"),
            ],
            keychain.calls,
        )
        self.assertEqual([], popen.calls)

    def test_direct_refusal_opens_pinned_tunnel_with_private_askpass_then_cleans_up(self) -> None:
        keychain = FakeKeychain()
        connect = FakeHealthFactory(
            {
                "http://192.168.42.253:8080": [AgentError("direct refused")],
                "http://127.0.0.1:18080": [None],
            }
        )
        process = FakeTunnelProcess()
        popen = FakePopen([process])
        route = ssh_session.ConnectRoute(
            keychain=keychain,
            connect_factory=connect,
            popen_executor=popen,
            group_signaler=ignore_group_signal,
            control_ready=lambda _bastion, _path: True,
            sleeper=lambda _seconds: None,
        )

        with route.open(route_config()) as url:
            self.assertEqual("http://127.0.0.1:18080", url)
            call = popen.calls[0]
            argv = call["argv"]
            env = call["env"]
            assert isinstance(argv, tuple)
            assert isinstance(env, dict)
            self.assertEqual("/usr/bin/ssh", argv[0])
            self.assertIn("-M", argv)
            self.assertIn("-S", argv)
            control_path = Path(argv[argv.index("-S") + 1])
            self.assertEqual(Path(env["SSH_ASKPASS"]).parent, control_path.parent)
            self.assertEqual(
                Path(ssh_session._short_temp_root()), control_path.parent.parent
            )
            self.assertLessEqual(len(str(control_path)) + 17, 103)
            self.assertIn("ExitOnForwardFailure=yes", argv)
            self.assertIn("IdentitiesOnly=yes", argv)
            self.assertIn("IdentityAgent=none", argv)
            assert_publickey_only(self, argv, batch_mode="no")
            identity_reset_index = argv.index("IdentityFile=none")
            approved_identity_index = argv.index("-i")
            self.assertLess(identity_reset_index, approved_identity_index)
            self.assertEqual(
                "/Users/clay/.ssh/homelab_bastion_bootstrap",
                argv[approved_identity_index + 1],
            )
            self.assertIn("127.0.0.1:18080:192.168.42.253:8080", argv)
            self.assertIn(str(bastion().encrypted_key_path), argv)
            self.assertIn("StrictHostKeyChecking=yes", argv)
            self.assertEqual("force", env["SSH_ASKPASS_REQUIRE"])
            self.assertEqual("bastion-service", env["HOMELAB_AGENT_ASKPASS_SERVICE"])
            self.assertEqual("test-mac", env["HOMELAB_AGENT_ASKPASS_ACCOUNT"])
            askpass_path = Path(env["SSH_ASKPASS"])
            self.assertTrue(askpass_path.exists())
            self.assertIn("homelab_agent.cli askpass", askpass_path.read_text(encoding="utf-8"))
            self.assertNotIn("bastion-passphrase", str(call))
            self.assertIs(subprocess.DEVNULL, call["stdin"])

        self.assertEqual(
            [
                ("local_account",),
                ("read", "connect-service", "test-mac"),
            ],
            keychain.calls,
        )
        self.assertTrue(process.waited)

    def test_unapproved_bastion_key_path_stops_before_askpass_or_ssh(self) -> None:
        config = route_config()
        config.bastion = Bastion(
            host=bastion().host,
            port=bastion().port,
            user=bastion().user,
            encrypted_key_path=Path("/Users/clay/.ssh/other-key"),
            known_host=bastion().known_host,
        )
        keychain = FakeKeychain()
        connect = FakeHealthFactory(
            {"http://192.168.42.253:8080": [AgentError("direct refused")]}
        )
        popen = FakePopen([])
        route = ssh_session.ConnectRoute(
            keychain=keychain,
            connect_factory=connect,
            popen_executor=popen,
            group_signaler=ignore_group_signal,
            control_ready=lambda _bastion, _path: True,
            sleeper=lambda _seconds: None,
        )

        with self.assertRaisesRegex(AgentError, "bastion key path is not approved"):
            with route.open(config):
                self.fail("unapproved bootstrap path must not start a tunnel")

        self.assertEqual([], popen.calls)
        self.assertEqual([], keychain.calls)

    def test_tunnel_startup_failure_is_redacted_and_removes_temporary_files(self) -> None:
        keychain = FakeKeychain()
        connect = FakeHealthFactory(
            {"http://192.168.42.253:8080": [AgentError("direct refused")]}
        )
        popen = FakePopen([OSError("secret child failure")])
        route = ssh_session.ConnectRoute(
            keychain=keychain,
            connect_factory=connect,
            popen_executor=popen,
            group_signaler=ignore_group_signal,
            control_ready=lambda _bastion, _path: True,
            sleeper=lambda _seconds: None,
        )

        with self.assertRaisesRegex(AgentError, "bastion tunnel could not be started") as caught:
            with route.open(route_config()):
                self.fail("failed tunnel startup must not yield a Connect URL")

        call = popen.calls[0]
        env = call["env"]
        assert isinstance(env, dict)
        self.assertFalse(Path(env["SSH_ASKPASS"]).exists())
        self.assertNotIn("secret child failure", str(caught.exception))
        self.assertNotIn("bastion-passphrase", str(caught.exception))

    def test_wrong_bastion_host_key_exit_stops_before_tunneled_connect(self) -> None:
        keychain = FakeKeychain()
        connect = FakeHealthFactory(
            {
                "http://192.168.42.253:8080": [AgentError("direct refused")],
                "http://127.0.0.1:18080": [AgentError("tunnel refused")],
            }
        )
        process = FakeTunnelProcess(returncode=255)
        popen = FakePopen([process])
        route = ssh_session.ConnectRoute(
            keychain=keychain,
            connect_factory=connect,
            popen_executor=popen,
            group_signaler=ignore_group_signal,
            control_ready=lambda _bastion, _path: True,
            sleeper=lambda _seconds: None,
        )

        with self.assertRaisesRegex(AgentError, "bastion tunnel exited before becoming healthy"):
            with route.open(route_config()):
                self.fail("wrong host trust must not yield a Connect URL")

        argv = popen.calls[0]["argv"]
        assert isinstance(argv, tuple)
        known_hosts = Path(
            next(value.removeprefix("UserKnownHostsFile=") for value in argv if value.startswith("UserKnownHostsFile="))
        )
        self.assertFalse(known_hosts.exists())
        self.assertTrue(process.waited)

    def test_authenticated_health_waits_for_this_ssh_master_to_own_the_forward(self) -> None:
        keychain = FakeKeychain()
        connect = FakeHealthFactory(
            {
                "http://192.168.42.253:8080": [AgentError("direct refused")],
                "http://127.0.0.1:18080": [None],
            }
        )
        process = FakeTunnelProcess()
        route = ssh_session.ConnectRoute(
            keychain=keychain,
            connect_factory=connect,
            popen_executor=FakePopen([process]),
            group_signaler=ignore_group_signal,
            control_ready=lambda _bastion, _path: False,
            sleeper=lambda _seconds: None,
        )

        with self.assertRaisesRegex(AgentError, "bastion tunnel did not become healthy"):
            with route.open(route_config()):
                self.fail("unowned loopback listener must not receive a Connect token")

        self.assertEqual(
            ["http://192.168.42.253:8080"], connect.health_calls
        )
        self.assertTrue(process.waited)

    def test_control_master_readiness_check_has_its_own_timeout(self) -> None:
        with patch.object(
            ssh_session.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(("ssh", "-O", "check"), 1.0),
        ) as control_check:
            ready = ssh_session._control_master_ready(
                bastion(), Path("/private/tmp/private-control")
            )

        self.assertFalse(ready)
        self.assertEqual(1.0, control_check.call_args.kwargs["timeout"])

    def test_askpass_reads_the_exact_keychain_item_without_secret_argv_or_environment(self) -> None:
        from homelab_agent import cli

        keychain = FakeKeychain()
        output = io.StringIO()
        rc = cli.run(
            ["askpass"],
            keychain_factory=lambda: keychain,
            load=lambda: route_config(),
            environ={
                "HOMELAB_AGENT_ASKPASS_SERVICE": "bastion-service",
                "HOMELAB_AGENT_ASKPASS_ACCOUNT": "test-mac",
            },
            output=output,
        )

        self.assertEqual(0, rc)
        self.assertEqual("bastion-passphrase\n", output.getvalue())
        self.assertEqual(
            [
                ("local_account",),
                ("read", "bastion-service", "test-mac"),
            ],
            keychain.calls,
        )

    def test_askpass_rejects_substituted_keychain_reference_before_secret_read(self) -> None:
        from homelab_agent import cli

        for name, service, account in (
            ("service", "other-service", "test-mac"),
            ("account", "bastion-service", "other-mac"),
        ):
            with self.subTest(name=name):
                keychain = FakeKeychain()
                with self.assertRaisesRegex(
                    AgentError, "bastion askpass Keychain reference is not approved"
                ):
                    cli.run(
                        ["askpass"],
                        load=lambda: route_config(),
                        keychain_factory=lambda: keychain,
                        environ={
                            "HOMELAB_AGENT_ASKPASS_SERVICE": service,
                            "HOMELAB_AGENT_ASKPASS_ACCOUNT": account,
                        },
                        output=io.StringIO(),
                    )

                self.assertEqual([("local_account",)], keychain.calls)

    def test_cleanup_signals_the_entire_group_and_reaps_after_wait_timeout(self) -> None:
        class SlowProcess(FakeTunnelProcess):
            def __init__(self) -> None:
                super().__init__(pid=7171)
                self.wait_calls = 0

            def wait(self, timeout: float | None = None) -> int:
                self.wait_calls += 1
                self.waited = True
                if self.wait_calls == 1:
                    raise subprocess.TimeoutExpired(("ssh",), timeout)
                return 0

        process = SlowProcess()
        group_signals: list[tuple[int, signal.Signals]] = []
        route = ssh_session.ConnectRoute(
            keychain=FakeKeychain(),
            connect_factory=FakeHealthFactory(
                {
                    "http://192.168.42.253:8080": [AgentError("direct refused")],
                    "http://127.0.0.1:18080": [None],
                }
            ),
            popen_executor=FakePopen([process]),
            group_signaler=lambda pgid, sent: group_signals.append((pgid, sent)),
            control_ready=lambda _bastion, _path: True,
            sleeper=lambda _seconds: None,
        )

        with route.open(route_config()):
            pass

        self.assertEqual(
            [(7171, signal.SIGTERM), (7171, signal.SIGKILL)], group_signals
        )
        self.assertEqual(2, process.wait_calls)

    def test_cleanup_kills_group_when_term_signal_fails(self) -> None:
        process = FakeTunnelProcess(pid=7272)
        sent: list[tuple[int, signal.Signals]] = []

        def kill_group(pgid: int, group_signal: signal.Signals) -> None:
            sent.append((pgid, group_signal))
            if group_signal == signal.SIGTERM:
                raise OSError("term failed")

        ssh_session._stop_tunnel(
            process, process.pid, group_signaler=kill_group
        )

        self.assertEqual(
            [(7272, signal.SIGTERM), (7272, signal.SIGKILL)], sent
        )
        self.assertTrue(process.waited)

    def test_cleanup_kills_group_even_when_leader_exits_after_term(self) -> None:
        process = FakeTunnelProcess(pid=7373)
        sent: list[tuple[int, signal.Signals]] = []

        ssh_session._stop_tunnel(
            process,
            process.pid,
            group_signaler=lambda pgid, group_signal: sent.append(
                (pgid, group_signal)
            ),
        )

        self.assertEqual(
            [(7373, signal.SIGTERM), (7373, signal.SIGKILL)], sent
        )
        self.assertTrue(process.waited)


class ManagedTargetSshTests(unittest.TestCase):
    def test_direct_target_uses_exact_item_and_preserves_remote_argv(self) -> None:
        agent = FakeAgentSession()
        observed: dict[str, object] = {}

        def ssh_executor(argv: tuple[str, ...], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            observed["argv"] = argv
            observed["known_hosts"] = Path(
                next(value.removeprefix("UserKnownHostsFile=") for value in argv if value.startswith("UserKnownHostsFile="))
            ).read_text(encoding="utf-8")
            return completed(argv, returncode=23)

        rc = ssh_session.run_target_ssh(
            target(),
            ["uname", "-a"],
            agent=agent,
            ssh_executor=ssh_executor,
        )

        argv = observed["argv"]
        assert isinstance(argv, tuple)
        self.assertEqual(23, rc)
        self.assertEqual(
            [("target-item-id", "private_key", FINGERPRINT)],
            agent.calls,
        )
        self.assertEqual(("ubuntu@monitor01", "uname", "-a"), argv[-3:])
        self.assertIn("IdentityAgent=/private/tmp/target-agent.sock", argv)
        self.assertIn("IdentityFile=none", argv)
        self.assertIn("StrictHostKeyChecking=yes", argv)
        assert_publickey_only(self, argv, batch_mode="yes")
        self.assertEqual(target().known_host + "\n", observed["known_hosts"])
        self.assertTrue(agent.exited)

    def test_bastion_target_uses_os_port_host_alias_and_separate_credentials(self) -> None:
        agent = FakeAgentSession()
        process = FakeTunnelProcess()
        popen = FakePopen([process])
        observed: dict[str, object] = {}

        def ssh_executor(argv: tuple[str, ...], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            observed["argv"] = argv
            return completed(argv)

        rc = ssh_session.run_target_ssh(
            target(route="bastion"),
            ["systemctl", "is-active", "node-exporter"],
            agent=agent,
            ssh_executor=ssh_executor,
            bastion=bastion(),
            bastion_keychain_service="bastion-service",
            keychain_account="test-mac",
            popen_executor=popen,
            group_signaler=ignore_group_signal,
            control_ready=lambda _bastion, _path: True,
            allocate_port=lambda: 49152,
            forward_ready=lambda _host, _port: True,
            sleeper=lambda _seconds: None,
        )

        tunnel_argv = popen.calls[0]["argv"]
        outer_argv = observed["argv"]
        assert isinstance(tunnel_argv, tuple)
        assert isinstance(outer_argv, tuple)
        self.assertEqual(0, rc)
        self.assertIn("127.0.0.1:49152:monitor01:22", tunnel_argv)
        self.assertIn("IdentitiesOnly=yes", tunnel_argv)
        self.assertIn("IdentityAgent=none", tunnel_argv)
        self.assertNotIn("/private/tmp/target-agent.sock", tunnel_argv)
        self.assertIn("IdentityAgent=/private/tmp/target-agent.sock", outer_argv)
        self.assertIn("HostKeyAlias=monitor01", outer_argv)
        assert_publickey_only(self, outer_argv, batch_mode="yes")
        assert_publickey_only(self, tunnel_argv, batch_mode="no")
        self.assertEqual("49152", outer_argv[outer_argv.index("-p") + 1])
        self.assertEqual(
            ("ubuntu@127.0.0.1", "systemctl", "is-active", "node-exporter"),
            outer_argv[-4:],
        )
        self.assertTrue(process.waited)
        self.assertTrue(agent.exited)

    def test_tunnel_is_removed_after_target_failure(self) -> None:
        agent = FakeAgentSession()
        process = FakeTunnelProcess()
        popen = FakePopen([process])

        with self.assertRaisesRegex(AgentError, "target SSH failed"):
            ssh_session.run_target_ssh(
                target(route="bastion"),
                ["true"],
                agent=agent,
                ssh_executor=lambda _argv: (_ for _ in ()).throw(AgentError("target SSH failed")),
                bastion=bastion(),
                bastion_keychain_service="bastion-service",
                keychain_account="test-mac",
                popen_executor=popen,
                group_signaler=ignore_group_signal,
                control_ready=lambda _bastion, _path: True,
                allocate_port=lambda: 49153,
                forward_ready=lambda _host, _port: True,
                sleeper=lambda _seconds: None,
            )

        self.assertTrue(process.waited)
        self.assertTrue(agent.exited)

    def test_bastion_target_forward_failure_stops_before_target_agent(self) -> None:
        agent = FakeAgentSession()
        process = FakeTunnelProcess(returncode=255)
        popen = FakePopen([process])
        ssh_calls: list[tuple[str, ...]] = []

        with self.assertRaisesRegex(AgentError, "bastion tunnel exited before becoming healthy"):
            ssh_session.run_target_ssh(
                target(route="bastion"),
                ["true"],
                agent=agent,
                ssh_executor=lambda argv: ssh_calls.append(argv),  # type: ignore[return-value]
                bastion=bastion(),
                bastion_keychain_service="bastion-service",
                keychain_account="test-mac",
                popen_executor=popen,
                group_signaler=ignore_group_signal,
                control_ready=lambda _bastion, _path: True,
                allocate_port=lambda: 49154,
                forward_ready=lambda _host, _port: False,
                sleeper=lambda _seconds: None,
            )

        self.assertEqual([], agent.calls)
        self.assertEqual([], ssh_calls)
        self.assertTrue(process.waited)


class CliTests(unittest.TestCase):
    def test_real_v1_map_reaches_the_forgejo_ssh_transport(self) -> None:
        from homelab_agent import cli

        config = load_config(LEGACY_MAP_PATH)
        observed: dict[str, object] = {}

        class Keychain:
            def local_account(self) -> str:
                return "test-mac"

            def read(self, service: str, account: str) -> Secret:
                observed["keychain"] = (service, account)
                return Secret("connect-token")

        class Route:
            @contextmanager
            def open(self, supplied_config: object):
                observed["route_config"] = supplied_config
                yield "http://approved-connect.example:8080"

        class ConnectClient:
            def __init__(self, url: str, token: Secret, *, vault_name: str) -> None:
                observed["connect"] = (url, token, vault_name)

        def transport(identity: SshIdentity, remote_args: list[str], **kwargs: object) -> int:
            observed["identity"] = identity
            observed["remote_args"] = remote_args
            observed["agent"] = kwargs["agent"]
            return 19

        with patch.object(cli, "EphemeralAgent", lambda client: ("agent", client)):
            result = cli.run(
                ["forgejo-ssh", "--", "git@git.4406.madtown.cloud", "git-upload-pack 'homelab/infra.git'"],
                load=lambda: config,
                keychain_factory=Keychain,
                connect_factory=ConnectClient,
                route_factory=lambda **_kwargs: Route(),
                transport=transport,
            )

        self.assertEqual(19, result)
        self.assertIs(config, observed["route_config"])
        self.assertEqual(config.forgejo, observed["identity"])
        self.assertEqual(
            ["git@git.4406.madtown.cloud", "git-upload-pack 'homelab/infra.git'"],
            observed["remote_args"],
        )
        self.assertEqual(
            (config.connect_keychain_service, "test-mac"), observed["keychain"]
        )

    def test_unknown_target_never_reads_keychain(self) -> None:
        from homelab_agent import cli

        keychain = FakeKeychain()
        config = SimpleNamespace(
            target=lambda alias: (_ for _ in ()).throw(ConfigError(f"unmapped target: {alias}"))
        )

        with self.assertRaisesRegex(ConfigError, "unmapped target: not-a-host"):
            cli.run(
                ["ssh", "not-a-host", "--", "true"],
                load=lambda: config,
                keychain_factory=lambda: keychain,
            )

        self.assertEqual([], keychain.calls)

    def test_mapped_target_cli_routes_connect_and_preserves_command_arguments(self) -> None:
        from homelab_agent import cli

        mapped_target = target(route="bastion")
        config = SimpleNamespace(
            direct_connect_url="http://direct.example:8080",
            tunnel_connect_url="http://127.0.0.1:18080",
            connect_keychain_service="connect-service",
            bastion_keychain_service="bastion-service",
            vault_name="Homelab Secrets",
            bastion=bastion(),
            target=lambda alias: mapped_target if alias == "monitor01" else None,
        )
        keychain = FakeKeychain()
        observed: dict[str, object] = {}

        class FakeRoute:
            @contextmanager
            def open(self, supplied_config: object):
                observed["route_config"] = supplied_config
                yield "http://direct.example:8080"

        class FakeConnectClient:
            def __init__(self, url: str, token: Secret, *, vault_name: str) -> None:
                observed["connect"] = (url, token, vault_name)

        def target_transport(
            supplied_target: ManagedTarget, remote_args: list[str], **kwargs: object
        ) -> int:
            observed["target"] = supplied_target
            observed["remote_args"] = remote_args
            observed["agent"] = kwargs["agent"]
            observed["transport_kwargs"] = kwargs
            return 29

        with patch.object(cli, "EphemeralAgent", lambda client: ("agent", client)):
            rc = cli.run(
                ["ssh", "monitor01", "--", "printf", "%s", "hello world"],
                load=lambda: config,
                keychain_factory=lambda: keychain,
                connect_factory=FakeConnectClient,
                route_factory=lambda **_kwargs: FakeRoute(),
                target_transport=target_transport,
            )

        self.assertEqual(29, rc)
        self.assertIs(config, observed["route_config"])
        self.assertEqual(mapped_target, observed["target"])
        self.assertEqual(["printf", "%s", "hello world"], observed["remote_args"])
        transport_kwargs = observed["transport_kwargs"]
        assert isinstance(transport_kwargs, dict)
        self.assertNotIn("bastion_passphrase", transport_kwargs)
        self.assertEqual("bastion-service", transport_kwargs["bastion_keychain_service"])
        self.assertEqual("test-mac", transport_kwargs["keychain_account"])
        self.assertEqual(
            [
                ("local_account",),
                ("read", "connect-service", "test-mac"),
            ],
            keychain.calls,
        )

    def test_cli_uses_health_selected_connect_url_and_preserves_git_args(self) -> None:
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

        class FakeRoute:
            @contextmanager
            def open(self, supplied_config: object):
                observed["route_config"] = supplied_config
                yield "http://direct.example:8080"

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
                route_factory=lambda **_kwargs: FakeRoute(),
            )

        self.assertEqual(17, rc)
        self.assertEqual("http://direct.example:8080", observed["url"])
        self.assertIs(config, observed["route_config"])
        self.assertEqual(identity(), observed["identity"])
        self.assertEqual(
            ["git@git.4406.madtown.cloud", "git-upload-pack 'homelab/infra.git'"],
            observed["remote_args"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)

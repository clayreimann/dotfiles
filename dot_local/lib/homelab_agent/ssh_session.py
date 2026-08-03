"""Ephemeral SSH-agent sessions and a pinned Forgejo SSH transport."""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, ContextManager, Iterator, Sequence

from .connect import ConnectClient
from .models import SshIdentity
from .process import AgentError, ProcessSpec, Runner, Secret


@dataclass(frozen=True)
class AgentSocket:
    """The public, temporary connection details for one ssh-agent process."""

    socket_path: str
    pid: int


_AGENT_ASSIGNMENT = re.compile(r"^(SSH_AUTH_SOCK|SSH_AGENT_PID)=([^;]+);")
SshExecutor = Callable[..., subprocess.CompletedProcess[str]]


class EphemeralAgent:
    """Load one verified SSH identity into a short-lived, isolated agent."""

    def __init__(self, connect: ConnectClient, runner: Runner | None = None) -> None:
        self._connect = connect
        self._runner = runner or Runner()

    @contextmanager
    def identity(
        self, item_id: str, field: str, expected_fingerprint: str
    ) -> Iterator[AgentSocket]:
        """Yield a verified one-key agent and terminate it on every exit path."""
        started = self._runner.run(
            ProcessSpec(
                argv=("/usr/bin/ssh-agent", "-s"),
                display_name="temporary SSH agent startup",
            )
        )
        agent_environment: dict[str, str] = {}
        private_key: Secret | None = None
        try:
            socket = _agent_socket(started.stdout)
            agent_environment = {
                "SSH_AUTH_SOCK": socket.socket_path,
                "SSH_AGENT_PID": str(socket.pid),
            }
            private_key = self._connect.get_string_field(item_id, field)
            self._runner.run(
                ProcessSpec(
                    argv=("/usr/bin/ssh-add", "-"),
                    stdin=private_key,
                    env_overlay=agent_environment,
                    display_name="temporary SSH key load",
                )
            )
            listed = self._runner.run(
                ProcessSpec(
                    argv=("/usr/bin/ssh-add", "-L"),
                    env_overlay=agent_environment,
                    display_name="temporary SSH public-key listing",
                )
            )
            public_key = _one_public_key(listed.stdout)
            fingerprint = self._runner.run(
                ProcessSpec(
                    argv=("/usr/bin/ssh-keygen", "-lf", "-", "-E", "sha256"),
                    stdin=public_key,
                    env_overlay=agent_environment,
                    display_name="temporary SSH key verification",
                )
            )
            if _fingerprint(fingerprint.stdout) != expected_fingerprint:
                raise AgentError("loaded SSH key fingerprint does not match expected fingerprint")
            yield socket
        finally:
            private_key = None
            prior_error = sys.exc_info()[0] is not None
            try:
                self._runner.run(
                    ProcessSpec(
                        argv=("/usr/bin/ssh-agent", "-k"),
                        env_overlay=agent_environment,
                        display_name="temporary SSH agent cleanup",
                    )
                )
            except AgentError:
                if not prior_error:
                    raise


def _agent_socket(output: str) -> AgentSocket:
    values: dict[str, str] = {}
    for line in output.splitlines():
        match = _AGENT_ASSIGNMENT.match(line)
        if match is None:
            continue
        name, value = match.groups()
        if name in values or not value:
            raise AgentError("temporary SSH agent returned invalid environment")
        values[name] = value
    if set(values) != {"SSH_AUTH_SOCK", "SSH_AGENT_PID"}:
        raise AgentError("temporary SSH agent returned invalid environment")
    try:
        pid = int(values["SSH_AGENT_PID"])
    except ValueError:
        raise AgentError("temporary SSH agent returned invalid environment") from None
    if pid <= 0:
        raise AgentError("temporary SSH agent returned invalid environment")
    return AgentSocket(socket_path=values["SSH_AUTH_SOCK"], pid=pid)


def _one_public_key(output: str) -> str:
    keys = [line for line in output.splitlines() if line.strip()]
    if len(keys) != 1:
        raise AgentError("temporary SSH agent must contain exactly one public key")
    return keys[0]


def _fingerprint(output: str) -> str:
    lines = [line for line in output.splitlines() if line.strip()]
    if len(lines) != 1:
        raise AgentError("temporary SSH key verification returned invalid output")
    fields = lines[0].split()
    if len(fields) < 2 or not fields[1].startswith("SHA256:"):
        raise AgentError("temporary SSH key verification returned invalid output")
    return fields[1]


def run_pinned_ssh(
    identity: SshIdentity,
    remote_args: Sequence[str],
    *,
    agent: EphemeralAgent | None = None,
    ssh_executor: SshExecutor = subprocess.run,
) -> int:
    """Run Git's SSH request with only the supplied verified identity available.

    A credential client is intentionally required from the caller so this module
    cannot read Keychain values or choose a Connect endpoint itself.
    """
    if agent is None:
        raise AgentError("pinned SSH requires an ephemeral credential agent")

    known_hosts_fd, known_hosts_name = tempfile.mkstemp(prefix="homelab-agent-known-hosts-")
    known_hosts_path = Path(known_hosts_name)
    try:
        os.fchmod(known_hosts_fd, 0o600)
        with os.fdopen(known_hosts_fd, "w", encoding="utf-8") as known_hosts:
            known_hosts.write(identity.known_host)
            known_hosts.write("\n")

        with agent.identity(
            identity.credential_item_id,
            identity.private_field,
            identity.expected_fingerprint,
        ) as socket:
            argv = (
                "/usr/bin/ssh",
                "-F",
                "/dev/null",
                "-o",
                f"IdentityAgent={socket.socket_path}",
                "-o",
                "IdentityFile=none",
                "-o",
                "IdentitiesOnly=no",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                f"UserKnownHostsFile={known_hosts_path}",
                "-o",
                "GlobalKnownHostsFile=/dev/null",
                "-p",
                str(identity.port),
                *remote_args,
            )
            completed = ssh_executor(argv)
            return completed.returncode
    finally:
        try:
            known_hosts_path.unlink()
        except FileNotFoundError:
            pass

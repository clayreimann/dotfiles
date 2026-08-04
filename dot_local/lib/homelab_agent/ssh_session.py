"""Ephemeral SSH-agent sessions and a pinned Forgejo SSH transport."""
from __future__ import annotations

import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Protocol, Sequence
from urllib.parse import urlsplit

from .connect import ConnectClient
from .keychain import Keychain
from .models import AgentConfig, Bastion, ManagedTarget, SshIdentity
from .process import AgentError, ProcessSpec, Runner, Secret


@dataclass(frozen=True)
class AgentSocket:
    """The public, temporary connection details for one ssh-agent process."""

    socket_path: str
    pid: int


_AGENT_ASSIGNMENT = re.compile(r"^(SSH_AUTH_SOCK|SSH_AGENT_PID)=([^;]+);")
_AGENT_ENVIRONMENT_NAMES = ("SSH_AUTH_SOCK", "SSH_AGENT_PID")
_OPTIONS_WITH_ARGUMENT = frozenset(
    {"-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p", "-Q", "-R", "-S", "-W", "-w"}
)
_FLAG_OPTIONS = frozenset({"-4", "-6", "-A", "-a", "-C", "-f", "-G", "-g", "-K", "-k", "-M", "-N", "-n", "-q", "-s", "-T", "-t", "-V", "-X", "-x", "-y"})
_PINNED_SECURITY_OPTIONS = frozenset(
    {
        "identityagent",
        "identityfile",
        "identitiesonly",
        "stricthostkeychecking",
        "userknownhostsfile",
        "globalknownhostsfile",
        "knownhostscommand",
        "verifyhostkeydns",
    }
)
SshExecutor = Callable[..., subprocess.CompletedProcess[str]]
PopenExecutor = Callable[..., object]
ControlReady = Callable[[Bastion, Path], bool]
GroupSignaler = Callable[[int, signal.Signals], None]
_TUNNEL_ATTEMPTS = 20
_TUNNEL_RETRY_SECONDS = 0.1
_TUNNEL_WAIT_SECONDS = 5.0
_CONTROL_CHECK_SECONDS = 1.0
_ASKPASS_SERVICE_ENV = "HOMELAB_AGENT_ASKPASS_SERVICE"
_ASKPASS_ACCOUNT_ENV = "HOMELAB_AGENT_ASKPASS_ACCOUNT"
_APPROVED_BASTION_KEY_PATH = Path(
    "/Users/clay/.ssh/homelab_bastion_bootstrap"
)


class TunnelProcess(Protocol):
    returncode: int | None
    pid: int

    def poll(self) -> int | None: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...

    def wait(self, timeout: float | None = None) -> int: ...


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
                unset_env=_AGENT_ENVIRONMENT_NAMES,
                display_name="temporary SSH agent startup",
            )
        )
        agent_environment: dict[str, str] = {}
        private_key: Secret | None = None
        ssh_add_input: Secret | None = None
        socket: AgentSocket | None = None
        try:
            socket = _agent_socket(started.stdout)
            agent_environment = {
                "SSH_AUTH_SOCK": socket.socket_path,
                "SSH_AGENT_PID": str(socket.pid),
            }
            private_key = self._connect.get_string_field(item_id, field)
            ssh_add_input = _ssh_add_input(private_key)
            self._runner.run(
                ProcessSpec(
                    argv=("/usr/bin/ssh-add", "-"),
                    stdin=ssh_add_input,
                    env_overlay=agent_environment,
                    unset_env=_AGENT_ENVIRONMENT_NAMES,
                    display_name="temporary SSH key load",
                )
            )
            listed = self._runner.run(
                ProcessSpec(
                    argv=("/usr/bin/ssh-add", "-L"),
                    env_overlay=agent_environment,
                    unset_env=_AGENT_ENVIRONMENT_NAMES,
                    display_name="temporary SSH public-key listing",
                )
            )
            public_key = _one_public_key(listed.stdout)
            fingerprint = self._runner.run(
                ProcessSpec(
                    argv=("/usr/bin/ssh-keygen", "-lf", "-", "-E", "sha256"),
                    stdin=public_key,
                    env_overlay=agent_environment,
                    unset_env=_AGENT_ENVIRONMENT_NAMES,
                    display_name="temporary SSH key verification",
                )
            )
            if _fingerprint(fingerprint.stdout) != expected_fingerprint:
                raise AgentError("loaded SSH key fingerprint does not match expected fingerprint")
            yield socket
        finally:
            ssh_add_input = None
            private_key = None
            prior_error = sys.exc_info()[0] is not None
            if socket is not None:
                try:
                    self._runner.run(
                        ProcessSpec(
                            argv=("/usr/bin/ssh-agent", "-k"),
                            env_overlay=agent_environment,
                            unset_env=_AGENT_ENVIRONMENT_NAMES,
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


def _ssh_add_input(private_key: Secret) -> Secret:
    """Keep Connect's stored text unchanged except for ssh-add's required final LF."""
    value = private_key.reveal()
    return private_key if value.endswith("\n") else Secret(value + "\n")


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


def _validate_destination(identity: SshIdentity, remote_args: Sequence[str]) -> None:
    """Fail closed unless Git's effective SSH destination is the pinned Forgejo user/host."""
    index = 0
    arguments = tuple(remote_args)
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--":
            index += 1
            break
        if not argument.startswith("-") or argument == "-":
            break
        if argument in _OPTIONS_WITH_ARGUMENT:
            if index + 1 >= len(arguments):
                raise AgentError("SSH invocation is missing an option value")
            _validate_destination_option(identity, argument, arguments[index + 1])
            index += 2
            continue
        if len(argument) > 2 and argument[:2] in {"-l", "-p", "-o"}:
            _validate_destination_option(identity, argument[:2], argument[2:])
            index += 1
            continue
        if argument in _FLAG_OPTIONS or re.fullmatch(r"-v+", argument):
            index += 1
            continue
        raise AgentError("SSH invocation contains an unsupported option")
    if index >= len(arguments):
        raise AgentError("SSH invocation is missing a destination")
    user, separator, host = arguments[index].partition("@")
    if separator != "@" or not user or not host or "@" in host:
        raise AgentError("SSH destination does not match configured identity")
    if user != identity.user or host != identity.host:
        raise AgentError("SSH destination does not match configured identity")


def _validate_destination_option(identity: SshIdentity, option: str, value: str) -> None:
    if not value:
        raise AgentError("SSH invocation is missing an option value")
    if option == "-l" and value != identity.user:
        raise AgentError("SSH destination does not match configured identity")
    if option == "-p" and value != str(identity.port):
        raise AgentError("SSH destination does not match configured identity")
    if option == "-F":
        raise AgentError("SSH invocation contains an unsupported option")
    if option != "-o":
        return
    name, option_value = _ssh_option(value)
    if name in _PINNED_SECURITY_OPTIONS:
        raise AgentError("SSH invocation overrides pinned security settings")
    expected = {
        "user": identity.user,
        "hostname": identity.host,
        "port": str(identity.port),
    }.get(name)
    if expected is not None and option_value != expected:
        raise AgentError("SSH destination does not match configured identity")


def _ssh_option(value: str) -> tuple[str, str]:
    """Parse OpenSSH's ``Key=value`` and ``Key value`` command-line forms."""
    text = value.strip()
    if "=" in text:
        name, option_value = text.split("=", 1)
    else:
        parts = text.split(maxsplit=1)
        if len(parts) != 2:
            raise AgentError("SSH invocation contains an invalid option")
        name, option_value = parts
    name = name.strip().casefold()
    option_value = option_value.strip()
    if not name or not option_value:
        raise AgentError("SSH invocation contains an invalid option")
    return name, option_value


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
    _validate_destination(identity, remote_args)

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


@contextmanager
def _known_hosts_file(known_host: str) -> Iterator[Path]:
    known_hosts_fd, known_hosts_name = tempfile.mkstemp(
        prefix="homelab-agent-known-hosts-"
    )
    known_hosts_path = Path(known_hosts_name)
    try:
        os.fchmod(known_hosts_fd, 0o600)
        with os.fdopen(known_hosts_fd, "w", encoding="utf-8") as known_hosts:
            known_hosts.write(known_host)
            known_hosts.write("\n")
        yield known_hosts_path
    finally:
        try:
            known_hosts_path.unlink()
        except FileNotFoundError:
            pass


@contextmanager
def _askpass_program() -> Iterator[Path]:
    with tempfile.TemporaryDirectory(prefix="homelab-agent-askpass-") as directory:
        path = Path(directory) / "askpass"
        path.write_text(
            "#!/bin/zsh\n"
            "exec /usr/bin/env PYTHONPATH=/Users/clay/.local/lib "
            "/opt/homebrew/bin/python3.12 -m homelab_agent.cli askpass\n",
            encoding="utf-8",
        )
        path.chmod(0o700)
        yield path


def _tunnel_environment(
    askpass: Path, keychain_service: str, keychain_account: str
) -> dict[str, str]:
    environment = os.environ.copy()
    for name in _AGENT_ENVIRONMENT_NAMES:
        environment.pop(name, None)
    environment.update(
        {
            "SSH_ASKPASS": str(askpass),
            "SSH_ASKPASS_REQUIRE": "force",
            _ASKPASS_SERVICE_ENV: keychain_service,
            _ASKPASS_ACCOUNT_ENV: keychain_account,
        }
    )
    return environment


def _validate_bastion_key_path(bastion: Bastion | None) -> None:
    if (
        bastion is not None
        and bastion.encrypted_key_path != _APPROVED_BASTION_KEY_PATH
    ):
        raise AgentError("bastion key path is not approved")


def _stop_tunnel(
    process: TunnelProcess,
    process_group: int,
    *,
    group_signaler: GroupSignaler = os.killpg,
) -> None:
    group_missing = False
    try:
        group_signaler(process_group, signal.SIGTERM)
    except ProcessLookupError:
        group_missing = True
    except Exception:
        pass

    leader_reaped = False
    try:
        process.wait(timeout=_TUNNEL_WAIT_SECONDS)
        leader_reaped = True
    except Exception:
        pass

    if not group_missing:
        try:
            group_signaler(process_group, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except Exception:
            pass

    if not leader_reaped:
        try:
            process.wait(timeout=_TUNNEL_WAIT_SECONDS)
        except Exception:
            raise AgentError("bastion tunnel cleanup failed") from None


@contextmanager
def _open_bastion_tunnel(
    bastion: Bastion,
    keychain_service: str,
    keychain_account: str,
    forward: str,
    *,
    popen_executor: PopenExecutor = subprocess.Popen,
    group_signaler: GroupSignaler = os.killpg,
) -> Iterator[tuple[TunnelProcess, Path]]:
    """Start one encrypted-key, pinned-host bastion forward and always reap it."""
    _validate_bastion_key_path(bastion)
    with _known_hosts_file(bastion.known_host) as known_hosts_path:
        with _askpass_program() as askpass_path:
            control_path = askpass_path.parent / "control"
            process: TunnelProcess | None = None
            process_group: int | None = None
            try:
                argv = (
                    "/usr/bin/ssh",
                    "-F",
                    "/dev/null",
                    "-NT",
                    "-M",
                    "-S",
                    str(control_path),
                    "-o",
                    "ExitOnForwardFailure=yes",
                    "-o",
                    "IdentitiesOnly=yes",
                    "-o",
                    "IdentityAgent=none",
                    "-o",
                    "PreferredAuthentications=publickey",
                    "-o",
                    "PasswordAuthentication=no",
                    "-o",
                    "KbdInteractiveAuthentication=no",
                    "-o",
                    "ChallengeResponseAuthentication=no",
                    "-o",
                    "BatchMode=no",
                    "-o",
                    "StrictHostKeyChecking=yes",
                    "-o",
                    f"UserKnownHostsFile={known_hosts_path}",
                    "-o",
                    "GlobalKnownHostsFile=/dev/null",
                    "-o",
                    "VerifyHostKeyDNS=no",
                    "-o",
                    "IdentityFile=none",
                    "-i",
                    str(bastion.encrypted_key_path),
                    "-L",
                    forward,
                    "-p",
                    str(bastion.port),
                    f"{bastion.user}@{bastion.host}",
                )
                try:
                    started = popen_executor(
                        argv,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        env=_tunnel_environment(
                            askpass_path, keychain_service, keychain_account
                        ),
                        start_new_session=True,
                    )
                except Exception:
                    raise AgentError("bastion tunnel could not be started") from None
                process = started  # type: ignore[assignment]
                process_group = process.pid
                if process_group <= 0:
                    raise AgentError("bastion tunnel returned an invalid process id")
                yield process, control_path
            finally:
                prior_error = sys.exc_info()[0] is not None
                if process is not None and process_group is not None:
                    try:
                        _stop_tunnel(
                            process,
                            process_group,
                            group_signaler=group_signaler,
                        )
                    except AgentError:
                        if not prior_error:
                            raise


def _wait_for_tunnel(
    process: TunnelProcess,
    ownership_ready: Callable[[], bool],
    ready: Callable[[], bool],
    *,
    sleeper: Callable[[float], None] = time.sleep,
) -> None:
    for _attempt in range(_TUNNEL_ATTEMPTS):
        if process.poll() is not None:
            raise AgentError("bastion tunnel exited before becoming healthy")
        if not ownership_ready():
            sleeper(_TUNNEL_RETRY_SECONDS)
            continue
        if ready():
            return
        sleeper(_TUNNEL_RETRY_SECONDS)
    raise AgentError("bastion tunnel did not become healthy")


def _control_master_ready(bastion: Bastion, control_path: Path) -> bool:
    environment = os.environ.copy()
    for name in _AGENT_ENVIRONMENT_NAMES:
        environment.pop(name, None)
    try:
        completed = subprocess.run(
            (
                "/usr/bin/ssh",
                "-F",
                "/dev/null",
                "-S",
                str(control_path),
                "-O",
                "check",
                "-p",
                str(bastion.port),
                f"{bastion.user}@{bastion.host}",
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
            timeout=_CONTROL_CHECK_SECONDS,
        )
    except Exception:
        return False
    return completed.returncode == 0


def _url_endpoint(url: str, operation: str) -> tuple[str, int]:
    try:
        parsed = urlsplit(url)
        if parsed.scheme != "http" or parsed.path not in {"", "/"}:
            raise ValueError
        host = parsed.hostname
        port = parsed.port or 80
    except ValueError:
        raise AgentError(f"{operation} URL is invalid") from None
    if not host:
        raise AgentError(f"{operation} URL is invalid")
    return host, port


class ConnectRoute:
    """Select direct Connect health or one encrypted, pinned bastion forward."""

    def __init__(
        self,
        *,
        keychain: Keychain | None = None,
        token: Secret | None = None,
        account: str | None = None,
        connect_factory: Callable[..., ConnectClient] = ConnectClient,
        popen_executor: PopenExecutor = subprocess.Popen,
        group_signaler: GroupSignaler = os.killpg,
        control_ready: ControlReady = _control_master_ready,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self._keychain = keychain or Keychain()
        self._token = token
        self._account = account
        self._connect_factory = connect_factory
        self._popen_executor = popen_executor
        self._group_signaler = group_signaler
        self._control_ready = control_ready
        self._sleeper = sleeper

    @contextmanager
    def open(self, config: AgentConfig) -> Iterator[str]:
        """Yield the health-checked approved Connect URL and own any tunnel."""
        _validate_bastion_key_path(config.bastion)
        account = self._account or self._keychain.local_account()
        token = self._token or self._keychain.read(
            config.connect_keychain_service, account
        )
        direct = self._connect_factory(
            config.direct_connect_url, token, vault_name=config.vault_name
        )
        try:
            direct.health()
        except AgentError:
            pass
        else:
            yield config.direct_connect_url
            return

        if config.bastion is None:
            raise AgentError("direct Connect is unavailable and no bastion is configured")
        direct_host, direct_port = _url_endpoint(
            config.direct_connect_url, "direct Connect"
        )
        tunnel_host, tunnel_port = _url_endpoint(
            config.tunnel_connect_url, "tunnel Connect"
        )
        if tunnel_host != "127.0.0.1":
            raise AgentError("tunnel Connect URL must use 127.0.0.1")
        forward = f"{tunnel_host}:{tunnel_port}:{direct_host}:{direct_port}"

        with _open_bastion_tunnel(
            config.bastion,
            config.bastion_keychain_service,
            account,
            forward,
            popen_executor=self._popen_executor,
            group_signaler=self._group_signaler,
        ) as (process, control_path):
            tunneled = self._connect_factory(
                config.tunnel_connect_url, token, vault_name=config.vault_name
            )

            def healthy() -> bool:
                try:
                    tunneled.health()
                except AgentError:
                    return False
                return True

            _wait_for_tunnel(
                process,
                lambda: self._control_ready(config.bastion, control_path),
                healthy,
                sleeper=self._sleeper,
            )
            yield config.tunnel_connect_url


def _allocate_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        return int(reservation.getsockname()[1])


def _loopback_ready(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.2):
            return True
    except OSError:
        return False


def _run_target_connection(
    target: ManagedTarget,
    remote_args: Sequence[str],
    *,
    host: str,
    port: int,
    agent: EphemeralAgent,
    ssh_executor: SshExecutor,
    host_key_alias: str | None = None,
) -> int:
    with _known_hosts_file(target.known_host) as known_hosts_path:
        with agent.identity(
            target.credential_item_id,
            target.private_field,
            target.expected_fingerprint,
        ) as agent_socket:
            alias_options: tuple[str, ...] = ()
            if host_key_alias is not None:
                alias_options = ("-o", f"HostKeyAlias={host_key_alias}")
            argv = (
                "/usr/bin/ssh",
                "-F",
                "/dev/null",
                "-o",
                f"IdentityAgent={agent_socket.socket_path}",
                "-o",
                "IdentityFile=none",
                "-o",
                "IdentitiesOnly=no",
                "-o",
                "PreferredAuthentications=publickey",
                "-o",
                "PasswordAuthentication=no",
                "-o",
                "KbdInteractiveAuthentication=no",
                "-o",
                "ChallengeResponseAuthentication=no",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                f"UserKnownHostsFile={known_hosts_path}",
                "-o",
                "GlobalKnownHostsFile=/dev/null",
                "-o",
                "VerifyHostKeyDNS=no",
                *alias_options,
                "-p",
                str(port),
                f"{target.user}@{host}",
                *remote_args,
            )
            try:
                completed = ssh_executor(argv)
            except AgentError:
                raise
            except Exception:
                raise AgentError("target SSH could not be started") from None
            return completed.returncode


def run_target_ssh(
    target: ManagedTarget,
    remote_args: Sequence[str],
    *,
    agent: EphemeralAgent | None = None,
    ssh_executor: SshExecutor = subprocess.run,
    bastion: Bastion | None = None,
    bastion_keychain_service: str | None = None,
    keychain_account: str | None = None,
    popen_executor: PopenExecutor = subprocess.Popen,
    group_signaler: GroupSignaler = os.killpg,
    control_ready: ControlReady = _control_master_ready,
    allocate_port: Callable[[], int] = _allocate_loopback_port,
    forward_ready: Callable[[str, int], bool] = _loopback_ready,
    sleeper: Callable[[float], None] = time.sleep,
) -> int:
    """Run an exact mapped target command with isolated target credentials."""
    if agent is None:
        raise AgentError("target SSH requires an ephemeral credential agent")
    arguments = tuple(remote_args)
    if not arguments:
        raise AgentError("target SSH requires a remote command")
    if target.route == "direct":
        return _run_target_connection(
            target,
            arguments,
            host=target.host,
            port=target.port,
            agent=agent,
            ssh_executor=ssh_executor,
        )
    if target.route != "bastion":
        raise AgentError("target SSH route is invalid")
    if (
        bastion is None
        or not bastion_keychain_service
        or not keychain_account
    ):
        raise AgentError("bastion target requires configured bastion credentials")

    local_port = allocate_port()
    if not 1 <= local_port <= 65535:
        raise AgentError("could not allocate a loopback forwarding port")
    forward = f"127.0.0.1:{local_port}:{target.host}:{target.port}"
    with _open_bastion_tunnel(
        bastion,
        bastion_keychain_service,
        keychain_account,
        forward,
        popen_executor=popen_executor,
        group_signaler=group_signaler,
    ) as (process, control_path):
        _wait_for_tunnel(
            process,
            lambda: control_ready(bastion, control_path),
            lambda: forward_ready("127.0.0.1", local_port),
            sleeper=sleeper,
        )
        return _run_target_connection(
            target,
            arguments,
            host="127.0.0.1",
            port=local_port,
            host_key_alias=target.host,
            agent=agent,
            ssh_executor=ssh_executor,
        )

"""Public diagnostics and deliberately narrow local-secret enrollment."""
from __future__ import annotations

import os
import stat
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from .config import ConfigError, load_config
from .connect import ConnectClient
from .git_command import GIT, SSH_COMMAND
from .keychain import Keychain
from .process import AgentError, ProcessSpec, Runner, Secret
from .ssh_session import ConnectRoute, EphemeralAgent, run_pinned_ssh


Status = Literal["PASS", "FAIL"]
_APPROVED_BASTION_KEY_PATH = Path("/Users/clay/.ssh/homelab_bastion_bootstrap")
_TOOL_PATHS = {
    "python": Path("/opt/homebrew/bin/python3.12"),
    "git": Path("/usr/bin/git"),
    "op": Path("/opt/homebrew/bin/op"),
    "tofu": Path("/opt/homebrew/bin/tofu"),
    "ansible": Path("/opt/homebrew/bin/ansible"),
    "tailscale": Path("/Applications/Tailscale.app/Contents/MacOS/Tailscale"),
}


@dataclass(frozen=True)
class CheckResult:
    """A public, machine-readable doctor result with no secret payload field."""

    status: Status
    category: str
    name: str
    detail: str


def _result(status: Status, category: str, name: str, detail: str) -> CheckResult:
    return CheckResult(status, category, name, detail)


def _python_version() -> str:
    return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"


def _tool_checks(
    config: Any,
    *,
    executable_exists: Callable[[Path], bool],
    python_version: Callable[[], str],
) -> list[CheckResult]:
    results: list[CheckResult] = []
    for name, required_major in config.tools.items():
        path = _TOOL_PATHS.get(name)
        if path is None or not executable_exists(path):
            results.append(
                _result("FAIL", "tools", name, "required executable is unavailable")
            )
            continue
        if name == "python" and not python_version().startswith(f"{required_major}."):
            results.append(
                _result(
                    "FAIL",
                    "tools",
                    name,
                    f"required Python {required_major} is unavailable",
                )
            )
            continue
        results.append(_result("PASS", "tools", name, "approved executable is available"))
    return results


def _presented_host_key_matches(identity: Any) -> bool:
    """Compare the real, public Forgejo presentation with the exact pinned line.

    ``ssh-keyscan`` output is captured and never shown to the caller.  A network
    error, a missing key, a different key, or additional key material are all a
    simple ``False`` host-trust result; no authentication is attempted afterward.
    """
    try:
        completed = subprocess.run(
            (
                "/usr/bin/ssh-keyscan",
                "-T",
                "10",
                "-t",
                "ed25519",
                "-p",
                str(identity.port),
                identity.host,
            ),
            stdin=subprocess.DEVNULL,
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError:
        return False
    presented = [
        line
        for line in completed.stdout.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    return completed.returncode == 0 and presented == [identity.known_host]


def _connect_scope_is_available(client: ConnectClient, identity: Any) -> bool:
    """Require an authenticated exact-item lookup, not just the unauthenticated health path."""
    try:
        client.get_item(identity.credential_item_id)
    except AgentError:
        return False
    return True


def _validate_credential(client: ConnectClient, identity: Any) -> bool:
    """Use the existing ephemeral-agent fingerprint validation without persistent keys."""
    try:
        with EphemeralAgent(client).identity(
            identity.credential_item_id,
            identity.private_field,
            identity.expected_fingerprint,
        ):
            return True
    except AgentError:
        return False


def _forgejo_probe(client: ConnectClient, identity: Any) -> int:
    """Return a pinned ``ssh -T`` status; 0/1 are documented authenticated outcomes."""
    agent = EphemeralAgent(client)
    return run_pinned_ssh(
        identity,
        ("-T", f"{identity.user}@{identity.host}"),
        agent=agent,
        ssh_executor=lambda argv, **kwargs: subprocess.run(
            argv, text=True, capture_output=True, **kwargs
        ),
    )


def _inspect_repository(repository: Any, *, runner: Runner | None = None) -> bool:
    """Inspect only existing clone metadata; never fetches or changes a worktree."""
    path = repository.path
    if not path.exists():
        return True
    if not path.is_dir():
        return False
    actual_runner = runner or Runner()
    unset_git_environment = tuple(
        sorted(name for name in os.environ if name.startswith("GIT_"))
    )
    try:
        origin = actual_runner.run(
            ProcessSpec(
                argv=(GIT, "-C", str(path), "remote", "get-url", "origin"),
                unset_env=unset_git_environment,
                display_name="Git origin inspection",
            )
        ).stdout.strip().rstrip("/")
        ssh_command = actual_runner.run(
            ProcessSpec(
                argv=(GIT, "-C", str(path), "config", "--local", "--get", "core.sshCommand"),
                unset_env=unset_git_environment,
                display_name="Git transport inspection",
            )
        ).stdout.strip()
    except AgentError:
        return False
    return origin == repository.remote.rstrip("/") and ssh_command == SSH_COMMAND


def _unavailable_live_checks() -> list[CheckResult]:
    return [
        _result("FAIL", "network", "Connect route", "live routing is unavailable"),
        _result("FAIL", "connect", "Homelab Secrets", "Connect inspection is unavailable"),
        _result("FAIL", "credential", "forgejo credential", "credential validation is unavailable"),
        _result("FAIL", "host-trust", "Forgejo host key", "host trust validation is unavailable"),
        _result("FAIL", "server-authorization", "Forgejo authentication", "server authorization is unavailable"),
    ]


def run_doctor(
    live: bool,
    *,
    load: Callable[[], Any] = load_config,
    executable_exists: Callable[[Path], bool] = Path.is_file,
    python_version: Callable[[], str] = _python_version,
    keychain_factory: Callable[[], Keychain] = Keychain,
    route_factory: Callable[..., ConnectRoute] = ConnectRoute,
    connect_factory: Callable[..., ConnectClient] = ConnectClient,
    connect_scope_checker: Callable[[ConnectClient, Any], bool] = _connect_scope_is_available,
    credential_validator: Callable[[ConnectClient, Any], bool] = _validate_credential,
    host_trust_probe: Callable[[Any], bool] = _presented_host_key_matches,
    forgejo_probe: Callable[[ConnectClient, Any], int] = _forgejo_probe,
    repository_inspector: Callable[[Any], bool] = _inspect_repository,
) -> tuple[CheckResult, ...]:
    """Return public diagnostics; non-live mode touches no Keychain or network."""
    try:
        config = load()
    except (AgentError, ConfigError, OSError, ValueError):
        return (_result("FAIL", "config", "credential map", "public configuration is invalid"),)

    results = _tool_checks(
        config, executable_exists=executable_exists, python_version=python_version
    )
    if config.vault_name == "Homelab Secrets":
        results.append(_result("PASS", "config", "credential map", "public configuration is approved"))
    else:
        results.append(_result("FAIL", "config", "credential map", "public configuration is invalid"))
    if not live:
        return tuple(results)

    try:
        keychain = keychain_factory()
        account = keychain.local_account()
    except (AgentError, OSError, ValueError):
        results.append(_result("FAIL", "keychain", "LocalHostName", "local account is unavailable"))
        results.extend(_unavailable_live_checks())
        return tuple(results)
    results.append(_result("PASS", "keychain", "LocalHostName", "local account is available"))

    try:
        token = keychain.read(config.connect_keychain_service, account)
    except (AgentError, OSError, ValueError):
        results.append(_result("FAIL", "keychain", "Connect token", "required item is unavailable"))
        results.extend(_unavailable_live_checks())
        return tuple(results)
    results.append(_result("PASS", "keychain", "Connect token", "required item is available"))

    if config.bastion is not None:
        try:
            keychain.read(config.bastion_keychain_service, account)
        except (AgentError, OSError, ValueError):
            results.append(_result("FAIL", "keychain", "Bastion passphrase", "required item is unavailable"))
        else:
            results.append(_result("PASS", "keychain", "Bastion passphrase", "required item is available"))

    try:
        route = route_factory(
            keychain=keychain,
            token=token,
            account=account,
            connect_factory=connect_factory,
        )
        with route.open(config) as connect_url:
            client = connect_factory(connect_url, token, vault_name=config.vault_name)
            client.health()
            results.append(_result("PASS", "network", "Connect route", "approved route is healthy"))
            if not connect_scope_checker(client, config.forgejo):
                results.append(
                    _result(
                        "FAIL",
                        "connect",
                        "Homelab Secrets",
                        "approved vault access failed",
                    )
                )
                results.extend(
                    [
                        _result("FAIL", "credential", "forgejo credential", "credential validation is unavailable"),
                        _result("FAIL", "host-trust", "Forgejo host key", "host trust validation is unavailable"),
                        _result("FAIL", "server-authorization", "Forgejo authentication", "server authorization is unavailable"),
                    ]
                )
                return tuple(results)
            results.append(_result("PASS", "connect", "Homelab Secrets", "approved vault is reachable"))
            credential_ok = credential_validator(client, config.forgejo)
            results.append(
                _result(
                    "PASS" if credential_ok else "FAIL",
                    "credential",
                    "forgejo credential",
                    "exact field and fingerprint are approved" if credential_ok else "exact field or fingerprint is invalid",
                )
            )
            host_ok = host_trust_probe(config.forgejo)
            results.append(
                _result(
                    "PASS" if host_ok else "FAIL",
                    "host-trust",
                    "Forgejo host key",
                    "pinned host key is approved" if host_ok else "pinned host key is invalid",
                )
            )
            if not host_ok:
                authorized = False
                authorization_detail = (
                    "authentication was not attempted after host-trust failure"
                )
            elif not credential_ok:
                authorized = False
                authorization_detail = (
                    "authentication was not attempted after credential validation failure"
                )
            else:
                try:
                    probe_status = forgejo_probe(client, config.forgejo)
                except (AgentError, OSError, ValueError):
                    probe_status = 255
                # OpenSSH -T commonly exits 1 after a successful server-side no-shell
                # response.  SSH authentication failures use distinct status 255.
                authorized = probe_status in {0, 1}
                authorization_detail = (
                    "pinned authentication succeeded"
                    if authorized
                    else "pinned authentication was rejected"
                )
            results.append(
                _result(
                    "PASS" if authorized else "FAIL",
                    "server-authorization",
                    "Forgejo authentication",
                    authorization_detail,
                )
            )
            for repository in config.repositories:
                wiring_ok = repository_inspector(repository)
                results.append(
                    _result(
                        "PASS" if wiring_ok else "FAIL",
                        "git-wiring",
                        repository.name,
                        "repository wiring is approved" if wiring_ok else "repository wiring is invalid",
                    )
                )
    except (AgentError, OSError, ValueError):
        results.extend(_unavailable_live_checks())
    return tuple(results)


def _empty_passphrase_probe(path: Path) -> int:
    """Run the public empty-passphrase check without exposing a passphrase anywhere."""
    try:
        return subprocess.run(
            ("/usr/bin/ssh-keygen", "-y", "-P", "", "-f", str(path)),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
    except OSError:
        raise AgentError("bastion key validation could not be started") from None


def enroll_keychain(
    service: str,
    *,
    load: Callable[[], Any] = load_config,
    keychain_factory: Callable[[], Keychain] = Keychain,
    key_path: Path = _APPROVED_BASTION_KEY_PATH,
    path_stat: Callable[[Path], os.stat_result] = os.lstat,
    chmod: Callable[[Path, int], None] = os.chmod,
    empty_passphrase_probe: Callable[[Path], int] = _empty_passphrase_probe,
) -> None:
    """Prompt to store one permitted local secret, never accepting its value as input."""
    config = load()
    allowed = {config.connect_keychain_service, config.bastion_keychain_service}
    if service not in allowed:
        raise AgentError("Keychain service is not approved")
    if service == config.bastion_keychain_service:
        if key_path != _APPROVED_BASTION_KEY_PATH:
            raise AgentError("bastion key path is not approved")
        try:
            mode = path_stat(key_path).st_mode
        except OSError:
            raise AgentError("bastion key file is unavailable") from None
        if not stat.S_ISREG(mode):
            raise AgentError("bastion key must be a regular non-symlink file")
        try:
            chmod(key_path, 0o600)
        except OSError:
            raise AgentError("bastion key permissions could not be set") from None
        try:
            is_unencrypted = empty_passphrase_probe(key_path) == 0
        except OSError:
            raise AgentError("bastion key validation could not be completed") from None
        if is_unencrypted:
            raise AgentError("bastion key is unencrypted")
    keychain = keychain_factory()
    keychain.enroll(service, keychain.local_account())

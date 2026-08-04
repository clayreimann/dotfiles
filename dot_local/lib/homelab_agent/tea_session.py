"""Ephemeral, Connect-backed authentication for the Tea Forgejo client."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, TextIO

from .config import load_config
from .connect import ConnectClient
from .keychain import Keychain
from .process import AgentError, Secret
from .ssh_session import ConnectRoute


TEA = "/opt/homebrew/bin/tea"
_LOGIN_NAME = "homelab-agent"
_EXPECTED_API_LOGIN = "claude"
_MINIMUM_VERSION = (0, 14, 2)
_VERSION_PATTERN = re.compile(r"(?:Version:\s*|\bversion\s+)(\d+)\.(\d+)\.(\d+)", re.I)
_ANSI_ESCAPE_PATTERN = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

ProcessExecutor = Callable[..., subprocess.CompletedProcess[str]]


class TeaSession:
    """A single temporary Tea login for the approved Forgejo API identity."""

    def __init__(
        self,
        forgejo: Any,
        client: ConnectClient,
        *,
        executor: ProcessExecutor = subprocess.run,
        environ: Mapping[str, str] = os.environ,
    ) -> None:
        self._forgejo = forgejo
        self._client = client
        self._executor = executor
        self._environ = environ
        self._temporary_directory: tempfile.TemporaryDirectory[str] | None = None
        self._config_root: Path | None = None

    def __enter__(self) -> TeaSession:
        try:
            self._temporary_directory = tempfile.TemporaryDirectory()
            self._config_root = Path(self._temporary_directory.name)
            os.chmod(self._config_root, 0o700)
        except OSError:
            self._cleanup()
            raise AgentError("Tea temporary configuration setup failed") from None
        try:
            self._verify_tea_version()
            token = self._client.get_string_field(
                self._forgejo.credential_item_id, self._forgejo.api_token_field
            )
            setup_environment = self._child_environment(
                {
                    "GITEA_SERVER_URL": self._forgejo.api_url,
                    "GITEA_SERVER_USER": self._forgejo.api_user,
                    "GITEA_SERVER_TOKEN": token.reveal(),
                }
            )
            self._require_success(
                (TEA, "logins", "add", "--name", _LOGIN_NAME),
                setup_environment,
                "Tea login setup failed",
            )
            identity = self._require_success(
                (TEA, "api", "/user", "--login", _LOGIN_NAME),
                self._child_environment(),
                "Tea identity verification failed",
            )
            try:
                payload = json.loads(identity.stdout)
            except json.JSONDecodeError:
                raise AgentError("Tea identity verification failed") from None
            if not isinstance(payload, dict) or payload.get("login") != _EXPECTED_API_LOGIN:
                raise AgentError("Tea identity verification failed")
        except BaseException:
            self._cleanup()
            raise
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self._cleanup()

    def run(
        self,
        arguments: Sequence[str],
        *,
        output: TextIO,
        error_output: TextIO,
    ) -> int:
        """Run arbitrary Tea arguments with the temporary login only."""
        del output, error_output
        completed = self._execute_interactive((TEA, *arguments), self._child_environment())
        return completed.returncode

    def api_json(self, arguments: Sequence[str]) -> object:
        """Call ``tea api`` and return only a valid JSON response."""
        completed = self._execute((TEA, "api", *arguments), self._child_environment())
        if completed.returncode != 0:
            raise AgentError("Tea API request failed")
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError:
            raise AgentError("Tea API response was invalid") from None

    def _verify_tea_version(self) -> None:
        completed = self._execute((TEA, "--version"), self._child_environment())
        match = _VERSION_PATTERN.search(_ANSI_ESCAPE_PATTERN.sub("", completed.stdout))
        if completed.returncode != 0 or match is None:
            raise AgentError("Tea version check failed")
        version = tuple(int(component) for component in match.groups())
        if version < _MINIMUM_VERSION:
            raise AgentError("Tea 0.14.2 or newer is required")

    def _child_environment(self, overlay: Mapping[str, str] | None = None) -> dict[str, str]:
        if self._config_root is None:
            raise AgentError("Tea session is not active")
        environment = {
            name: value
            for name, value in self._environ.items()
            if not name.startswith("GITEA_SERVER_")
        }
        environment["XDG_CONFIG_HOME"] = str(self._config_root)
        if overlay is not None:
            environment.update(overlay)
        return environment

    def _require_success(
        self, argv: tuple[str, ...], environment: Mapping[str, str], message: str
    ) -> subprocess.CompletedProcess[str]:
        completed = self._execute(argv, environment)
        if completed.returncode != 0:
            raise AgentError(message)
        return completed

    def _execute(
        self, argv: tuple[str, ...], environment: Mapping[str, str]
    ) -> subprocess.CompletedProcess[str]:
        try:
            return self._executor(argv, text=True, capture_output=True, env=dict(environment))
        except Exception:
            raise AgentError("Tea process could not be started") from None

    def _execute_interactive(
        self, argv: tuple[str, ...], environment: Mapping[str, str]
    ) -> subprocess.CompletedProcess[str]:
        try:
            return self._executor(argv, env=dict(environment))
        except Exception:
            raise AgentError("Tea process could not be started") from None

    def _cleanup(self) -> None:
        if self._temporary_directory is not None:
            self._temporary_directory.cleanup()
            self._temporary_directory = None
            self._config_root = None


def run_tea(
    arguments: Sequence[str],
    *,
    load: Callable[[], Any] = load_config,
    keychain_factory: Callable[[], Keychain] = Keychain,
    connect_factory: Callable[..., ConnectClient] = ConnectClient,
    route_factory: Callable[..., ConnectRoute] = ConnectRoute,
    executor: ProcessExecutor = subprocess.run,
    environ: Mapping[str, str] = os.environ,
    output: TextIO = sys.stdout,
    error_output: TextIO = sys.stderr,
    client: ConnectClient | None = None,
) -> int:
    """Authenticate a temporary Tea session and forward the caller's exit code."""
    config = load()
    if getattr(config, "version", None) != 2:
        raise AgentError("Tea workflow policy requires credential map version 2")
    if client is not None:
        with TeaSession(config.forgejo, client, executor=executor, environ=environ) as session:
            return session.run(arguments, output=output, error_output=error_output)

    keychain = keychain_factory()
    account = keychain.local_account()
    token: Secret = keychain.read(config.connect_keychain_service, account)
    route = route_factory(
        keychain=keychain,
        token=token,
        account=account,
        connect_factory=connect_factory,
    )
    with route.open(config) as connect_url:
        connected_client = connect_factory(
            connect_url, token, vault_name=config.vault_name
        )
        with TeaSession(
            config.forgejo, connected_client, executor=executor, environ=environ
        ) as session:
            return session.run(arguments, output=output, error_output=error_output)

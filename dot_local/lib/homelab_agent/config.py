"""Strict loading for the public Mac homelab-agent credential map."""
from __future__ import annotations

import json
import os
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from .models import AgentConfig, Bastion, ManagedTarget, Repository, SshIdentity


DEFAULT_CONFIG_PATH = Path(
    "/Users/clay/Code/homelab/infra/config/mac-agent/credential-map.json"
)
_FORBIDDEN_SECRET_KEYS = frozenset({"token", "password", "passphrase", "private_key"})
_DOCUMENT_KEYS = frozenset(
    {
        "version",
        "vault",
        "connect",
        "keychain",
        "forgejo",
        "bastion",
        "targets",
        "repositories",
        "tools",
    }
)
_IDENTITY_KEYS = frozenset(
    {
        "host",
        "port",
        "user",
        "credential_item_id",
        "private_field",
        "expected_fingerprint",
        "known_host",
    }
)
_TARGET_KEYS = _IDENTITY_KEYS | {"alias", "route"}
_BASTION_KEYS = frozenset({"host", "port", "user", "encrypted_key_path", "known_host"})
_REPOSITORY_KEYS = frozenset({"name", "remote", "path"})
_TOOL_KEYS = frozenset({"python", "git", "op", "tofu", "ansible", "tailscale"})


class ConfigError(ValueError):
    """The public credential map is missing or violates its runtime contract."""


def _config_path(path: Path | None) -> Path:
    if path is not None:
        return path
    override = os.environ.get("HOMELAB_AGENT_CONFIG")
    return Path(override) if override else DEFAULT_CONFIG_PATH


def _read_document(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ConfigError("cannot read or parse configuration") from error
    if not isinstance(document, dict):
        raise ConfigError("configuration document must be an object")
    return document


def _reject_secret_keys(value: object, path: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            child_path = f"{path}.{key_text}" if path else key_text
            if key_text.lower() in _FORBIDDEN_SECRET_KEYS:
                raise ConfigError(f"forbidden secret key: {child_path}")
            _reject_secret_keys(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_keys(child, f"{path}.{index}" if path else str(index))


def _object(value: object, path: str, keys: frozenset[str]) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{path} must be an object")
    actual = set(value)
    unknown = sorted(actual - keys)
    missing = sorted(keys - actual)
    if unknown:
        raise ConfigError(f"unknown keys at {path}: {', '.join(unknown)}")
    if missing:
        raise ConfigError(f"missing keys at {path}: {', '.join(missing)}")
    return value


def _string(value: object, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise ConfigError(f"{path} must be a non-empty string")
    return value


def _port(value: object, path: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535:
        raise ConfigError(f"{path} must be an integer from 1 through 65535")
    return value


def _identity(value: object, path: str) -> SshIdentity:
    fields = _object(value, path, _IDENTITY_KEYS)
    return SshIdentity(
        host=_string(fields["host"], f"{path}.host"),
        port=_port(fields["port"], f"{path}.port"),
        user=_string(fields["user"], f"{path}.user"),
        credential_item_id=_string(fields["credential_item_id"], f"{path}.credential_item_id"),
        private_field=_string(fields["private_field"], f"{path}.private_field"),
        expected_fingerprint=_string(fields["expected_fingerprint"], f"{path}.expected_fingerprint"),
        known_host=_string(fields["known_host"], f"{path}.known_host"),
    )


def _target(value: object, path: str) -> ManagedTarget:
    fields = _object(value, path, _TARGET_KEYS)
    route = _string(fields["route"], f"{path}.route")
    if route not in {"direct", "bastion"}:
        raise ConfigError(f"{path}.route must be direct or bastion")
    return ManagedTarget(
        host=_string(fields["host"], f"{path}.host"),
        port=_port(fields["port"], f"{path}.port"),
        user=_string(fields["user"], f"{path}.user"),
        credential_item_id=_string(
            fields["credential_item_id"], f"{path}.credential_item_id"
        ),
        private_field=_string(fields["private_field"], f"{path}.private_field"),
        expected_fingerprint=_string(
            fields["expected_fingerprint"], f"{path}.expected_fingerprint"
        ),
        known_host=_string(fields["known_host"], f"{path}.known_host"),
        alias=_string(fields["alias"], f"{path}.alias"),
        route=route,
    )


def _bastion(value: object) -> Bastion | None:
    if value is None:
        return None
    fields = _object(value, "bastion", _BASTION_KEYS)
    return Bastion(
        host=_string(fields["host"], "bastion.host"),
        port=_port(fields["port"], "bastion.port"),
        user=_string(fields["user"], "bastion.user"),
        encrypted_key_path=Path(_string(fields["encrypted_key_path"], "bastion.encrypted_key_path")),
        known_host=_string(fields["known_host"], "bastion.known_host"),
    )


def _targets(value: object) -> Mapping[str, ManagedTarget]:
    if not isinstance(value, list):
        raise ConfigError("targets must be a list")
    targets: dict[str, ManagedTarget] = {}
    for index, value_at_index in enumerate(value):
        target = _target(value_at_index, f"targets.{index}")
        if target.alias in targets:
            raise ConfigError(f"duplicate target alias: {target.alias}")
        targets[target.alias] = target
    return MappingProxyType(targets)


def _repositories(value: object) -> tuple[Repository, ...]:
    if not isinstance(value, list):
        raise ConfigError("repositories must be a list")
    repositories: list[Repository] = []
    destinations: set[Path] = set()
    for index, value_at_index in enumerate(value):
        path = f"repositories.{index}"
        fields = _object(value_at_index, path, _REPOSITORY_KEYS)
        destination = Path(_string(fields["path"], f"{path}.path"))
        resolved_destination = destination.resolve()
        if resolved_destination in destinations:
            raise ConfigError(f"duplicate repository destination: {destination}")
        destinations.add(resolved_destination)
        repositories.append(
            Repository(
                name=_string(fields["name"], f"{path}.name"),
                remote=_string(fields["remote"], f"{path}.remote"),
                path=destination,
            )
        )
    return tuple(repositories)


def _tools(value: object) -> Mapping[str, str]:
    fields = _object(value, "tools", _TOOL_KEYS)
    return MappingProxyType({name: _string(fields[name], f"tools.{name}") for name in _TOOL_KEYS})


def load_config(path: Path | None = None) -> AgentConfig:
    """Load a strict, non-secret version-1 map into immutable runtime models."""
    document = _read_document(_config_path(path))
    _reject_secret_keys(document)
    fields = _object(document, "document", _DOCUMENT_KEYS)
    if fields["version"] != 1:
        raise ConfigError("unsupported config version")

    vault = _object(fields["vault"], "vault", frozenset({"name"}))
    connect = _object(fields["connect"], "connect", frozenset({"direct_url", "tunnel_url"}))
    keychain = _object(
        fields["keychain"],
        "keychain",
        frozenset({"connect_service", "bastion_service"}),
    )
    forgejo = _identity(fields["forgejo"], "forgejo")

    return AgentConfig(
        vault_name=_string(vault["name"], "vault.name"),
        direct_connect_url=_string(connect["direct_url"], "connect.direct_url"),
        tunnel_connect_url=_string(connect["tunnel_url"], "connect.tunnel_url"),
        connect_keychain_service=_string(
            keychain["connect_service"], "keychain.connect_service"
        ),
        bastion_keychain_service=_string(
            keychain["bastion_service"], "keychain.bastion_service"
        ),
        forgejo=forgejo,
        bastion=_bastion(fields["bastion"]),
        targets=_targets(fields["targets"]),
        repositories=_repositories(fields["repositories"]),
        tools=_tools(fields["tools"]),
    )

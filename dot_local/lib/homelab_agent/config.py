"""Strict loading for the public Mac homelab-agent credential map."""
from __future__ import annotations

import json
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from .models import (
    AgentConfig,
    Bastion,
    ForgejoAutomation,
    ForgejoIdentity,
    ManagedTarget,
    Repository,
    SshIdentity,
)


DEFAULT_CONFIG_PATH = Path(
    "/Users/clay/Code/homelab/infra/config/mac-agent/credential-map.json"
)
_APPROVED_VAULT_NAME = "Homelab Secrets"
_APPROVED_DIRECT_CONNECT_URL = "http://192.168.42.253:8080"
_APPROVED_TUNNEL_CONNECT_URL = "http://127.0.0.1:18080"
_APPROVED_CONNECT_KEYCHAIN_SERVICE = "com.4406.homelab-agent.connect-token"
_APPROVED_BASTION_KEYCHAIN_SERVICE = "com.4406.homelab-agent.bastion-passphrase"
_APPROVED_FORGEJO = {
    "host": "git.4406.madtown.cloud",
    "port": 2222,
    "user": "git",
    "credential_item_id": "yznfzgoql7jl4oa6spa7vm3644",
    "private_field": "private_key",
    "expected_fingerprint": "SHA256:hK4mZs4YQvDEf1zgeAOKtER0+eIdPJsDxRzPHlpXpjA",
    "known_host": "[git.4406.madtown.cloud]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGyB56wKbde2dOT+puZOfjpWqTNx3sIDkEjoN1wvUTyT",
    "api_url": "https://git.4406.madtown.cloud",
    "api_user": "claude",
    "api_token_field": "api_token",
}
_APPROVED_FORGEJO_SSH = {
    "host": "git.4406.madtown.cloud",
    "port": 2222,
    "user": "git",
    "credential_item_id": "yznfzgoql7jl4oa6spa7vm3644",
    "private_field": "private_key",
    "expected_fingerprint": "SHA256:hK4mZs4YQvDEf1zgeAOKtER0+eIdPJsDxRzPHlpXpjA",
    "known_host": "[git.4406.madtown.cloud]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGyB56wKbde2dOT+puZOfjpWqTNx3sIDkEjoN1wvUTyT",
}
_APPROVED_FORGEJO_AUTOMATION = {
    "repository": "homelab/infra",
    "required_workflows": (
        "infra-validate.yml",
        "infra-vm-plan.yml",
        "infra-lxc-plan.yml",
        "infra-guest-config-check.yml",
        "infra-stack-config-check.yml",
    ),
    "deploy_workflow": "infra-stacks-deploy.yml",
    "deploy_ref": "main",
    "deploy_targets": ("docker01", "monitor01"),
}
_APPROVED_TEA_VERSION = "0.14"
_FORBIDDEN_SECRET_KEYS = frozenset({"token", "password", "passphrase", "private_key"})
_LEGACY_DOCUMENT_KEYS = frozenset(
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
_VERSION_2_DOCUMENT_KEYS = _LEGACY_DOCUMENT_KEYS | {"forgejo_automation"}
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
_FORGEJO_KEYS = _IDENTITY_KEYS | frozenset({"api_url", "api_user", "api_token_field"})
_FORGEJO_AUTOMATION_KEYS = frozenset(
    {"repository", "required_workflows", "deploy_workflow", "deploy_ref", "deploy_targets"}
)
_TARGET_KEYS = _IDENTITY_KEYS | {"alias", "route"}
_BASTION_KEYS = frozenset({"host", "port", "user", "encrypted_key_path", "known_host"})
_REPOSITORY_KEYS = frozenset({"name", "remote", "path"})
_LEGACY_TOOL_KEYS = frozenset({"python", "git", "op", "tofu", "ansible", "tailscale"})
_VERSION_2_TOOL_KEYS = _LEGACY_TOOL_KEYS | {"tea"}


class ConfigError(ValueError):
    """The public credential map is missing or violates its runtime contract."""


def _config_path(path: Path | None) -> Path:
    return path if path is not None else DEFAULT_CONFIG_PATH


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


def _forgejo_identity(value: object) -> ForgejoIdentity:
    fields = _object(value, "forgejo", _FORGEJO_KEYS)
    return ForgejoIdentity(
        host=_string(fields["host"], "forgejo.host"),
        port=_port(fields["port"], "forgejo.port"),
        user=_string(fields["user"], "forgejo.user"),
        credential_item_id=_string(fields["credential_item_id"], "forgejo.credential_item_id"),
        private_field=_string(fields["private_field"], "forgejo.private_field"),
        expected_fingerprint=_string(
            fields["expected_fingerprint"], "forgejo.expected_fingerprint"
        ),
        known_host=_string(fields["known_host"], "forgejo.known_host"),
        api_url=_string(fields["api_url"], "forgejo.api_url"),
        api_user=_string(fields["api_user"], "forgejo.api_user"),
        api_token_field=_string(fields["api_token_field"], "forgejo.api_token_field"),
    )


def _validate_forgejo_pins(identity: SshIdentity | ForgejoIdentity) -> None:
    approved = (
        _APPROVED_FORGEJO
        if isinstance(identity, ForgejoIdentity)
        else _APPROVED_FORGEJO_SSH
    )
    for field, expected in approved.items():
        if getattr(identity, field) != expected:
            raise ConfigError(f"forgejo.{field} must match the approved value")


def _string_tuple(value: object, path: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ConfigError(f"{path} must be a list")
    return tuple(_string(entry, f"{path}.{index}") for index, entry in enumerate(value))


def _forgejo_automation(value: object) -> ForgejoAutomation:
    fields = _object(value, "forgejo_automation", _FORGEJO_AUTOMATION_KEYS)
    automation = ForgejoAutomation(
        repository=_string(fields["repository"], "forgejo_automation.repository"),
        required_workflows=_string_tuple(
            fields["required_workflows"], "forgejo_automation.required_workflows"
        ),
        deploy_workflow=_string(fields["deploy_workflow"], "forgejo_automation.deploy_workflow"),
        deploy_ref=_string(fields["deploy_ref"], "forgejo_automation.deploy_ref"),
        deploy_targets=_string_tuple(
            fields["deploy_targets"], "forgejo_automation.deploy_targets"
        ),
    )
    for field, expected in _APPROVED_FORGEJO_AUTOMATION.items():
        if getattr(automation, field) != expected:
            raise ConfigError(
                f"forgejo_automation.{field} must match the approved value"
            )
    return automation


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


def _tools(value: object, version: int) -> Mapping[str, str]:
    keys = _VERSION_2_TOOL_KEYS if version == 2 else _LEGACY_TOOL_KEYS
    fields = _object(value, "tools", keys)
    tools = MappingProxyType(
        {name: _string(fields[name], f"tools.{name}") for name in keys}
    )
    if version == 2 and tools["tea"] != _APPROVED_TEA_VERSION:
        raise ConfigError("tools.tea must match the approved value")
    return tools


def load_config(path: Path | None = None) -> AgentConfig:
    """Load a strict, non-secret version-1 or version-2 credential map."""
    document = _read_document(_config_path(path))
    _reject_secret_keys(document)
    version = document.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version not in {1, 2}:
        raise ConfigError("unsupported config version")
    fields = _object(
        document,
        "document",
        _VERSION_2_DOCUMENT_KEYS if version == 2 else _LEGACY_DOCUMENT_KEYS,
    )

    vault = _object(fields["vault"], "vault", frozenset({"name"}))
    connect = _object(fields["connect"], "connect", frozenset({"direct_url", "tunnel_url"}))
    keychain = _object(
        fields["keychain"],
        "keychain",
        frozenset({"connect_service", "bastion_service"}),
    )
    vault_name = _string(vault["name"], "vault.name")
    if vault_name != _APPROVED_VAULT_NAME:
        raise ConfigError("vault.name must match the approved value")

    direct_connect_url = _string(connect["direct_url"], "connect.direct_url")
    if direct_connect_url != _APPROVED_DIRECT_CONNECT_URL:
        raise ConfigError("connect.direct_url must match the approved value")
    tunnel_connect_url = _string(connect["tunnel_url"], "connect.tunnel_url")
    if tunnel_connect_url != _APPROVED_TUNNEL_CONNECT_URL:
        raise ConfigError("connect.tunnel_url must match the approved value")
    connect_keychain_service = _string(
        keychain["connect_service"], "keychain.connect_service"
    )
    if connect_keychain_service != _APPROVED_CONNECT_KEYCHAIN_SERVICE:
        raise ConfigError("keychain.connect_service must match the approved value")
    bastion_keychain_service = _string(
        keychain["bastion_service"], "keychain.bastion_service"
    )
    if bastion_keychain_service != _APPROVED_BASTION_KEYCHAIN_SERVICE:
        raise ConfigError("keychain.bastion_service must match the approved value")

    forgejo = (
        _forgejo_identity(fields["forgejo"])
        if version == 2
        else _identity(fields["forgejo"], "forgejo")
    )
    _validate_forgejo_pins(forgejo)

    return AgentConfig(
        version=version,
        vault_name=vault_name,
        direct_connect_url=direct_connect_url,
        tunnel_connect_url=tunnel_connect_url,
        connect_keychain_service=connect_keychain_service,
        bastion_keychain_service=bastion_keychain_service,
        forgejo=forgejo,
        forgejo_automation=(
            _forgejo_automation(fields["forgejo_automation"])
            if version == 2
            else None
        ),
        bastion=_bastion(fields["bastion"]),
        targets=_targets(fields["targets"]),
        repositories=_repositories(fields["repositories"]),
        tools=_tools(fields["tools"], version),
    )

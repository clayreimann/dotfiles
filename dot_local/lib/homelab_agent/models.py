"""Immutable public configuration models for the Mac homelab agent."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Mapping


@dataclass(frozen=True)
class SshIdentity:
    host: str
    port: int
    user: str
    credential_item_id: str
    private_field: str
    expected_fingerprint: str
    known_host: str


@dataclass(frozen=True)
class ManagedTarget(SshIdentity):
    alias: str
    route: Literal["direct", "bastion"]


@dataclass(frozen=True)
class Bastion:
    host: str
    port: int
    user: str
    encrypted_key_path: Path
    known_host: str


@dataclass(frozen=True)
class Repository:
    name: str
    remote: str
    path: Path


@dataclass(frozen=True)
class AgentConfig:
    vault_name: str
    direct_connect_url: str
    tunnel_connect_url: str
    connect_keychain_service: str
    bastion_keychain_service: str
    forgejo: SshIdentity
    bastion: Bastion | None
    targets: Mapping[str, ManagedTarget]
    repositories: tuple[Repository, ...]
    tools: Mapping[str, str]

    def target(self, alias: str) -> ManagedTarget:
        try:
            return self.targets[alias]
        except KeyError as error:
            from .config import ConfigError

            raise ConfigError(f"unmapped target: {alias}") from error

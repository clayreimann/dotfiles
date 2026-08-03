"""Minimal, fail-closed 1Password Connect read client."""
from __future__ import annotations

import json
from typing import Protocol
from urllib.request import Request, urlopen

from .process import AgentError, Secret


_TIMEOUT_SECONDS = 20
_DEFAULT_VAULT_NAME = "Homelab Secrets"


class HttpTransport(Protocol):
    def open(self, request: Request, *, timeout: float) -> object: ...


class UrllibTransport:
    """Default urllib transport, separated to keep HTTP tests process-local."""

    def open(self, request: Request, *, timeout: float) -> object:
        return urlopen(request, timeout=timeout)


class ConnectClient:
    """Read a configured Connect vault without exposing access-token values."""

    def __init__(
        self,
        base_url: str,
        token: Secret,
        transport: HttpTransport | None = None,
        vault_name: str = _DEFAULT_VAULT_NAME,
    ) -> None:
        if vault_name != _DEFAULT_VAULT_NAME:
            raise AgentError("configured vault name is not approved")
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._transport = transport or UrllibTransport()
        self._vault_name = vault_name
        self._vault_id: str | None = None

    def health(self) -> None:
        """Check that Connect responds to its health endpoint."""
        self._request_json("/health", "Connect health check")

    def get_item(self, item_id: str) -> dict[str, object]:
        """Return the exact UUID-addressed item from the configured vault."""
        payload = self._request_json(
            f"/v1/vaults/{self._configured_vault_id()}/items/{item_id}",
            "Connect item lookup",
        )
        if not isinstance(payload, dict):
            raise AgentError("Connect item lookup returned an invalid item")
        return dict(payload)

    def get_string_field(self, item_id: str, label: str) -> Secret:
        """Return precisely one string field, otherwise stop without exposing values."""
        item = self.get_item(item_id)
        fields = item.get("fields")
        if not isinstance(fields, list):
            raise AgentError("Connect item has an invalid fields collection")
        matching = [
            field
            for field in fields
            if isinstance(field, dict) and field.get("label") == label
        ]
        if len(matching) != 1:
            raise AgentError("Connect item field is missing or ambiguous")
        value = matching[0].get("value")
        if not isinstance(value, str):
            raise AgentError("Connect item field is not a string")
        return Secret(value)

    def _configured_vault_id(self) -> str:
        if self._vault_id is not None:
            return self._vault_id
        payload = self._request_json("/v1/vaults", "Connect vault discovery")
        if not isinstance(payload, list):
            raise AgentError("configured vault is unavailable")
        matching = [
            vault
            for vault in payload
            if isinstance(vault, dict) and vault.get("name") == self._vault_name
        ]
        if not matching:
            raise AgentError("configured vault is unavailable")
        if len(matching) != 1:
            raise AgentError("configured vault is ambiguous")
        vault_id = matching[0].get("id")
        if not isinstance(vault_id, str) or not vault_id:
            raise AgentError("configured vault is unavailable")
        self._vault_id = vault_id
        return vault_id

    def _request_json(self, path: str, operation: str) -> object:
        try:
            request = Request(
                f"{self._base_url}{path}",
                headers={
                    "Authorization": f"Bearer {self._token.reveal()}",
                    "Accept": "application/json",
                },
            )
            with self._transport.open(request, timeout=_TIMEOUT_SECONDS) as response:  # type: ignore[union-attr]
                return json.loads(response.read().decode("utf-8"))  # type: ignore[union-attr]
        except Exception:
            raise AgentError(f"{operation} failed") from None

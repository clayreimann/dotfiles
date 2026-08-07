"""Minimal, fail-closed 1Password Connect client."""
from __future__ import annotations

import json
from typing import Mapping, Protocol
from urllib.error import HTTPError
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


def _connect_error_detail(error: HTTPError) -> str:
    """Best-effort `HTTP <code> (<message>)` detail; never raises, never guesses."""
    try:
        body = json.loads(error.read().decode("utf-8"))
    except Exception:
        return f"HTTP {error.code}"
    message = body.get("message") if isinstance(body, dict) else None
    if isinstance(message, str) and message:
        return f"HTTP {error.code} ({message})"
    return f"HTTP {error.code}"


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
        self._vault: dict[str, object] | None = None

    def health(self) -> None:
        """Check that Connect responds to its health endpoint."""
        self._request_json("GET", "/health", "Connect health check")

    def get_item(self, item_id: str) -> dict[str, object]:
        """Return the exact UUID-addressed item from the configured vault."""
        payload = self._request_json(
            "GET",
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

    def get_vault(self) -> dict[str, object]:
        """Return the configured vault as a single object (`op vault get`'s REST equivalent).

        Goes through `_configured_vault()`, so this can never return a vault
        other than the one approved, exact-name match.
        """
        return dict(self._configured_vault())

    def list_vaults(self) -> list[dict[str, object]]:
        """Return the configured vault only, in the same shape Connect uses."""
        return [self.get_vault()]

    def list_items(self) -> list[dict[str, object]]:
        """Return the item summaries in the configured vault (`op item list`'s REST equivalent)."""
        payload = self._request_json(
            "GET",
            f"/v1/vaults/{self._configured_vault_id()}/items",
            "Connect item list",
        )
        if not isinstance(payload, list):
            raise AgentError("Connect item list returned an invalid response")
        return list(payload)

    def create_item(self, payload: Mapping[str, object]) -> dict[str, object]:
        """Create an item; the caller supplies category/fields, we pin the vault."""
        body = dict(payload)
        body["vault"] = {"id": self._configured_vault_id()}
        result = self._request_json(
            "POST",
            f"/v1/vaults/{self._configured_vault_id()}/items",
            "Connect item create",
            body,
        )
        if not isinstance(result, dict):
            raise AgentError("Connect item create returned an invalid item")
        return dict(result)

    def update_item(self, item_id: str, payload: Mapping[str, object]) -> dict[str, object]:
        """Replace an item's contents; the caller supplies the full body, we pin the vault.

        Connect's PUT replaces the whole item, unlike `op item edit`'s partial
        field update. Callers of the approved `item edit ITEM_UUID` form must
        send the complete item body on stdin, not a patch -- a partial body
        here will silently drop whatever fields it omits.
        """
        body = dict(payload)
        body["vault"] = {"id": self._configured_vault_id()}
        result = self._request_json(
            "PUT",
            f"/v1/vaults/{self._configured_vault_id()}/items/{item_id}",
            "Connect item edit",
            body,
        )
        if not isinstance(result, dict):
            raise AgentError("Connect item edit returned an invalid item")
        return dict(result)

    def _configured_vault(self) -> dict[str, object]:
        if self._vault is not None:
            return self._vault
        payload = self._request_json("GET", "/v1/vaults", "Connect vault discovery")
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
        self._vault = matching[0]
        return self._vault

    def _configured_vault_id(self) -> str:
        vault_id = self._configured_vault().get("id")
        if not isinstance(vault_id, str) or not vault_id:
            raise AgentError("configured vault is unavailable")
        return vault_id

    def _request_json(
        self,
        method: str,
        path: str,
        operation: str,
        body: Mapping[str, object] | None = None,
    ) -> object:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {
            "Authorization": f"Bearer {self._token.reveal()}",
            "Accept": "application/json",
        }
        if data is not None:
            headers["Content-Type"] = "application/json"
        try:
            request = Request(
                f"{self._base_url}{path}",
                data=data,
                headers=headers,
                method=method,
            )
            with self._transport.open(request, timeout=_TIMEOUT_SECONDS) as response:  # type: ignore[union-attr]
                raw = response.read()  # type: ignore[union-attr]
            return json.loads(raw.decode("utf-8")) if raw else None
        except HTTPError as error:
            # The status code and Connect's `message` field are diagnostics, not
            # secrets -- surfacing them is what makes an `op`-over-Connect
            # rejection ("doesn't work with Connect", missing required field,
            # wrong output format) debuggable instead of a generic failure.
            raise AgentError(f"{operation} failed: {_connect_error_detail(error)}") from None
        except Exception:
            raise AgentError(f"{operation} failed") from None

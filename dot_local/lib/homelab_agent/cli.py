"""Desktop-safe command dispatch for the Mac homelab agent."""
from __future__ import annotations

import os
import sys
from collections.abc import Callable, Sequence
from typing import Any

from .config import load_config
from .connect import ConnectClient
from .keychain import Keychain
from .process import AgentError
from .ssh_session import EphemeralAgent, run_pinned_ssh


def _connect_url(config: Any) -> str:
    supplied = os.environ.get("HOMELAB_AGENT_CONNECT_URL")
    if supplied is None:
        return config.direct_connect_url
    if supplied not in {config.direct_connect_url, config.tunnel_connect_url}:
        raise AgentError("Connect URL is not approved")
    return supplied


def main(
    argv: Sequence[str] | None = None,
    *,
    load: Callable[[], Any] = load_config,
    keychain_factory: Callable[[], Keychain] = Keychain,
    connect_factory: Callable[..., ConnectClient] = ConnectClient,
    transport: Callable[..., int] = run_pinned_ssh,
) -> int:
    """Dispatch the Git SSH wrapper without exposing credential values."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments[0] != "forgejo-ssh":
        print("usage: homelab-agent forgejo-ssh -- <git-supplied ssh args>", file=sys.stderr)
        return 2
    if len(arguments) < 3 or arguments[1] != "--":
        print("usage: homelab-agent forgejo-ssh -- <git-supplied ssh args>", file=sys.stderr)
        return 2

    try:
        config = load()
        keychain = keychain_factory()
        token = keychain.read(config.connect_keychain_service, keychain.local_account())
        client = connect_factory(
            _connect_url(config), token, vault_name=config.vault_name
        )
        return transport(
            config.forgejo,
            arguments[2:],
            agent=EphemeralAgent(client),
        )
    except AgentError as error:
        print(f"homelab-agent: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

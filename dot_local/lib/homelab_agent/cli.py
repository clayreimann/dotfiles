"""Desktop-safe command dispatch for the Mac homelab agent."""
from __future__ import annotations

import os
import sys
from collections.abc import Callable, Sequence
from typing import Any, Mapping, TextIO

from .config import ConfigError, load_config
from .connect import ConnectClient
from .keychain import Keychain
from .process import AgentError
from .ssh_session import ConnectRoute, EphemeralAgent, run_pinned_ssh, run_target_ssh


def _valid_invocation(arguments: Sequence[str]) -> bool:
    if arguments == ["askpass"]:
        return True
    if arguments and arguments[0] == "forgejo-ssh":
        return len(arguments) >= 3 and arguments[1] == "--"
    if arguments and arguments[0] == "ssh":
        return len(arguments) >= 4 and arguments[2] == "--"
    return False


def _usage(arguments: Sequence[str]) -> str:
    if arguments and arguments[0] == "ssh":
        return "usage: homelab-agent ssh TARGET -- COMMAND..."
    return "usage: homelab-agent forgejo-ssh -- <git-supplied ssh args>"


def _askpass(
    *,
    load: Callable[[], Any],
    keychain_factory: Callable[[], Keychain],
    environ: Mapping[str, str],
    output: TextIO,
) -> int:
    service = environ.get("HOMELAB_AGENT_ASKPASS_SERVICE", "")
    account = environ.get("HOMELAB_AGENT_ASKPASS_ACCOUNT", "")
    if not service or not account:
        raise AgentError("bastion askpass Keychain reference is invalid")
    config = load()
    keychain = keychain_factory()
    local_account = keychain.local_account()
    if service != config.bastion_keychain_service or account != local_account:
        raise AgentError("bastion askpass Keychain reference is not approved")
    passphrase = keychain.read(service, account)
    output.write(passphrase.reveal())
    output.write("\n")
    output.flush()
    return 0


def run(
    argv: Sequence[str],
    *,
    load: Callable[[], Any] = load_config,
    keychain_factory: Callable[[], Keychain] = Keychain,
    connect_factory: Callable[..., ConnectClient] = ConnectClient,
    transport: Callable[..., int] = run_pinned_ssh,
    target_transport: Callable[..., int] = run_target_ssh,
    route_factory: Callable[..., ConnectRoute] = ConnectRoute,
    environ: Mapping[str, str] = os.environ,
    output: TextIO = sys.stdout,
) -> int:
    """Run one validated command, allowing callers to test fail-closed errors."""
    arguments = list(argv)
    if not _valid_invocation(arguments):
        raise AgentError("invalid homelab-agent invocation")
    if arguments == ["askpass"]:
        return _askpass(
            load=load,
            keychain_factory=keychain_factory,
            environ=environ,
            output=output,
        )

    config = load()
    target = None
    if arguments[0] == "ssh":
        # Resolve the public allowlist before touching either Keychain secret.
        target = config.target(arguments[1])

    keychain = keychain_factory()
    account = keychain.local_account()
    token = keychain.read(config.connect_keychain_service, account)
    route = route_factory(
        keychain=keychain,
        token=token,
        account=account,
        connect_factory=connect_factory,
    )
    with route.open(config) as connect_url:
        client = connect_factory(
            connect_url, token, vault_name=config.vault_name
        )
        agent = EphemeralAgent(client)
        if arguments[0] == "forgejo-ssh":
            return transport(config.forgejo, arguments[2:], agent=agent)

        assert target is not None
        return target_transport(
            target,
            arguments[3:],
            agent=agent,
            bastion=config.bastion,
            bastion_keychain_service=config.bastion_keychain_service,
            keychain_account=account,
        )


def main(
    argv: Sequence[str] | None = None,
    *,
    load: Callable[[], Any] = load_config,
    keychain_factory: Callable[[], Keychain] = Keychain,
    connect_factory: Callable[..., ConnectClient] = ConnectClient,
    transport: Callable[..., int] = run_pinned_ssh,
    target_transport: Callable[..., int] = run_target_ssh,
    route_factory: Callable[..., ConnectRoute] = ConnectRoute,
) -> int:
    """Dispatch the approved wrappers without exposing credential values."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not _valid_invocation(arguments):
        print(_usage(arguments), file=sys.stderr)
        return 2

    try:
        return run(
            arguments,
            load=load,
            keychain_factory=keychain_factory,
            connect_factory=connect_factory,
            transport=transport,
            target_transport=target_transport,
            route_factory=route_factory,
        )
    except (AgentError, ConfigError) as error:
        print(f"homelab-agent: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

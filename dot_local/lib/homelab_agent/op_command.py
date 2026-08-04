"""Narrow, vault-pinned wrapper around the 1Password CLI."""
from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable, Sequence
from typing import Any, Mapping, TextIO

from .config import load_config
from .keychain import Keychain
from .process import AgentError, ProcessSpec, Runner, Secret
from .ssh_session import ConnectRoute


_OP_PATH = "/opt/homebrew/bin/op"
_VAULT_NAME = "Homelab Secrets"
_LOCAL_OP_ENVIRONMENT = frozenset(
    {
        "OP_ACCOUNT",
        "OP_CONFIG_DIR",
        "OP_CONNECT_HOST",
        "OP_CONNECT_TOKEN",
        "OP_SERVICE_ACCOUNT_TOKEN",
        "OP_SESSION",
    }
)


class UsageError(AgentError):
    """A rejected command that must not read credentials."""


def _usage(message: str) -> UsageError:
    return UsageError(message)


def _valid_item_uuid(value: str) -> bool:
    return (
        len(value) == 26
        and value.isascii()
        and value.isalnum()
        and value == value.lower()
    )


def validate_op_argv(argv: Sequence[str]) -> tuple[str, ...]:
    """Return a public, vault-pinned `op` command or reject it before Keychain."""
    arguments = tuple(argv)
    if not arguments or any(not argument for argument in arguments):
        raise _usage("operation is not supported")
    if any(argument.endswith("[delete]") for argument in arguments):
        raise _usage("field deletion is not supported")

    if arguments[:2] == ("item", "create"):
        if len(arguments) < 3 or arguments[2] != "-":
            raise _usage("item create requires JSON on stdin with item create -")
        if arguments != ("item", "create", "-"):
            raise _usage("item create requires the exact stdin-only form: item create -")
        return (*arguments, "--vault", _VAULT_NAME)

    if arguments[:2] == ("item", "edit"):
        if len(arguments) < 3 or not _valid_item_uuid(arguments[2]):
            raise _usage("item edit requires a 26-character item UUID")
        if len(arguments) != 3:
            raise _usage("item edit requires the exact stdin-only form: item edit ITEM_UUID")
        return (*arguments, "--vault", _VAULT_NAME)

    if arguments == ("vault", "list"):
        return ("vault", "list", "--format", "json")
    if arguments == ("vault", "get", _VAULT_NAME):
        return arguments
    if arguments == ("item", "list"):
        return (*arguments, "--vault", _VAULT_NAME)
    if (
        len(arguments) == 3
        and arguments[:2] == ("item", "get")
        and not arguments[2].startswith("-")
        and "=" not in arguments[2]
    ):
        return (*arguments, "--vault", _VAULT_NAME)
    if len(arguments) == 2 and arguments[0] == "read":
        if arguments[1].startswith(f"op://{_VAULT_NAME}/"):
            return arguments
        raise _usage("only the Homelab Secrets vault is supported")
    raise _usage("operation is not supported")


def _json_stdin(arguments: Sequence[str], stdin: TextIO) -> Secret | None:
    mutating = len(arguments) >= 2 and arguments[:2] in (("item", "create"), ("item", "edit"))
    if not mutating:
        return None
    payload = stdin.read()
    operation = " ".join(arguments[:2])
    try:
        decoded = json.loads(payload)
    except json.JSONDecodeError:
        raise _usage(f"{operation} requires JSON on stdin") from None
    if not isinstance(decoded, dict):
        raise _usage(f"{operation} requires JSON on stdin")
    return Secret(payload)


def _op_environment_to_unset(environ: Mapping[str, str]) -> tuple[str, ...]:
    names = _LOCAL_OP_ENVIRONMENT | {
        name for name in environ if name.startswith("OP_")
    }
    return tuple(sorted(names))


def _scoped_vault_list(payload: str) -> str:
    try:
        decoded = json.loads(payload)
    except json.JSONDecodeError:
        raise AgentError("vault list did not return valid JSON") from None
    if not isinstance(decoded, list):
        raise AgentError("vault list did not return valid JSON")
    matches = [
        entry
        for entry in decoded
        if isinstance(entry, dict) and entry.get("name") == _VAULT_NAME
    ]
    if len(matches) != 1:
        raise AgentError("vault list did not return exactly one exact Homelab Secrets vault")
    return json.dumps(matches[0]) + "\n"


def run_op(
    argv: Sequence[str],
    *,
    load: Callable[[], Any] = load_config,
    keychain_factory: Callable[[], Keychain] = Keychain,
    route_factory: Callable[..., ConnectRoute] = ConnectRoute,
    runner: Runner | None = None,
    stdin: TextIO = sys.stdin,
    output: TextIO = sys.stdout,
) -> int:
    """Run an approved `op` command with Connect credentials scoped to its child."""
    arguments = validate_op_argv(argv)
    json_input = _json_stdin(arguments, stdin)
    config = load()
    if config.vault_name != _VAULT_NAME:
        raise _usage("only the Homelab Secrets vault is supported")

    keychain = keychain_factory()
    account = keychain.local_account()
    token = keychain.read(config.connect_keychain_service, account)
    route = route_factory(keychain=keychain, token=token, account=account)
    command_runner = runner or Runner()
    with route.open(config) as connect_url:
        completed = command_runner.run(
            ProcessSpec(
                argv=(_OP_PATH, *arguments),
                stdin=json_input,
                env_overlay={
                    "OP_CONNECT_HOST": connect_url,
                    "OP_CONNECT_TOKEN": token.reveal(),
                },
                unset_env=_op_environment_to_unset(os.environ),
                display_name="approved 1Password command",
            )
        )
    if arguments[:2] == ("vault", "list"):
        output.write(_scoped_vault_list(completed.stdout or ""))
    elif arguments[:2] not in (("item", "create"), ("item", "edit")):
        output.write(completed.stdout or "")
    output.flush()
    return 0

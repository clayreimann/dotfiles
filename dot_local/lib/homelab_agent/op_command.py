"""Narrow, vault-pinned wrapper around the 1Password CLI."""
from __future__ import annotations

import json
import sys
from collections.abc import Callable, Sequence
from typing import Any, TextIO

from .config import load_config
from .keychain import Keychain
from .process import AgentError, ProcessSpec, Runner, Secret
from .ssh_session import ConnectRoute


_OP_PATH = "/opt/homebrew/bin/op"
_VAULT_NAME = "Homelab Secrets"
_CONNECT_ENVIRONMENT = ("OP_CONNECT_HOST", "OP_CONNECT_TOKEN")


class UsageError(AgentError):
    """A rejected command that must not read credentials."""


def _usage(message: str) -> UsageError:
    return UsageError(message)


def _has_option(arguments: Sequence[str], name: str) -> bool:
    return any(argument == name or argument.startswith(f"{name}=") for argument in arguments)


def _vault_value(arguments: Sequence[str]) -> str | None:
    values: list[str] = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--vault":
            if index + 1 >= len(arguments):
                raise _usage("--vault requires Homelab Secrets")
            values.append(arguments[index + 1])
            index += 2
            continue
        if argument.startswith("--vault="):
            values.append(argument.removeprefix("--vault="))
        index += 1
    if not values:
        return None
    if any(value != _VAULT_NAME for value in values):
        raise _usage("only the Homelab Secrets vault is supported")
    return _VAULT_NAME


def _reject_unsafe_arguments(arguments: Sequence[str]) -> None:
    if not arguments or any(not argument for argument in arguments):
        raise _usage("operation is not supported")
    if any("=" in argument and not argument.startswith("--vault=") for argument in arguments):
        raise _usage("assignment statements are not supported")
    for option in ("--template", "--reveal", "--connect-host", "--connect-token"):
        if _has_option(arguments, option):
            raise _usage(f"{option} is not supported")
    _vault_value(arguments)


def _without_vault(arguments: Sequence[str]) -> tuple[str, ...]:
    result: list[str] = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument == "--vault":
            index += 2
            continue
        if argument.startswith("--vault="):
            index += 1
            continue
        result.append(argument)
        index += 1
    return tuple(result)


def validate_op_argv(argv: Sequence[str]) -> tuple[str, ...]:
    """Return a public, vault-pinned `op` command or reject it before Keychain."""
    arguments = tuple(argv)
    if len(arguments) >= 2 and arguments[:2] == ("item", "create") and (
        len(arguments) < 3 or arguments[2] != "-"
    ):
        raise _usage("item create requires JSON on stdin with item create -")
    _reject_unsafe_arguments(arguments)
    command = _without_vault(arguments)

    if command[0] == "read":
        if len(command) < 2 or not command[1].startswith(f"op://{_VAULT_NAME}/"):
            raise _usage("only the Homelab Secrets vault is supported")
        return command
    elif command[0] == "vault":
        if len(command) < 2 or command[1] not in {"list", "get"}:
            raise _usage("operation is not supported")
        if command[1] == "get" and (len(command) < 3 or command[2] != _VAULT_NAME):
            raise _usage("only the Homelab Secrets vault is supported")
        return command
    elif command[0] == "item":
        if len(command) < 2 or command[1] not in {"list", "get", "create", "edit"}:
            raise _usage("operation is not supported")
        if command[1] == "create" and (len(command) < 3 or command[2] != "-"):
            raise _usage("item create requires JSON on stdin with item create -")
        if command[1] == "edit":
            if (
                len(command) < 3
                or len(command[2]) != 26
                or not command[2].isascii()
                or not command[2].isalnum()
                or command[2] != command[2].lower()
            ):
                raise _usage("item edit requires a 26-character item UUID")
    else:
        raise _usage("operation is not supported")

    return (*command, "--vault", _VAULT_NAME)


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


def run_op(
    argv: Sequence[str],
    *,
    load: Callable[[], Any] = load_config,
    keychain_factory: Callable[[], Keychain] = Keychain,
    route_factory: Callable[..., ConnectRoute] = ConnectRoute,
    runner: Runner | None = None,
    stdin: TextIO = sys.stdin,
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
        command_runner.run(
            ProcessSpec(
                argv=(_OP_PATH, *arguments),
                stdin=json_input,
                env_overlay={
                    "OP_CONNECT_HOST": connect_url,
                    "OP_CONNECT_TOKEN": token.reveal(),
                },
                unset_env=_CONNECT_ENVIRONMENT,
                display_name="approved 1Password command",
            )
        )
    return 0

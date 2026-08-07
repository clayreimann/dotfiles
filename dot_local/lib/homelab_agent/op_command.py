"""Narrow, vault-pinned wrapper around the 1Password CLI."""
from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable, Sequence
from typing import Any, Mapping, TextIO

from .config import load_config
from .connect import ConnectClient
from .keychain import Keychain
from .process import AgentError, ProcessSpec, Runner, Secret
from .ssh_session import ConnectRoute


_OP_PATH = "/opt/homebrew/bin/op"
_VAULT_NAME = "Homelab Secrets"

# `op` refuses these subcommands against a Connect server ("doesn't work with
# Connect" / wrong output format) even though the Connect REST API supports
# all of them -- see ConnectClient. `vault get` shares the same "op vault get"
# subcommand as `vault list` (which is rewritten to it), so it fails the same
# way and is routed the same way. `read` and `item get` are left on the CLI
# because they work as-is (item get additionally gets --format=json appended
# below, which Connect requires).
_REST_ROUTED_PREFIXES = (
    ("vault", "list"),
    ("vault", "get"),
    ("item", "list"),
    ("item", "create"),
    ("item", "edit"),
)
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
        return ("vault", "get", _VAULT_NAME, "--format", "json")
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
        # Connect only serves item get in JSON output; this changes op's
        # human-formatted stdout to JSON, which is intended.
        return (*arguments, "--vault", _VAULT_NAME, "--format", "json")
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


def _item_payload_with_category(json_input: Secret | None, operation: str) -> dict[str, object]:
    """Decode the stdin JSON `_json_stdin` already validated and require a category.

    Connect maps `category` to the item's `templateUuid`; without it the API
    400s. This runs before Keychain/Connect access (same fail-closed spot as
    `_json_stdin`'s shape check), so a missing category never costs a request.
    """
    payload = json.loads(json_input.reveal()) if json_input is not None else {}
    if not isinstance(payload.get("category"), str) or not payload["category"]:
        raise _usage(f"{operation} requires a category field in the item JSON")
    return payload


def _run_rest(
    caller_arguments: tuple[str, ...],
    client: ConnectClient,
    item_payload: dict[str, object] | None,
) -> str:
    """Serve the op-over-Connect-unsupported commands over the REST API."""
    if caller_arguments == ("vault", "list"):
        return json.dumps(client.list_vaults()) + "\n"
    if caller_arguments == ("vault", "get", _VAULT_NAME):
        # Object, not array: `vault get` is single-item op-CLI syntax, distinct
        # from `vault list`'s array shape even though both resolve to the one
        # approved vault.
        return json.dumps(client.get_vault()) + "\n"
    if caller_arguments == ("item", "list"):
        return json.dumps(client.list_items()) + "\n"
    if caller_arguments[:2] == ("item", "create"):
        if item_payload is None:
            raise AgentError("item create is missing its decoded payload")
        return json.dumps(client.create_item(item_payload)) + "\n"
    if caller_arguments[:2] == ("item", "edit"):
        if item_payload is None:
            raise AgentError("item edit is missing its decoded payload")
        return json.dumps(client.update_item(caller_arguments[2], item_payload)) + "\n"
    raise AgentError("operation is not supported")  # unreachable: gated by _REST_ROUTED_PREFIXES


def run_op(
    argv: Sequence[str],
    *,
    load: Callable[[], Any] = load_config,
    keychain_factory: Callable[[], Keychain] = Keychain,
    route_factory: Callable[..., ConnectRoute] = ConnectRoute,
    runner: Runner | None = None,
    connect_client_factory: Callable[..., ConnectClient] = ConnectClient,
    stdin: TextIO = sys.stdin,
    output: TextIO = sys.stdout,
) -> int:
    """Run an approved `op`/Connect command with credentials scoped to its call."""
    caller_arguments = tuple(argv)
    arguments = validate_op_argv(caller_arguments)
    json_input = _json_stdin(arguments, stdin)
    # Decode and validate the item payload here, before Keychain/Connect
    # access, so a missing category (like malformed stdin JSON above) is
    # rejected without spending a credential read or a doomed HTTP request.
    item_payload: dict[str, object] | None = None
    if caller_arguments[:2] in (("item", "create"), ("item", "edit")):
        item_payload = _item_payload_with_category(json_input, " ".join(caller_arguments[:2]))
    config = load()
    if config.vault_name != _VAULT_NAME:
        raise _usage("only the Homelab Secrets vault is supported")

    keychain = keychain_factory()
    account = keychain.local_account()
    token = keychain.read(config.connect_keychain_service, account)
    route = route_factory(keychain=keychain, token=token, account=account)
    with route.open(config) as connect_url:
        if caller_arguments[:2] in _REST_ROUTED_PREFIXES:
            client = connect_client_factory(connect_url, token, vault_name=_VAULT_NAME)
            output.write(_run_rest(caller_arguments, client, item_payload))
            output.flush()
            return 0

        command_runner = runner or Runner()
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
                # op's contract is that secret values go to stdout and
                # diagnostics go to stderr, so forwarding stderr here is safe
                # -- it's what makes op-over-Connect rejections diagnosable.
                # The ssh/git/tea call sites keep the strict default because
                # they don't share that stdout/stderr invariant.
                forward_stderr=True,
            )
        )
    output.write(completed.stdout or "")
    output.flush()
    return 0

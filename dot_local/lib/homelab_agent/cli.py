"""Desktop-safe command dispatch for the Mac homelab agent."""
from __future__ import annotations

import os
import sys
from collections.abc import Callable, Sequence
from typing import Any, Mapping, TextIO

from .config import ConfigError, load_config
from .connect import ConnectClient
from .doctor import CheckResult, enroll_keychain, run_doctor
from .git_command import run_git
from .keychain import Keychain
from .op_command import run_op
from .process import AgentError
from .ssh_session import ConnectRoute, EphemeralAgent, run_pinned_ssh, run_target_ssh
from .tea_session import run_tea
from .forgejo_policy import run_authenticated_forgejo


_MAIN_HELP = """usage: homelab-agent <command>

Commands:
  doctor [--live]
  enroll connect-token|bastion-passphrase
  git clone NAME|clone-foundation|configure PATH|fetch NAME
  ssh TARGET -- COMMAND...
  op <approved 1Password command>
  tea -- TEA_ARGS...
  forgejo checks|deploy <approved Forgejo policy command>
"""
_GIT_HELP = """usage: homelab-agent-git clone NAME|clone-foundation|configure PATH|fetch NAME

Approved commands:
  clone NAME
  clone-foundation
  configure PATH
  fetch NAME
"""
_SSH_HELP = """usage: homelab-agent-ssh TARGET -- COMMAND...

TARGET is one configured host alias. COMMAND is passed as an argument list to
that host; the helper does not accept host, user, port, or identity overrides.
"""
_OP_HELP = """usage: homelab-agent-op COMMAND

Approved commands (Homelab Secrets only):
  vault list
  vault get Homelab Secrets
  item list
  item get ITEM_IDENTIFIER
  item create -                 # JSON object on stdin
  item edit ITEM_UUID            # JSON object on stdin
  read op://Homelab Secrets/ITEM/FIELD

Item deletion is intentionally unsupported. Create and edit accept no flags or
assignments; provide the complete JSON object on standard input.
"""
_TEA_HELP = """usage: homelab-agent-tea -- TEA_ARGS...

TEA_ARGS are passed unchanged to Tea after ephemeral authentication to the
approved Forgejo server.
"""
_FORGEJO_HELP = """usage: homelab-agent-forgejo COMMAND

Approved commands:
  checks status infra SHA
  checks wait infra SHA [--timeout SECONDS]
  deploy stacks --target-host HOST --reason TEXT --confirm apply [--stacks CSV] [--post-deploy-configure]
  deploy status RUN_ID
  deploy wait RUN_ID [--timeout SECONDS]
"""


def _help(arguments: Sequence[str]) -> str | None:
    """Return public help before configuration, Keychain, or transport work."""
    if arguments == ["--help"]:
        return _MAIN_HELP
    if arguments == ["git", "--help"]:
        return _GIT_HELP
    if arguments == ["ssh", "--help"]:
        return _SSH_HELP
    if arguments == ["op", "--help"]:
        return _OP_HELP
    if arguments == ["tea", "--help"]:
        return _TEA_HELP
    if arguments == ["forgejo", "--help"]:
        return _FORGEJO_HELP
    return None


def _valid_invocation(arguments: Sequence[str]) -> bool:
    if arguments == ["askpass"]:
        return True
    if arguments and arguments[0] == "forgejo-ssh":
        return len(arguments) >= 3 and arguments[1] == "--"
    if arguments and arguments[0] == "ssh":
        return len(arguments) >= 4 and arguments[2] == "--"
    if arguments and arguments[0] == "op":
        return len(arguments) >= 2
    if arguments and arguments[0] == "tea":
        return len(arguments) >= 3 and arguments[1] == "--"
    if arguments and arguments[0] == "forgejo":
        return _valid_forgejo_invocation(arguments[1:])
    if arguments and arguments[0] == "git":
        return (
            len(arguments) == 2 and arguments[1] == "clone-foundation"
        ) or (
            len(arguments) == 3 and arguments[1] in {"clone", "configure", "fetch"}
        )
    if arguments in (["doctor"], ["doctor", "--live"]):
        return True
    if arguments in (["enroll", "connect-token"], ["enroll", "bastion-passphrase"]):
        return True
    return False


def _valid_forgejo_invocation(arguments: Sequence[str]) -> bool:
    """Reject policy widening before any credential setup occurs."""
    if len(arguments) == 4 and arguments[:2] == ["checks", "status"]:
        return True
    if len(arguments) in {4, 6} and arguments[:2] == ["checks", "wait"]:
        return len(arguments) == 4 or arguments[4] == "--timeout"
    if len(arguments) == 3 and arguments[:2] == ["deploy", "status"]:
        return True
    if len(arguments) in {3, 5} and arguments[:2] == ["deploy", "wait"]:
        return len(arguments) == 3 or arguments[3] == "--timeout"
    if arguments[:2] != ["deploy", "stacks"]:
        return False
    allowed = {"--target-host", "--reason", "--stacks", "--confirm", "--post-deploy-configure"}
    seen: set[str] = set()
    index = 2
    while index < len(arguments):
        option = arguments[index]
        if option not in allowed or option in seen:
            return False
        seen.add(option)
        if option == "--post-deploy-configure":
            index += 1
        elif index + 1 < len(arguments):
            if option == "--confirm" and arguments[index + 1] != "apply":
                return False
            index += 2
        else:
            return False
    return {"--target-host", "--reason", "--confirm"}.issubset(seen)


def _usage(arguments: Sequence[str]) -> str:
    if arguments and arguments[0] == "ssh":
        return "usage: homelab-agent ssh TARGET -- COMMAND..."
    if arguments and arguments[0] == "op":
        return "usage: homelab-agent op <approved 1Password command>"
    if arguments and arguments[0] == "tea":
        return "usage: homelab-agent tea -- TEA_ARGS..."
    if arguments and arguments[0] == "forgejo":
        return "usage: homelab-agent forgejo checks|deploy <approved Forgejo policy command>"
    if arguments and arguments[0] == "git":
        return "usage: homelab-agent git clone NAME|clone-foundation|configure PATH|fetch NAME"
    if arguments and arguments[0] == "doctor":
        return "usage: homelab-agent doctor [--live]"
    if arguments and arguments[0] == "enroll":
        return "usage: homelab-agent enroll connect-token|bastion-passphrase"
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
    op_runner: Callable[[Sequence[str]], int] = run_op,
    git_runner: Callable[[Sequence[str]], int] = run_git,
    tea_runner: Callable[[Sequence[str]], int] = run_tea,
    forgejo_runner: Callable[[Sequence[str]], int] | None = None,
    doctor_runner: Callable[[bool], Sequence[CheckResult]] | None = None,
    enroll_runner: Callable[[str], None] | None = None,
    output: TextIO | None = None,
    error_output: TextIO | None = None,
) -> int:
    """Dispatch the approved wrappers without exposing credential values."""
    actual_output = output or sys.stdout
    actual_error_output = error_output or sys.stderr
    arguments = list(sys.argv[1:] if argv is None else argv)
    help_text = _help(arguments)
    if help_text is not None:
        actual_output.write(help_text)
        actual_output.flush()
        return 0
    if not _valid_invocation(arguments):
        print(_usage(arguments), file=actual_error_output)
        return 2

    try:
        if arguments[0] == "doctor":
            live = arguments == ["doctor", "--live"]
            checks = (
                doctor_runner(live)
                if doctor_runner is not None
                else run_doctor(
                    live,
                    load=load,
                    keychain_factory=keychain_factory,
                    connect_factory=connect_factory,
                    route_factory=route_factory,
                )
            )
            for check in checks:
                print(_format_check(check), file=actual_output)
            return 0 if all(check.status == "PASS" for check in checks) else 1
        if arguments[0] == "enroll":
            config = load()
            service = (
                config.connect_keychain_service
                if arguments[1] == "connect-token"
                else config.bastion_keychain_service
            )
            if enroll_runner is not None:
                enroll_runner(service)
            else:
                enroll_keychain(service, load=load, keychain_factory=keychain_factory)
            return 0
        if arguments[0] == "op":
            return op_runner(arguments[1:])
        if arguments[0] == "git":
            return git_runner(arguments[1:])
        if arguments[0] == "tea":
            return tea_runner(arguments[2:])
        if arguments[0] == "forgejo":
            if forgejo_runner is not None:
                return forgejo_runner(arguments[1:])
            return run_authenticated_forgejo(arguments[1:], output=actual_output)
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
        print(f"homelab-agent: {error}", file=actual_error_output)
        return 1


def _format_check(check: CheckResult) -> str:
    """Render only established public text; never relay error strings from dependencies."""
    safe_details = {
        "required executable is unavailable",
        "required Python 3.12 is unavailable",
        "approved executable is available",
        "public configuration is approved",
        "public configuration is invalid",
        "local account is unavailable",
        "local account is available",
        "required item is unavailable",
        "required item is available",
        "live routing is unavailable",
        "Connect inspection is unavailable",
        "credential validation is unavailable",
        "host trust validation is unavailable",
        "server authorization is unavailable",
        "approved route is healthy",
        "approved vault is reachable",
        "approved vault access failed",
        "exact field and fingerprint are approved",
        "exact field or fingerprint is invalid",
        "pinned host key is approved",
        "pinned host key is invalid",
        "authentication was not attempted after host-trust failure",
        "authentication was not attempted after credential validation failure",
        "pinned authentication succeeded",
        "pinned authentication was rejected",
        "repository wiring is approved",
        "repository wiring is invalid",
    }
    detail = check.detail if check.detail in safe_details else "redacted diagnostic"
    return f"{check.status} {check.category} {check.name}: {detail}"


if __name__ == "__main__":
    raise SystemExit(main())

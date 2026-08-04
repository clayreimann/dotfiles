"""Narrow, fail-closed policy for the Forgejo 14 Actions endpoints."""
from __future__ import annotations

import re
import time
import math
from dataclasses import dataclass
from datetime import datetime
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Protocol, TextIO

from .process import AgentError
from .config import load_config
from .connect import ConnectClient
from .keychain import Keychain
from .ssh_session import ConnectRoute
from .tea_session import TeaSession


_KNOWN_STATES = frozenset({"waiting", "running", "success", "failure", "cancelled", "skipped", "blocked"})
_PENDING_STATES = frozenset({"pending", "waiting", "running", "blocked", "unknown"})
_FAILED_STATES = frozenset({"failure", "cancelled", "skipped"})
_STACK_NAME = re.compile(r"[a-z0-9][a-z0-9-]*\Z")
_COMMIT_SHA = re.compile(r"[0-9a-fA-F]{40}\Z")
_POLL_INTERVAL = 5.0
_PAGE_SIZE = 50


class PolicyError(AgentError):
    """The public Actions contract or policy allowlist was not satisfied."""


class ApiSession(Protocol):
    def api_json(self, arguments: Sequence[str], *, input_json: object | None = None) -> object: ...


@dataclass(frozen=True)
class WorkflowRun:
    workflow: str
    run_id: int | None
    state: str
    url: str | None


@dataclass(frozen=True)
class CheckStatus:
    state: str
    runs: tuple[WorkflowRun, ...]


@dataclass(frozen=True)
class DeployStatus:
    run_id: int
    state: str
    url: str


def _request(session: ApiSession, arguments: Sequence[str], *, input_json: object | None = None) -> object:
    try:
        return session.api_json(arguments, input_json=input_json)
    except (AgentError, ValueError, TypeError):
        raise PolicyError("Forgejo Actions request failed") from None


def _string(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise PolicyError("Forgejo Actions response was invalid")
    return value


def _commit_sha(value: object) -> str:
    if not isinstance(value, str) or not _COMMIT_SHA.fullmatch(value):
        raise PolicyError("Forgejo Actions response was invalid")
    return value.lower()


def _integer(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise PolicyError("Forgejo Actions response was invalid")
    return value


def _created(value: object) -> datetime:
    text = _string(value)
    normalized = f"{text[:-1]}+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        raise PolicyError("Forgejo Actions response was invalid") from None
    if parsed.tzinfo is None:
        raise PolicyError("Forgejo Actions response was invalid")
    return parsed


def _parse_run(value: object) -> tuple[str, int, str, str, str, datetime]:
    required = {"workflow_id", "id", "status", "html_url", "commit_sha", "created"}
    if not isinstance(value, dict) or not required.issubset(value):
        raise PolicyError("Forgejo Actions response was invalid")
    workflow = _string(value["workflow_id"])
    run_id = _integer(value["id"])
    status = _string(value["status"])
    url = _string(value["html_url"])
    commit_sha = _commit_sha(value["commit_sha"])
    created = _created(value["created"])
    return workflow, run_id, status, url, commit_sha, created


def _parse_workflow_runs(
    payload: object,
) -> tuple[tuple[tuple[str, int, str, str, str, datetime], ...], int | None]:
    if not isinstance(payload, dict) or "workflow_runs" not in payload:
        raise PolicyError("Forgejo Actions response was invalid")
    entries = payload["workflow_runs"]
    if not isinstance(entries, list):
        raise PolicyError("Forgejo Actions response was invalid")
    total_count = payload.get("total_count")
    if total_count is not None and (
        not isinstance(total_count, int) or isinstance(total_count, bool) or total_count < 0
    ):
        raise PolicyError("Forgejo Actions response was invalid")
    return tuple(_parse_run(value) for value in entries), total_count


def _require_checks_repository(automation: Any, repository: str) -> None:
    if repository != "infra" or getattr(automation, "repository", None) != "homelab/infra":
        raise PolicyError("required checks are available only for infra")


def _aggregate(runs: tuple[WorkflowRun, ...]) -> str:
    states = {run.state for run in runs}
    if states & _FAILED_STATES:
        return "failure"
    if states & _PENDING_STATES:
        return "pending"
    return "success"


def checks_status(session: ApiSession, automation: Any, repository: str, commit_sha: str) -> CheckStatus:
    """Return the latest known outcome for every pinned required workflow."""
    _require_checks_repository(automation, repository)
    if not isinstance(commit_sha, str) or not _COMMIT_SHA.fullmatch(commit_sha):
        raise PolicyError("commit SHA must be a 40-character hexadecimal commit ID")
    expected_sha = commit_sha.lower()
    entries: list[tuple[str, int, str, str, str, datetime]] = []
    page = 1
    expected_total: int | None = None
    while True:
        endpoint = (
            f"/repos/{automation.repository}/actions/runs?head_sha={expected_sha}"
            f"&event=pull_request&limit={_PAGE_SIZE}&page={page}"
        )
        page_entries, total_count = _parse_workflow_runs(_request(session, (endpoint,)))
        entries.extend(page_entries)
        if total_count is not None:
            if expected_total is None:
                expected_total = total_count
            elif total_count != expected_total:
                raise PolicyError("Forgejo Actions response was invalid")
            if len(entries) > expected_total or (not page_entries and len(entries) < expected_total):
                raise PolicyError("Forgejo Actions response was invalid")
            if len(entries) == expected_total:
                break
        elif len(page_entries) < _PAGE_SIZE:
            break
        page += 1
    newest: dict[str, tuple[int, str, str, datetime]] = {}
    required = set(automation.required_workflows)
    for workflow, run_id, status, url, sha, created in entries:
        if workflow not in required or sha != expected_sha:
            continue
        previous = newest.get(workflow)
        if previous is None or (created, run_id) > (previous[3], previous[0]):
            newest[workflow] = (run_id, status if status in _KNOWN_STATES else "unknown", url, created)
    result: list[WorkflowRun] = []
    for workflow in automation.required_workflows:
        selected = newest.get(workflow)
        if selected is None:
            result.append(WorkflowRun(workflow, None, "pending", None))
        else:
            result.append(WorkflowRun(workflow, selected[0], selected[1], selected[2]))
    checked = tuple(result)
    return CheckStatus(_aggregate(checked), checked)


def _timeout(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        raise PolicyError("timeout must be a non-negative number")
    return float(value)


def checks_wait(
    session: ApiSession, automation: Any, repository: str, commit_sha: str, *, timeout: object,
    clock: Callable[[], float] = time.monotonic, sleeper: Callable[[float], None] = time.sleep,
) -> CheckStatus:
    """Poll only the fixed checks endpoint until it is terminal or timed out."""
    deadline = clock() + _timeout(timeout)
    while True:
        result = checks_status(session, automation, repository, commit_sha)
        if result.state != "pending":
            return result
        remaining = deadline - clock()
        if remaining <= 0:
            return CheckStatus("timeout", result.runs)
        sleeper(min(_POLL_INTERVAL, remaining))


def _validate_deploy_options(
    automation: Any, *, target_host: object, reason: object, stacks: object,
    post_deploy_configure: object, repository: object, workflow: object, ref: object, confirm: object,
) -> tuple[str, str, str, str]:
    if repository is not None and repository != automation.repository:
        raise PolicyError("repository is not approved for deployment")
    if workflow is not None and workflow != automation.deploy_workflow:
        raise PolicyError("workflow is not approved for deployment")
    if ref is not None and ref != automation.deploy_ref:
        raise PolicyError("ref is not approved for deployment")
    if confirm != "apply":
        raise PolicyError("deployment confirmation must be the literal string apply")
    if not isinstance(target_host, str) or target_host not in automation.deploy_targets:
        raise PolicyError("target host is not approved for deployment")
    if not isinstance(reason, str) or not reason.strip():
        raise PolicyError("deployment reason must be non-empty")
    if stacks is None:
        stack_csv = ""
    elif not isinstance(stacks, str):
        raise PolicyError("stack selection is invalid")
    else:
        pieces = stacks.split(",")
        if not pieces or any(not _STACK_NAME.fullmatch(piece) for piece in pieces):
            raise PolicyError("stack selection is invalid")
        stack_csv = stacks
    if not isinstance(post_deploy_configure, bool):
        raise PolicyError("post-deploy configure must be a boolean")
    return target_host, reason, stack_csv, "true" if post_deploy_configure else "false"


def deploy_stacks(
    session: ApiSession, automation: Any, *, target_host: object, reason: object, stacks: object = None,
    post_deploy_configure: object = False, repository: object = None, workflow: object = None,
    ref: object = None, confirm: object = None,
) -> int:
    """Dispatch only the configured stacks workflow with explicit confirmation."""
    host, safe_reason, stack_csv, configure = _validate_deploy_options(
        automation, target_host=target_host, reason=reason, stacks=stacks,
        post_deploy_configure=post_deploy_configure, repository=repository,
        workflow=workflow, ref=ref, confirm=confirm,
    )
    endpoint = f"/repos/{automation.repository}/actions/workflows/{automation.deploy_workflow}/dispatches"
    payload = {
        "ref": automation.deploy_ref,
        "return_run_info": True,
        "inputs": {
            "confirm": confirm, "reason": safe_reason, "target_host": host,
            "target_stacks": stack_csv, "run_post_deploy_configure": configure,
        },
    }
    response = _request(session, (endpoint, "--method", "POST", "--data", "@-"), input_json=payload)
    if not isinstance(response, dict) or "id" not in response:
        raise PolicyError("Forgejo Actions response was invalid")
    return _integer(response["id"])


def deploy_status(session: ApiSession, automation: Any, run_id: object) -> DeployStatus:
    """Read one pinned deployment run without exposing environment approval."""
    run_number = _integer(run_id)
    workflow, returned_id, status, url, _sha, _created = _parse_run(
        _request(session, (f"/repos/{automation.repository}/actions/runs/{run_number}",))
    )
    if returned_id != run_number or workflow != automation.deploy_workflow:
        raise PolicyError("Forgejo Actions response was invalid")
    return DeployStatus(run_number, status if status in _KNOWN_STATES else "unknown", url)


def deploy_wait(
    session: ApiSession, automation: Any, run_id: object, *, timeout: object,
    clock: Callable[[], float] = time.monotonic, sleeper: Callable[[float], None] = time.sleep,
) -> DeployStatus:
    """Poll the sole deployment run while blocked and unknown states remain pending."""
    deadline = clock() + _timeout(timeout)
    while True:
        result = deploy_status(session, automation, run_id)
        if result.state not in _PENDING_STATES:
            return result
        remaining = deadline - clock()
        if remaining <= 0:
            return DeployStatus(result.run_id, "timeout", result.url)
        sleeper(min(_POLL_INTERVAL, remaining))


def format_checks_status(result: CheckStatus) -> str:
    lines = [f"checks {result.state}"]
    for run in result.runs:
        run_id = "-" if run.run_id is None else str(run.run_id)
        url = "-" if run.url is None else run.url
        lines.append(f"{run.workflow} {run.state} {run_id} {url}")
    return "\n".join(lines)


def format_deploy_status(result: DeployStatus) -> str:
    return f"deployment {result.run_id} {result.state} {result.url}"


def run_forgejo(
    arguments: Sequence[str], *, session: ApiSession, automation: Any, output: TextIO,
    clock: Callable[[], float] = time.monotonic, sleeper: Callable[[float], None] = time.sleep,
) -> int:
    """Parse the five public subcommands; no generic API grammar is accepted."""
    values = list(arguments)
    if len(values) == 4 and values[:2] == ["checks", "status"]:
        result = checks_status(session, automation, values[2], values[3])
        print(format_checks_status(result), file=output)
        return 0 if result.state == "success" else 1
    if len(values) in {4, 6} and values[:2] == ["checks", "wait"] and (len(values) == 4 or values[4] == "--timeout"):
        timeout = 300.0 if len(values) == 4 else _cli_timeout(values[5])
        result = checks_wait(session, automation, values[2], values[3], timeout=timeout, clock=clock, sleeper=sleeper)
        print(format_checks_status(result), file=output)
        return 0 if result.state == "success" else 1
    if len(values) == 3 and values[:2] == ["deploy", "status"]:
        result = deploy_status(session, automation, _cli_run_id(values[2]))
        print(format_deploy_status(result), file=output)
        return _deploy_exit_code(result)
    if len(values) in {3, 5} and values[:2] == ["deploy", "wait"] and (len(values) == 3 or values[3] == "--timeout"):
        timeout = 300.0 if len(values) == 3 else _cli_timeout(values[4])
        result = deploy_wait(session, automation, _cli_run_id(values[2]), timeout=timeout, clock=clock, sleeper=sleeper)
        print(format_deploy_status(result), file=output)
        return _deploy_exit_code(result)
    if values[:2] == ["deploy", "stacks"]:
        options = _deploy_cli_options(values[2:])
        run_id = deploy_stacks(session, automation, **options)
        print(f"deployment dispatched {run_id}", file=output)
        return 0
    raise PolicyError("invalid Forgejo policy invocation")


def _cli_timeout(value: str) -> float:
    try:
        return _timeout(float(value))
    except ValueError:
        raise PolicyError("timeout must be a non-negative number") from None


def _cli_run_id(value: str) -> int:
    if not value.isdecimal():
        raise PolicyError("run ID must be a positive integer")
    return _integer(int(value))


def _deploy_cli_options(values: Sequence[str]) -> dict[str, object]:
    result: dict[str, object] = {"post_deploy_configure": False}
    index = 0
    while index < len(values):
        option = values[index]
        if option == "--post-deploy-configure":
            if result["post_deploy_configure"] is not False:
                raise PolicyError("invalid Forgejo policy invocation")
            result["post_deploy_configure"] = True
            index += 1
            continue
        if option not in {"--target-host", "--reason", "--stacks", "--confirm"} or index + 1 >= len(values):
            raise PolicyError("invalid Forgejo policy invocation")
        key = option[2:].replace("-", "_")
        if key in result:
            raise PolicyError("invalid Forgejo policy invocation")
        result[key] = values[index + 1]
        index += 2
    if "target_host" not in result or "reason" not in result or "confirm" not in result:
        raise PolicyError("invalid Forgejo policy invocation")
    result.setdefault("stacks", None)
    return result


def _deploy_exit_code(result: DeployStatus) -> int:
    if result.state == "success":
        return 0
    return 1


def run_authenticated_forgejo(
    arguments: Sequence[str], *, load: Callable[[], Any] = load_config,
    keychain_factory: Callable[[], Keychain] = Keychain,
    connect_factory: Callable[..., ConnectClient] = ConnectClient,
    route_factory: Callable[..., ConnectRoute] = ConnectRoute,
    output: TextIO, client: ConnectClient | None = None,
    session_factory: Callable[..., TeaSession] = TeaSession,
    clock: Callable[[], float] = time.monotonic, sleeper: Callable[[float], None] = time.sleep,
) -> int:
    """Open the temporary Tea session only after the version-2 policy gate."""
    config = load()
    automation = getattr(config, "forgejo_automation", None)
    if getattr(config, "version", None) != 2 or automation is None:
        raise AgentError("Tea workflow policy requires credential map version 2")
    if client is not None:
        with session_factory(config.forgejo, client) as session:
            return run_forgejo(arguments, session=session, automation=automation, output=output, clock=clock, sleeper=sleeper)
    keychain = keychain_factory()
    account = keychain.local_account()
    token = keychain.read(config.connect_keychain_service, account)
    route = route_factory(keychain=keychain, token=token, account=account, connect_factory=connect_factory)
    with route.open(config) as connect_url:
        connected_client = connect_factory(connect_url, token, vault_name=config.vault_name)
        with session_factory(config.forgejo, connected_client) as session:
            return run_forgejo(arguments, session=session, automation=automation, output=output, clock=clock, sleeper=sleeper)

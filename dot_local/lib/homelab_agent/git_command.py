"""Narrow, durable Git operations for configured homelab repositories."""
from __future__ import annotations

from collections.abc import Callable, Sequence
import os
from pathlib import Path
from typing import Any

from .config import load_config
from .models import Repository
from .process import AgentError, ProcessSpec, Runner


GIT = "/usr/bin/git"
SSH_COMMAND = "/Users/clay/.local/bin/homelab-forgejo-ssh"


class UsageError(AgentError):
    """The requested Git operation is outside the small approved grammar."""


class GitError(AgentError):
    """A safe refusal to modify an unexpected repository destination."""


def _run(runner: Runner, argv: tuple[str, ...], display_name: str):
    """Run Git without inheriting any caller-controlled Git behavior."""
    return runner.run(
        ProcessSpec(
            argv=argv,
            unset_env=tuple(sorted(name for name in os.environ if name.startswith("GIT_"))),
            display_name=display_name,
        )
    )


def _normal_remote(remote: str) -> str:
    return remote.strip().rstrip("/")


def _check_repository(repository: Repository, *, runner: Runner) -> None:
    """Require an existing configured worktree with its expected origin."""
    path = repository.path
    if not path.exists() or not path.is_dir():
        raise GitError("configured repository destination is not an approved Git worktree")
    try:
        worktree = _run(
            runner,
            (GIT, "-C", str(path), "rev-parse", "--is-inside-work-tree"),
            "Git worktree check",
        )
    except AgentError:
        raise GitError("configured repository destination is not an approved Git worktree") from None
    if worktree.stdout.strip() != "true":
        raise GitError("configured repository destination is not an approved Git worktree")
    try:
        top_level = _run(
            runner,
            (GIT, "-C", str(path), "rev-parse", "--show-toplevel"),
            "Git worktree top-level check",
        )
    except AgentError:
        raise GitError("configured repository destination is not the top-level Git worktree") from None
    if Path(top_level.stdout.strip()).resolve() != path.resolve():
        raise GitError("configured repository destination is not the top-level Git worktree")
    try:
        origin = _run(
            runner,
            (GIT, "-C", str(path), "remote", "get-url", "origin"),
            "Git origin check",
        )
    except AgentError:
        raise GitError("configured repository origin does not match") from None
    if _normal_remote(origin.stdout) != _normal_remote(repository.remote):
        raise GitError("configured repository origin does not match")


def configure_repository(path: Path, *, runner: Runner | None = None) -> None:
    """Set the helper only in this repository's local Git configuration."""
    actual_runner = runner or Runner()
    _run(
        actual_runner,
        (GIT, "-C", str(path), "config", "--local", "core.sshCommand", SSH_COMMAND),
        "Git local transport configuration",
    )


def clone_repository(repository: Repository, *, runner: Runner | None = None) -> None:
    """Clone a missing configured repository or confirm its existing safe state."""
    actual_runner = runner or Runner()
    if repository.path.exists():
        _check_repository(repository, runner=actual_runner)
    else:
        _run(
            actual_runner,
            (
                GIT,
                "-c",
                f"core.sshCommand={SSH_COMMAND}",
                "clone",
                repository.remote,
                str(repository.path),
            ),
            "Git repository clone",
        )
    configure_repository(repository.path, runner=actual_runner)


def clone_foundation(
    *, load: Callable[[], Any] = load_config, runner: Runner | None = None
) -> None:
    """Clone configured foundation repositories in the declared configuration order."""
    actual_runner = runner or Runner()
    for repository in load().repositories:
        clone_repository(repository, runner=actual_runner)


def _repository_by_name(name: str, repositories: Sequence[Repository]) -> Repository:
    for repository in repositories:
        if repository.name == name:
            return repository
    raise UsageError("unknown repository")


def _repository_by_path(path: Path, repositories: Sequence[Repository]) -> Repository:
    resolved_path = path.resolve()
    for repository in repositories:
        if repository.path.resolve() == resolved_path:
            return repository
    raise UsageError("path must be a configured repository destination")


def run_git(
    argv: Sequence[str],
    *,
    load: Callable[[], Any] = load_config,
    runner: Runner | None = None,
) -> int:
    """Dispatch only declared clone, configure, and fetch operations."""
    arguments = tuple(argv)
    config = load()
    actual_runner = runner or Runner()
    if len(arguments) == 2 and arguments[0] == "clone":
        clone_repository(_repository_by_name(arguments[1], config.repositories), runner=actual_runner)
        return 0
    if arguments == ("clone-foundation",):
        for repository in config.repositories:
            clone_repository(repository, runner=actual_runner)
        return 0
    if len(arguments) == 2 and arguments[0] == "configure":
        repository = _repository_by_path(Path(arguments[1]), config.repositories)
        _check_repository(repository, runner=actual_runner)
        configure_repository(repository.path, runner=actual_runner)
        return 0
    if len(arguments) == 2 and arguments[0] == "fetch":
        repository = _repository_by_name(arguments[1], config.repositories)
        _check_repository(repository, runner=actual_runner)
        _run(
            actual_runner,
            (GIT, "-C", str(repository.path), "fetch"),
            "Git repository fetch",
        )
        return 0
    raise UsageError("usage: homelab-agent git clone NAME|clone-foundation|configure PATH|fetch NAME")

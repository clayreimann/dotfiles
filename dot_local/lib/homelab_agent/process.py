"""Small process boundary that keeps secret values out of diagnostics."""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Mapping


class AgentError(RuntimeError):
    """A fail-closed agent error whose message contains no child output."""


@dataclass(frozen=True)
class Secret:
    """A value that is revealed only at an explicit process boundary."""

    _value: str

    def reveal(self) -> str:
        return self._value

    def __str__(self) -> str:
        return "<redacted>"

    def __repr__(self) -> str:
        return "Secret(<redacted>)"


@dataclass(frozen=True)
class ProcessSpec:
    """A process invocation with a public diagnostic name."""

    argv: tuple[str, ...]
    stdin: Secret | str | None = None
    env_overlay: Mapping[str, str] = field(default_factory=dict)
    unset_env: tuple[str, ...] = ()
    pass_fds: tuple[int, ...] = ()
    display_name: str = "child process"


ProcessExecutor = Callable[..., subprocess.CompletedProcess[str]]


class Runner:
    """Run processes while exposing only public failure metadata."""

    def __init__(self, executor: ProcessExecutor = subprocess.run) -> None:
        self._executor = executor

    def run(self, spec: ProcessSpec) -> subprocess.CompletedProcess[str]:
        stdin = spec.stdin.reveal() if isinstance(spec.stdin, Secret) else spec.stdin
        environment = os.environ.copy()
        for name in spec.unset_env:
            environment.pop(name, None)
        environment.update(spec.env_overlay)
        try:
            completed = self._executor(
                spec.argv,
                input=stdin,
                text=True,
                capture_output=True,
                env=environment,
                pass_fds=spec.pass_fds,
            )
        except Exception:
            raise AgentError(f"{spec.display_name} could not be started") from None

        if completed.returncode != 0:
            raise AgentError(
                f"{spec.display_name} failed with exit status {completed.returncode}"
            )
        return completed

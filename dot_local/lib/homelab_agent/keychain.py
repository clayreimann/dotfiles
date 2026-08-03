"""Redacted macOS login-Keychain operations for machine-local secrets."""
from __future__ import annotations

from .process import AgentError, ProcessSpec, Runner, Secret


class Keychain:
    """Read and enroll generic-password values without putting them in argv."""

    def __init__(self, runner: Runner | None = None) -> None:
        self._runner = runner or Runner()

    def local_account(self) -> str:
        """Return the whitespace-normalized LocalHostName used as the account."""
        completed = self._runner.run(
            ProcessSpec(
                argv=("/usr/sbin/scutil", "--get", "LocalHostName"),
                display_name="local hostname lookup",
            )
        )
        account = completed.stdout.strip()
        if not account:
            raise AgentError("local hostname lookup returned no account")
        return account

    def read(self, service: str, account: str) -> Secret:
        """Read a generic-password value for the supplied public service/account."""
        completed = self._runner.run(
            ProcessSpec(
                argv=(
                    "/usr/bin/security",
                    "find-generic-password",
                    "-w",
                    "-s",
                    service,
                    "-a",
                    account,
                ),
                display_name="Keychain secret lookup",
            )
        )
        value = completed.stdout.rstrip("\r\n")
        if not value:
            raise AgentError("Keychain secret lookup returned no value")
        return Secret(value)

    def enroll(self, service: str, account: str) -> None:
        """Prompt macOS to create or replace an item without receiving its value."""
        self._runner.run(
            ProcessSpec(
                argv=(
                    "/usr/bin/security",
                    "add-generic-password",
                    "-U",
                    "-a",
                    account,
                    "-s",
                    service,
                    "-T",
                    "/usr/bin/security",
                    "-w",
                ),
                display_name="Keychain enrollment",
            )
        )

"""Behavioral coverage for the narrow Forgejo Actions policy."""
from __future__ import annotations

import io
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "dot_local" / "lib"))


AUTOMATION = SimpleNamespace(
    repository="homelab/infra",
    required_workflows=("validate.yml", "plan.yml"),
    deploy_workflow="infra-stacks-deploy.yml",
    deploy_ref="main",
    deploy_targets=("docker01", "monitor01"),
)
SHA = "a" * 40


def run(
    workflow_id: str,
    run_id: int,
    status: str,
    created: str,
    *,
    sha: str = SHA,
) -> dict[str, object]:
    return {
        "workflow_id": workflow_id,
        "id": run_id,
        "status": status,
        "html_url": f"https://git.example/runs/{run_id}",
        "commit_sha": sha,
        "created": created,
    }


class Session:
    def __init__(self, responses: list[object]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[tuple[str, ...], object | None]] = []

    def api_json(self, arguments, *, input_json=None):
        self.calls.append((tuple(arguments), input_json))
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


class ForgejoPolicyTests(unittest.TestCase):
    """A broken endpoint contract or policy widening must stop before mutation."""

    def test_check_status_selects_only_the_newest_matching_run_per_workflow(self) -> None:
        from homelab_agent.forgejo_policy import checks_status

        session = Session(
            [{"workflow_runs": [
                run("validate.yml", 11, "failure", "2026-08-03T01:00:00Z"),
                run("validate.yml", 12, "success", "2026-08-04T01:00:00Z"),
                run("plan.yml", 13, "running", "2026-08-04T01:00:00Z"),
                run("unapproved.yml", 14, "success", "2026-08-04T01:00:00Z"),
            ]}]
        )

        result = checks_status(session, AUTOMATION, "infra", SHA)

        self.assertEqual("pending", result.state)
        self.assertEqual([("validate.yml", 12, "success"), ("plan.yml", 13, "running")], [
            (item.workflow, item.run_id, item.state) for item in result.runs
        ])
        self.assertEqual(
            (f"/repos/homelab/infra/actions/runs?head_sha={SHA}&event=pull_request&limit=50",),
            session.calls[0][0],
        )

    def test_check_status_aggregates_missing_pending_success_and_terminal_failure(self) -> None:
        from homelab_agent.forgejo_policy import checks_status

        cases = {
            "missing": ({"workflow_runs": [run("validate.yml", 1, "success", "2026-08-04T01:00:00Z")]}, "pending"),
            "waiting": ({"workflow_runs": [run("validate.yml", 1, "waiting", "2026-08-04T01:00:00Z"), run("plan.yml", 2, "success", "2026-08-04T01:00:00Z")]}, "pending"),
            "success": ({"workflow_runs": [run("validate.yml", 1, "success", "2026-08-04T01:00:00Z"), run("plan.yml", 2, "success", "2026-08-04T01:00:00Z")]}, "success"),
            "failure": ({"workflow_runs": [run("validate.yml", 1, "failure", "2026-08-04T01:00:00Z"), run("plan.yml", 2, "success", "2026-08-04T01:00:00Z")]}, "failure"),
        }
        for name, (payload, expected) in cases.items():
            with self.subTest(name=name):
                self.assertEqual(expected, checks_status(Session([payload]), AUTOMATION, "infra", SHA).state)

    def test_bad_responses_and_tea_errors_are_redacted(self) -> None:
        from homelab_agent.forgejo_policy import PolicyError, checks_status
        from homelab_agent.process import AgentError

        bad_payloads = (
            {},
            {"workflow_runs": "not-a-list"},
            {"workflow_runs": [{"workflow_id": "validate.yml"}]},
            {"workflow_runs": [dict(run("validate.yml", 1, "success", "2026-08-04T01:00:00Z"), unexpected=True)]},
        )
        for payload in bad_payloads:
            with self.subTest(payload=payload), self.assertRaisesRegex(PolicyError, "Forgejo Actions response was invalid") as caught:
                checks_status(Session([payload]), AUTOMATION, "infra", SHA)
            self.assertNotIn("not-a-list", str(caught.exception))
        with self.assertRaisesRegex(PolicyError, "Forgejo Actions request failed") as caught:
            checks_status(Session([AgentError("api-token-fixture")]), AUTOMATION, "infra", SHA)
        self.assertNotIn("api-token-fixture", str(caught.exception))

    def test_wait_times_out_without_sleeping_past_its_deadline(self) -> None:
        from homelab_agent.forgejo_policy import checks_wait

        session = Session([
            {"workflow_runs": [run("validate.yml", 1, "waiting", "2026-08-04T01:00:00Z")]},
            {"workflow_runs": [run("validate.yml", 1, "waiting", "2026-08-04T01:00:00Z")]},
        ])
        clock = iter((0.0, 0.0, 5.0)).__next__
        sleeps: list[float] = []

        result = checks_wait(session, AUTOMATION, "infra", SHA, timeout=5, clock=clock, sleeper=sleeps.append)

        self.assertEqual("timeout", result.state)
        self.assertEqual([5.0], sleeps)

    def test_deploy_dispatch_has_only_the_fixed_endpoint_and_approved_inputs(self) -> None:
        from homelab_agent.forgejo_policy import deploy_stacks

        session = Session([{ "id": 82 }])
        run_id = deploy_stacks(
            session, AUTOMATION, target_host="docker01", reason="approved maintenance",
            stacks="traefik,authentik", post_deploy_configure=True,
        )

        self.assertEqual(82, run_id)
        self.assertEqual(
            ("/repos/homelab/infra/actions/workflows/infra-stacks-deploy.yml/dispatches", "--method", "POST", "--data", "@-"),
            session.calls[0][0],
        )
        self.assertEqual(
            {
                "ref": "main", "return_run_info": True,
                "inputs": {
                    "confirm": "apply", "reason": "approved maintenance", "target_host": "docker01",
                    "target_stacks": "traefik,authentik", "run_post_deploy_configure": "true",
                },
            },
            session.calls[0][1],
        )

    def test_deploy_rejects_all_unapproved_options_before_dispatch(self) -> None:
        from homelab_agent.forgejo_policy import PolicyError, deploy_stacks

        cases = (
            {"target_host": "router01", "reason": "reason"},
            {"target_host": "docker01", "reason": "   "},
            {"target_host": "docker01", "reason": "reason", "stacks": "traefik,,authentik"},
            {"target_host": "docker01", "reason": "reason", "stacks": "Traefik"},
            {"target_host": "docker01", "reason": "reason", "confirm": "no"},
            {"target_host": "docker01", "reason": "reason", "repository": "other/repo"},
            {"target_host": "docker01", "reason": "reason", "workflow": "other.yml"},
            {"target_host": "docker01", "reason": "reason", "ref": "feature"},
        )
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                session = Session([])
                with self.assertRaises(PolicyError):
                    deploy_stacks(session, AUTOMATION, **kwargs)
                self.assertEqual([], session.calls)

    def test_deploy_status_blocked_reports_the_production_approval_gate_without_approving_it(self) -> None:
        from homelab_agent.forgejo_policy import deploy_status, format_deploy_status

        session = Session([run("infra-stacks-deploy.yml", 82, "blocked", "2026-08-04T01:00:00Z")])
        result = deploy_status(session, AUTOMATION, 82)

        self.assertEqual("blocked", result.state)
        self.assertEqual(
            "deployment 82 blocked: awaiting Forgejo production environment reviewer",
            format_deploy_status(result),
        )
        self.assertEqual(("/repos/homelab/infra/actions/runs/82",), session.calls[0][0])

    def test_public_check_output_contains_no_response_diagnostics(self) -> None:
        from homelab_agent.forgejo_policy import checks_status, format_checks_status

        result = checks_status(Session([{ "workflow_runs": [
            run("validate.yml", 1, "success", "2026-08-04T01:00:00Z"),
            run("plan.yml", 2, "success", "2026-08-04T01:00:00Z"),
        ]}]), AUTOMATION, "infra", SHA)
        rendered = format_checks_status(result)

        self.assertIn("validate.yml success 1 https://git.example/runs/1", rendered)
        self.assertNotIn(SHA, rendered)


class ForgejoCliTests(unittest.TestCase):
    def test_cli_dispatches_forgejo_arguments_to_the_policy_runner(self) -> None:
        from homelab_agent import cli

        observed: list[tuple[str, ...]] = []
        result = cli.main(["forgejo", "checks", "status", "infra", SHA], forgejo_runner=lambda argv: observed.append(tuple(argv)) or 9)

        self.assertEqual(9, result)
        self.assertEqual([("checks", "status", "infra", SHA)], observed)

    def test_cli_rejects_unknown_policy_grammar_before_runner(self) -> None:
        from homelab_agent import cli

        stderr = io.StringIO()
        result = cli.main(["forgejo", "deploy", "stacks", "--confirm", "apply"], forgejo_runner=lambda _argv: self.fail("must not dispatch"), error_output=stderr)

        self.assertEqual(2, result)
        self.assertIn("usage: homelab-agent forgejo", stderr.getvalue())

    def test_legacy_map_stops_before_keychain_or_connect(self) -> None:
        from homelab_agent.forgejo_policy import run_authenticated_forgejo
        from homelab_agent.process import AgentError

        legacy = SimpleNamespace(version=1, forgejo_automation=None)
        with self.assertRaisesRegex(AgentError, "Tea workflow policy requires credential map version 2"):
            run_authenticated_forgejo(
                ["checks", "status", "infra", SHA], load=lambda: legacy,
                keychain_factory=lambda: self.fail("legacy policy must not access Keychain"),
                connect_factory=lambda *_args, **_kwargs: self.fail("legacy policy must not connect"),
                output=io.StringIO(),
            )


if __name__ == "__main__":
    unittest.main()

"""Behavioral coverage for the narrow Forgejo Actions policy."""
from __future__ import annotations

import io
import math
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


def forgejo14_run(
    workflow_id: str, run_id: int, status: str, created: str, *, sha: str = SHA
) -> dict[str, object]:
    """A real Actions response includes keys outside this policy's scope."""
    return dict(
        run(workflow_id, run_id, status, created, sha=sha),
        event="pull_request", head_branch="reviewed-change", name="infra checks",
        run_number=17, run_attempt=1, updated="2026-08-04T01:01:00Z",
        workflow_url="https://git.example/api/v1/workflows/17",
    )


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
            [{"total_count": 4, "workflow_runs": [
                forgejo14_run("validate.yml", 11, "failure", "2026-08-03T01:00:00Z"),
                forgejo14_run("validate.yml", 12, "success", "2026-08-04T01:00:00Z"),
                forgejo14_run("plan.yml", 13, "running", "2026-08-04T01:00:00Z"),
                forgejo14_run("unapproved.yml", 14, "success", "2026-08-04T01:00:00Z"),
            ]}]
        )

        result = checks_status(session, AUTOMATION, "infra", SHA)

        self.assertEqual("pending", result.state)
        self.assertEqual([("validate.yml", 12, "success"), ("plan.yml", 13, "running")], [
            (item.workflow, item.run_id, item.state) for item in result.runs
        ])
        self.assertEqual(
            (f"/repos/homelab/infra/actions/runs?head_sha={SHA}&event=pull_request&limit=50&page=1",),
            session.calls[0][0],
        )

    def test_check_status_aggregates_missing_pending_success_and_terminal_failure(self) -> None:
        from homelab_agent.forgejo_policy import checks_status

        cases = {
            "missing": ({"workflow_runs": [run("validate.yml", 1, "success", "2026-08-04T01:00:00Z")]}, "pending"),
            "waiting": ({"workflow_runs": [run("validate.yml", 1, "waiting", "2026-08-04T01:00:00Z"), run("plan.yml", 2, "success", "2026-08-04T01:00:00Z")]}, "pending"),
            "blocked": ({"workflow_runs": [run("validate.yml", 1, "blocked", "2026-08-04T01:00:00Z"), run("plan.yml", 2, "success", "2026-08-04T01:00:00Z")]}, "pending"),
            "unknown": ({"workflow_runs": [run("validate.yml", 1, "future-state", "2026-08-04T01:00:00Z"), run("plan.yml", 2, "success", "2026-08-04T01:00:00Z")]}, "pending"),
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
            {"workflow_runs": [dict(run("validate.yml", 1, "success", "2026-08-04T01:00:00Z"), id="wrong-type")]},
            {"workflow_runs": [dict(run("validate.yml", 1, "success", "2026-08-04T01:00:00Z"), created="not-a-timestamp")]},
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

    def test_wait_rejects_non_finite_timeouts_before_requesting_actions(self) -> None:
        from homelab_agent.forgejo_policy import PolicyError, checks_wait

        for timeout in (math.nan, math.inf, -math.inf):
            with self.subTest(timeout=timeout):
                session = Session([])
                with self.assertRaises(PolicyError):
                    checks_wait(session, AUTOMATION, "infra", SHA, timeout=timeout)
                self.assertEqual([], session.calls)

    def test_checks_wait_polls_blocked_and_unknown_states_until_terminal(self) -> None:
        from homelab_agent.forgejo_policy import checks_wait

        session = Session([
            {"workflow_runs": [run("validate.yml", 1, "blocked", "2026-08-04T01:00:00Z"), run("plan.yml", 2, "future-state", "2026-08-04T01:00:00Z")]},
            {"workflow_runs": [run("validate.yml", 1, "success", "2026-08-04T01:01:00Z"), run("plan.yml", 2, "success", "2026-08-04T01:01:00Z")]},
        ])
        clock = iter((0.0, 0.0)).__next__
        sleeps: list[float] = []

        result = checks_wait(session, AUTOMATION, "infra", SHA, timeout=5, clock=clock, sleeper=sleeps.append)

        self.assertEqual("success", result.state)
        self.assertEqual([5.0], sleeps)

    def test_check_status_uses_larger_run_id_when_created_timestamps_match(self) -> None:
        from homelab_agent.forgejo_policy import checks_status

        result = checks_status(Session([{"workflow_runs": [
            run("validate.yml", 3, "success", "2026-08-04T01:00:00Z"),
            run("validate.yml", 9, "failure", "2026-08-04T01:00:00Z"),
            run("plan.yml", 2, "success", "2026-08-04T01:00:00Z"),
        ]}]), AUTOMATION, "infra", SHA)

        self.assertEqual("failure", result.state)
        self.assertEqual(9, result.runs[0].run_id)

    def test_check_status_paginates_before_declaring_required_workflows_missing(self) -> None:
        from homelab_agent.forgejo_policy import checks_status

        first_page = [run("unapproved.yml", index + 1, "success", "2026-08-04T01:00:00Z") for index in range(50)]
        session = Session([
            {"total_count": 52, "workflow_runs": first_page},
            {"total_count": 52, "workflow_runs": [
                run("validate.yml", 51, "success", "2026-08-04T01:01:00Z"),
                run("plan.yml", 52, "success", "2026-08-04T01:01:00Z"),
            ]},
        ])

        result = checks_status(session, AUTOMATION, "infra", SHA)

        self.assertEqual("success", result.state)
        self.assertEqual(
            (f"/repos/homelab/infra/actions/runs?head_sha={SHA}&event=pull_request&limit=50&page=2",),
            session.calls[1][0],
        )

    def test_check_status_rejects_a_non_hex_or_short_commit_id_before_request(self) -> None:
        from homelab_agent.forgejo_policy import PolicyError, checks_status

        for sha in ("bad-sha", "a" * 39, "b" * 64):
            with self.subTest(sha=sha):
                session = Session([])
                with self.assertRaises(PolicyError):
                    checks_status(session, AUTOMATION, "infra", sha)
                self.assertEqual([], session.calls)

    def test_deploy_dispatch_has_only_the_fixed_endpoint_and_approved_inputs(self) -> None:
        from homelab_agent.forgejo_policy import deploy_stacks

        session = Session([{ "id": 82, "run_number": 17, "jobs": [] }])
        run_id = deploy_stacks(
            session, AUTOMATION, target_host="docker01", reason="approved maintenance",
            stacks="traefik,authentik", post_deploy_configure=True, confirm="apply",
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
            {"target_host": "router01", "reason": "reason", "confirm": "apply"},
            {"target_host": "docker01", "reason": "   ", "confirm": "apply"},
            {"target_host": "docker01", "reason": "reason", "stacks": "traefik,,authentik", "confirm": "apply"},
            {"target_host": "docker01", "reason": "reason", "stacks": "Traefik", "confirm": "apply"},
            {"target_host": "docker01", "reason": "reason"},
            {"target_host": "docker01", "reason": "reason", "confirm": "no"},
            {"target_host": "docker01", "reason": "reason", "repository": "other/repo", "confirm": "apply"},
            {"target_host": "docker01", "reason": "reason", "workflow": "other.yml", "confirm": "apply"},
            {"target_host": "docker01", "reason": "reason", "ref": "feature", "confirm": "apply"},
        )
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                session = Session([])
                with self.assertRaises(PolicyError):
                    deploy_stacks(session, AUTOMATION, **kwargs)
                self.assertEqual([], session.calls)

    def test_deploy_status_blocked_is_a_neutral_non_terminal_state(self) -> None:
        from homelab_agent.forgejo_policy import deploy_status, format_deploy_status

        session = Session([forgejo14_run("infra-stacks-deploy.yml", 82, "blocked", "2026-08-04T01:00:00Z")])
        result = deploy_status(session, AUTOMATION, 82)

        self.assertEqual("blocked", result.state)
        self.assertEqual(
            "deployment 82 blocked https://git.example/runs/82",
            format_deploy_status(result),
        )
        self.assertEqual(("/repos/homelab/infra/actions/runs/82",), session.calls[0][0])

    def test_non_successful_deploy_status_has_no_special_approval_exit_code(self) -> None:
        from homelab_agent.forgejo_policy import run_forgejo

        output = io.StringIO()
        result = run_forgejo(
            ["deploy", "status", "82"],
            session=Session([forgejo14_run("infra-stacks-deploy.yml", 82, "blocked", "2026-08-04T01:00:00Z")]),
            automation=AUTOMATION,
            output=output,
        )

        self.assertEqual(1, result)
        self.assertEqual("deployment 82 blocked https://git.example/runs/82\n", output.getvalue())

    def test_deploy_wait_polls_a_blocked_run_until_it_reaches_a_terminal_state(self) -> None:
        from homelab_agent.forgejo_policy import deploy_wait

        session = Session([
            forgejo14_run("infra-stacks-deploy.yml", 82, "blocked", "2026-08-04T01:00:00Z"),
            forgejo14_run("infra-stacks-deploy.yml", 82, "future-state", "2026-08-04T01:01:00Z"),
            forgejo14_run("infra-stacks-deploy.yml", 82, "success", "2026-08-04T01:02:00Z"),
        ])
        clock = iter((0.0, 0.0, 0.0)).__next__
        sleeps: list[float] = []

        result = deploy_wait(session, AUTOMATION, 82, timeout=5, clock=clock, sleeper=sleeps.append)

        self.assertEqual("success", result.state)
        self.assertEqual([5.0, 5.0], sleeps)
        self.assertEqual(3, len(session.calls))

    def test_deploy_cli_requires_an_explicit_apply_confirmation(self) -> None:
        from homelab_agent.forgejo_policy import run_forgejo

        session = Session([{ "id": 82 }])
        output = io.StringIO()
        result = run_forgejo(
            ["deploy", "stacks", "--target-host", "docker01", "--reason", "maintenance", "--confirm", "apply"],
            session=session, automation=AUTOMATION, output=output,
        )

        self.assertEqual(0, result)
        self.assertEqual("apply", session.calls[0][1]["inputs"]["confirm"])

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

    def test_cli_rejects_non_apply_confirmation_before_runner(self) -> None:
        from homelab_agent import cli

        stderr = io.StringIO()
        result = cli.main(
            ["forgejo", "deploy", "stacks", "--target-host", "docker01", "--reason", "maintenance", "--confirm", "no"],
            forgejo_runner=lambda _argv: self.fail("invalid confirmation must not dispatch"),
            error_output=stderr,
        )

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

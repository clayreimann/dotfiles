"""Regression tests for strict public Mac homelab-agent configuration loading."""
from __future__ import annotations

import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "dot_local" / "lib"))

from homelab_agent.config import ConfigError, load_config


def valid_document() -> dict[str, object]:
    """Return a complete, non-secret version-1 public credential map."""
    return {
        "version": 1,
        "vault": {"name": "Homelab Secrets"},
        "connect": {
            "direct_url": "http://192.168.42.253:8080",
            "tunnel_url": "http://127.0.0.1:18080",
        },
        "keychain": {
            "connect_service": "com.4406.homelab-agent.connect-token",
            "bastion_service": "com.4406.homelab-agent.bastion-passphrase",
        },
        "forgejo": {
            "host": "git.4406.madtown.cloud",
            "port": 2222,
            "user": "git",
            "credential_item_id": "yznfzgoql7jl4oa6spa7vm3644",
            "private_field": "private_key",
            "expected_fingerprint": "SHA256:hK4mZs4YQvDEf1zgeAOKtER0+eIdPJsDxRzPHlpXpjA",
            "known_host": "[git.4406.madtown.cloud]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGyB56wKbde2dOT+puZOfjpWqTNx3sIDkEjoN1wvUTyT",
            "api_url": "https://git.4406.madtown.cloud",
            "api_user": "claude",
            "api_token_field": "api_token",
        },
        "forgejo_automation": {
            "repository": "homelab/infra",
            "required_workflows": [
                "infra-validate.yml",
                "infra-vm-plan.yml",
                "infra-lxc-plan.yml",
                "infra-guest-config-check.yml",
                "infra-stack-config-check.yml",
            ],
            "deploy_workflow": "infra-stacks-deploy.yml",
            "deploy_ref": "main",
            "deploy_targets": ["docker01", "monitor01"],
        },
        "bastion": None,
        "targets": [
            {
                "alias": "docker01",
                "route": "direct",
                "host": "docker01",
                "port": 22,
                "user": "ubuntu",
                "credential_item_id": "aaaaaaaaaaaaaaaaaaaaaaaaaa",
                "private_field": "private_key",
                "expected_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "known_host": "docker01 ssh-ed25519 AAAA",
            }
        ],
        "repositories": [
            {
                "name": "infra",
                "remote": "ssh://git@git.4406.madtown.cloud:2222/homelab/infra.git",
                "path": "/Users/clay/Code/homelab/infra",
            }
        ],
        "tools": {
            "python": "3.12",
            "git": "2",
            "op": "2",
            "tofu": "1",
            "ansible": "2",
            "tailscale": "1",
            "tea": "0.14",
        },
    }


class LoadConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)

    def write_config(self, document: dict[str, object]) -> Path:
        path = Path(self.tempdir.name) / "credential-map.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_load_config_builds_typed_forgejo_api_identity_and_automation_policy(self) -> None:
        config = load_config(self.write_config(valid_document()))

        self.assertEqual("yznfzgoql7jl4oa6spa7vm3644", config.forgejo.credential_item_id)
        self.assertEqual(2222, config.forgejo.port)
        self.assertEqual("https://git.4406.madtown.cloud", config.forgejo.api_url)
        self.assertEqual("claude", config.forgejo.api_user)
        self.assertEqual("api_token", config.forgejo.api_token_field)
        self.assertEqual("homelab/infra", config.forgejo_automation.repository)
        self.assertEqual(
            (
                "infra-validate.yml",
                "infra-vm-plan.yml",
                "infra-lxc-plan.yml",
                "infra-guest-config-check.yml",
                "infra-stack-config-check.yml",
            ),
            config.forgejo_automation.required_workflows,
        )
        self.assertEqual("infra-stacks-deploy.yml", config.forgejo_automation.deploy_workflow)
        self.assertEqual("main", config.forgejo_automation.deploy_ref)
        self.assertEqual(("docker01", "monitor01"), config.forgejo_automation.deploy_targets)
        self.assertEqual("0.14", config.tools["tea"])
        self.assertEqual("docker01", config.target("docker01").alias)
        self.assertEqual(Path("/Users/clay/Code/homelab/infra"), config.repositories[0].path)

    def test_load_config_ignores_ambient_environment_override_when_path_is_omitted(self) -> None:
        approved_path = self.write_config(valid_document())
        attacker_document = valid_document()
        attacker_document["vault"]["name"] = "Other vault"  # type: ignore[index]
        attacker_path = Path(self.tempdir.name) / "attacker-map.json"
        attacker_path.write_text(json.dumps(attacker_document), encoding="utf-8")

        with patch("homelab_agent.config.DEFAULT_CONFIG_PATH", approved_path), patch.dict(
            os.environ, {"HOMELAB_AGENT_CONFIG": str(attacker_path)}
        ):
            config = load_config()

        self.assertEqual("Homelab Secrets", config.vault_name)

    def test_load_config_allows_an_explicit_test_path(self) -> None:
        path = self.write_config(valid_document())

        config = load_config(path)

        self.assertEqual("Homelab Secrets", config.vault_name)

    def test_load_config_rejects_unapproved_vault_name(self) -> None:
        document = valid_document()
        document["vault"]["name"] = "Other vault"  # type: ignore[index]

        with self.assertRaisesRegex(
            ConfigError, "vault.name must match the approved value"
        ):
            load_config(self.write_config(document))

    def test_load_config_rejects_unapproved_connect_endpoints(self) -> None:
        cases = {
            "direct_url": "http://other-connect.example:8080",
            "tunnel_url": "http://127.0.0.1:28080",
        }

        for field, replacement in cases.items():
            with self.subTest(field=field):
                document = valid_document()
                document["connect"][field] = replacement  # type: ignore[index]

                with self.assertRaisesRegex(
                    ConfigError, f"connect.{field} must match the approved value"
                ):
                    load_config(self.write_config(document))

    def test_load_config_rejects_unapproved_keychain_service_names(self) -> None:
        cases = {
            "connect_service": "com.example.unapproved-connect-token",
            "bastion_service": "com.example.unapproved-bastion-passphrase",
        }

        for field, replacement in cases.items():
            with self.subTest(field=field):
                document = valid_document()
                document["keychain"][field] = replacement  # type: ignore[index]

                with self.assertRaisesRegex(
                    ConfigError, f"keychain.{field} must match the approved value"
                ):
                    load_config(self.write_config(document))

    def test_load_config_rejects_unapproved_forgejo_pins(self) -> None:
        cases = {
            "host": "other.example",
            "port": 2200,
            "user": "other-git",
            "credential_item_id": "aaaaaaaaaaaaaaaaaaaaaaaaaa",
            "private_field": "ssh_key",
            "expected_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "known_host": "[git.4406.madtown.cloud]:2222 ssh-ed25519 AAAA",
            "api_url": "https://other.example",
            "api_user": "other-user",
            "api_token_field": "token",
        }

        for field, replacement in cases.items():
            with self.subTest(field=field):
                document = valid_document()
                document["forgejo"][field] = replacement  # type: ignore[index]

                with self.assertRaisesRegex(
                    ConfigError, f"forgejo.{field} must match the approved value"
                ):
                    load_config(self.write_config(document))

    def test_load_config_rejects_unapproved_forgejo_automation_pins(self) -> None:
        cases: list[tuple[str, object]] = [
            ("repository", "other/repository"),
            ("deploy_workflow", "other-deploy.yml"),
            ("deploy_ref", "release"),
        ]
        for index in range(5):
            workflows = valid_document()["forgejo_automation"]["required_workflows"]  # type: ignore[index]
            workflows[index] = "other-workflow.yml"  # type: ignore[index]
            cases.append(("required_workflows", workflows))
        for index in range(2):
            targets = valid_document()["forgejo_automation"]["deploy_targets"]  # type: ignore[index]
            targets[index] = "other-host"  # type: ignore[index]
            cases.append(("deploy_targets", targets))

        for field, replacement in cases:
            with self.subTest(field=field, replacement=replacement):
                document = valid_document()
                document["forgejo_automation"][field] = replacement  # type: ignore[index]

                with self.assertRaisesRegex(
                    ConfigError,
                    f"forgejo_automation.{field} must match the approved value",
                ):
                    load_config(self.write_config(document))

    def test_load_config_rejects_unapproved_tea_pin(self) -> None:
        document = valid_document()
        document["tools"]["tea"] = "1"  # type: ignore[index]

        with self.assertRaisesRegex(ConfigError, "tools.tea must match the approved value"):
            load_config(self.write_config(document))

    def test_load_config_rejects_unknown_version(self) -> None:
        document = valid_document()
        document["version"] = 2

        with self.assertRaisesRegex(ConfigError, "unsupported config version"):
            load_config(self.write_config(document))

    def test_load_config_rejects_unknown_document_key(self) -> None:
        document = valid_document()
        document["surprise"] = "value"

        with self.assertRaisesRegex(ConfigError, "unknown keys at document: surprise"):
            load_config(self.write_config(document))

    def test_load_config_rejects_missing_forgejo_field(self) -> None:
        document = valid_document()
        del document["forgejo"]["known_host"]  # type: ignore[index]

        with self.assertRaisesRegex(ConfigError, "missing keys at forgejo: known_host"):
            load_config(self.write_config(document))

    def test_target_fails_closed_for_unknown_alias(self) -> None:
        config = load_config(self.write_config(valid_document()))

        with self.assertRaisesRegex(ConfigError, "unmapped target: pm02"):
            config.target("pm02")

    def test_load_config_rejects_duplicate_repository_destination(self) -> None:
        document = valid_document()
        repositories = document["repositories"]  # type: ignore[assignment]
        repositories.append(  # type: ignore[union-attr]
            {
                "name": "infra-copy",
                "remote": "ssh://git@git.4406.madtown.cloud:2222/homelab/infra-copy.git",
                "path": "/Users/clay/Code/homelab/infra",
            }
        )

        with self.assertRaisesRegex(ConfigError, "duplicate repository destination"):
            load_config(self.write_config(document))

    def test_load_config_rejects_forbidden_secret_shaped_data(self) -> None:
        document = copy.deepcopy(valid_document())
        document["connect"]["token"] = "not-a-real-secret"  # type: ignore[index]

        with self.assertRaisesRegex(ConfigError, "forbidden secret key: connect.token") as error:
            load_config(self.write_config(document))

        self.assertNotIn("not-a-real-secret", str(error.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)

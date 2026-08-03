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
            "known_host": "[git.4406.madtown.cloud]:2222 ssh-ed25519 AAAA",
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

    def test_load_config_builds_typed_forgejo_identity(self) -> None:
        config = load_config(self.write_config(valid_document()))

        self.assertEqual("yznfzgoql7jl4oa6spa7vm3644", config.forgejo.credential_item_id)
        self.assertEqual(2222, config.forgejo.port)
        self.assertEqual("docker01", config.target("docker01").alias)
        self.assertEqual(Path("/Users/clay/Code/homelab/infra"), config.repositories[0].path)

    def test_load_config_uses_environment_override_when_path_is_omitted(self) -> None:
        path = self.write_config(valid_document())

        with patch.dict(os.environ, {"HOMELAB_AGENT_CONFIG": str(path)}):
            config = load_config()

        self.assertEqual("Homelab Secrets", config.vault_name)

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

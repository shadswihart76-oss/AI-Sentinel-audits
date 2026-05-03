from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

import yaml

from openclaw.auto_register import auto_register_repo_from_zip

from tests.test_utils import make_base_config


class AutoRegisterTests(unittest.TestCase):
    def test_auto_register_derives_repo_from_zip_name_and_updates_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_base_config(root)
            config["scope"]["github_repos"] = ["coinbase/<IN_SCOPE_REPO_1>"]
            config_path = root / "openclaw.localstub.yaml"
            config_path.write_text(yaml.safe_dump({"openclaw": config}, sort_keys=False), encoding="utf-8")

            zip_path = root / "coinbase-wallet-sdk-master.zip"
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("coinbase-wallet-sdk-master/README.md", "# test")

            result = auto_register_repo_from_zip(
                config_path=str(config_path),
                zip_path=str(zip_path),
                current_target="coinbase/<IN_SCOPE_REPO_1>",
            )

            self.assertEqual(result.target, "coinbase/coinbase-wallet-sdk")
            self.assertTrue(Path(result.backup_path).exists())

            updated = yaml.safe_load(config_path.read_text(encoding="utf-8"))
            repos = updated["openclaw"]["scope"]["github_repos"]
            self.assertIn("coinbase/coinbase-wallet-sdk", repos)

    def test_auto_register_is_idempotent_when_repo_already_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_base_config(root)
            config["scope"]["github_repos"] = ["coinbase/coinbase-wallet-sdk"]
            config_path = root / "openclaw.localstub.yaml"
            config_path.write_text(yaml.safe_dump({"openclaw": config}, sort_keys=False), encoding="utf-8")

            zip_path = root / "coinbase-wallet-sdk-main.zip"
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("coinbase-wallet-sdk-main/src/index.ts", "export {}")

            result = auto_register_repo_from_zip(
                config_path=str(config_path),
                zip_path=str(zip_path),
                current_target="coinbase/coinbase-wallet-sdk",
            )

            self.assertEqual(result.target, "coinbase/coinbase-wallet-sdk")
            self.assertFalse(result.added_to_scope)

            updated = yaml.safe_load(config_path.read_text(encoding="utf-8"))
            repos = updated["openclaw"]["scope"]["github_repos"]
            self.assertEqual(repos.count("coinbase/coinbase-wallet-sdk"), 1)


if __name__ == "__main__":
    unittest.main()

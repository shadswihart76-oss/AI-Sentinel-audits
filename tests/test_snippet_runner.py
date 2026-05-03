from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

import yaml

from openclaw.snippet_runner import run_repo_pipeline, run_snippet_pipeline, run_zip_pipeline

from tests.test_utils import make_base_config


class SnippetRunnerTests(unittest.TestCase):
    def test_snippet_runner_generates_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_base_config(root)
            config_path = root / "openclaw.yaml"
            config_path.write_text(yaml.safe_dump({"openclaw": config}), encoding="utf-8")

            result = run_snippet_pipeline(
                config_path=str(config_path),
                target="org/repo",
                code_snippet="user_id = request.args.get('user_id')",
                file_name="snippet.py",
                workspace_root=str(root / "snippet_sessions"),
            )

            self.assertIn("summary", result.__dict__)
            self.assertIn("final_findings", result.summary)
            self.assertTrue(Path(result.markdown_report).exists())
            self.assertTrue(Path(result.json_report).exists())

    def test_zip_runner_generates_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_base_config(root)
            config_path = root / "openclaw.yaml"
            config_path.write_text(yaml.safe_dump({"openclaw": config}), encoding="utf-8")

            repo_root = root / "sample_repo"
            repo_root.mkdir(parents=True, exist_ok=True)
            (repo_root / "app.py").write_text("user_id = request.args.get('user_id')\n", encoding="utf-8")
            (repo_root / "README.md").write_text("# Sample repo\n", encoding="utf-8")

            zip_path = root / "sample_repo.zip"
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.write(repo_root / "app.py", arcname="sample_repo/app.py")
                archive.write(repo_root / "README.md", arcname="sample_repo/README.md")

            result = run_zip_pipeline(
                config_path=str(config_path),
                target="org/repo",
                zip_path=str(zip_path),
                workspace_root=str(root / "zip_sessions"),
            )

            self.assertIn("summary", result.__dict__)
            self.assertIn("final_findings", result.summary)
            self.assertIn("extracted_repo_path", result.summary)
            self.assertTrue(Path(result.summary["extracted_repo_path"]).exists())
            self.assertTrue(Path(result.markdown_report).exists())
            self.assertTrue(Path(result.json_report).exists())

    def test_zip_runner_rejects_unsafe_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_base_config(root)
            config_path = root / "openclaw.yaml"
            config_path.write_text(yaml.safe_dump({"openclaw": config}), encoding="utf-8")

            zip_path = root / "unsafe.zip"
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("../../outside.py", "print('unsafe')")

            with self.assertRaises(ValueError):
                run_zip_pipeline(
                    config_path=str(config_path),
                    target="org/repo",
                    zip_path=str(zip_path),
                    workspace_root=str(root / "zip_sessions"),
                )

    def test_repo_runner_generates_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_base_config(root)
            config_path = root / "openclaw.yaml"
            config_path.write_text(yaml.safe_dump({"openclaw": config}), encoding="utf-8")

            repo_root = root / "repo_local"
            repo_root.mkdir(parents=True, exist_ok=True)
            (repo_root / "service.py").write_text("token = request.args.get('token')\n", encoding="utf-8")

            result = run_repo_pipeline(
                config_path=str(config_path),
                target="org/repo",
                repo_path=str(repo_root),
                workspace_root=str(root / "folder_sessions"),
            )

            self.assertIn("summary", result.__dict__)
            self.assertIn("final_findings", result.summary)
            self.assertTrue(Path(result.markdown_report).exists())
            self.assertTrue(Path(result.json_report).exists())


if __name__ == "__main__":
    unittest.main()

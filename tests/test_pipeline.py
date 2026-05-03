from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import yaml

from openclaw.pipeline import OpenClawPipeline

from tests.test_utils import make_base_config


class PipelineTests(unittest.TestCase):
    def test_pipeline_runs_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_base_config(root)
            repo = root / "repo"
            repo.mkdir()
            (repo / "app.py").write_text("user_id = request.args.get('user_id')", encoding="utf-8")

            config_path = root / "openclaw.yaml"
            config_path.write_text(yaml.safe_dump({"openclaw": config}), encoding="utf-8")

            pipeline = OpenClawPipeline(str(config_path))
            events: list[tuple[str, str]] = []

            def caller(_model: str, _prompt: str) -> str:
                return json.dumps(
                    {
                        "findings": [
                            {
                                "title": "Missing authorization check",
                                "summary": "Possible access control issue.",
                                "severity": "High",
                                "recommendations": ["Enforce ownership checks."],
                            }
                        ]
                    }
                )

            result = pipeline.run(
                target="org/repo",
                repo_path=str(repo),
                model_caller=caller,
                max_ai_files=10,
                progress_callback=lambda stage, status, _details: events.append((stage, status)),
            )
            self.assertGreaterEqual(result.ai_findings_count, 1)
            self.assertGreaterEqual(len(result.final_findings), 1)
            self.assertIn("markdown_report", result.report_paths)
            self.assertIn(("config_scope", "start"), events)
            self.assertIn(("report_generator", "done"), events)
            self.assertIn(("complete", "done"), events)


if __name__ == "__main__":
    unittest.main()

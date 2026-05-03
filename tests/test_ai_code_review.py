from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from openclaw.ai_code_review import run_ai_code_review

from tests.test_utils import make_base_config


class AICodeReviewTests(unittest.TestCase):
    def test_ai_schema_validation_non_strict_keeps_normalized_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_base_config(root)
            config["modules"]["ai_code_review"]["prompts"] = {
                "general_security": config["modules"]["ai_code_review"]["prompts"]["general_security"]
            }
            config["modules"]["ai_code_review"]["schema_validation"]["strict"] = False
            config["modules"]["ai_code_review"]["parallel"]["max_workers"] = 4

            code_file = root / "code.py"
            code_file.write_text("user_id = request.args.get('user_id')", encoding="utf-8")

            def caller(_model: str, _prompt: str) -> str:
                payload = {
                    "findings": [
                        {"title": "t1", "summary": "s1", "severity": "High"},
                        {"title": "", "summary": ""},  # invalid, should be normalized in non-strict mode
                    ]
                }
                return json.dumps(payload)

            findings = run_ai_code_review(
                target="org/repo",
                file_paths=[str(code_file)],
                config=config,
                model_caller=caller,
            )
            self.assertGreaterEqual(len(findings), 2)

    def test_ai_schema_validation_strict_drops_invalid_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_base_config(root)
            config["modules"]["ai_code_review"]["prompts"] = {
                "general_security": config["modules"]["ai_code_review"]["prompts"]["general_security"]
            }
            config["modules"]["ai_code_review"]["schema_validation"]["strict"] = True
            code_file = root / "code.py"
            code_file.write_text("print('hello')", encoding="utf-8")

            def caller(_model: str, _prompt: str) -> str:
                return json.dumps({"findings": [{"title": "", "summary": ""}]})

            findings = run_ai_code_review(
                target="org/repo",
                file_paths=[str(code_file)],
                config=config,
                model_caller=caller,
            )
            self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()

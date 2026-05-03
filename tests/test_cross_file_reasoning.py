from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openclaw.cross_file_reasoning import run_cross_file_reasoning

from tests.test_utils import make_base_config


class CrossFileReasoningTests(unittest.TestCase):
    def test_cross_file_reasoning_emits_chain_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_base_config(root)
            config["modules"]["cross_file_reasoning"] = {"enabled": True, "min_files_for_chain": 2}

            file_a = root / "a.py"
            file_b = root / "b.py"
            file_c = root / "c.py"
            file_a.write_text("user_id = request.args.get('user_id')", encoding="utf-8")
            file_b.write_text("requests.get(target_url)", encoding="utf-8")
            file_c.write_text("owner_id = params['owner_id']", encoding="utf-8")

            findings = run_cross_file_reasoning(
                target="org/repo",
                file_paths=[str(file_a), str(file_b), str(file_c)],
                ai_findings=[],
                static_findings=[],
                config=config,
            )
            self.assertGreaterEqual(len(findings), 1)
            self.assertTrue(any(item.get("source") == "cross_file_reasoning" for item in findings))


if __name__ == "__main__":
    unittest.main()

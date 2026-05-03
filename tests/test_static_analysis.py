from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from openclaw.static_analysis import run_static_analysis

from tests.test_utils import make_base_config


class StaticAnalysisTests(unittest.TestCase):
    def test_static_analysis_gracefully_marks_missing_tools(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_base_config(root)
            repo = root / "repo"
            repo.mkdir()
            (repo / "main.py").write_text("print('x')", encoding="utf-8")

            with patch("openclaw.static_analysis.shutil.which", return_value=None):
                result = run_static_analysis(
                    target="org/repo",
                    repo_path=repo,
                    config=config,
                    output_dir=root / "reports",
                )

            statuses = {item.tool: item.status for item in result.tool_runs}
            self.assertEqual(statuses.get("semgrep"), "missing")
            self.assertEqual(statuses.get("bandit"), "missing")


if __name__ == "__main__":
    unittest.main()

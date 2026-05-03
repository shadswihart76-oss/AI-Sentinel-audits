from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openclaw.models import Finding
from openclaw.report_generator import generate_report

from tests.test_utils import make_base_config


class ReportGeneratorTests(unittest.TestCase):
    def test_report_files_are_generated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_base_config(root)
            finding = Finding(
                title="Test finding",
                asset="org/repo",
                component="x.py",
                summary="summary",
                severity="Medium",
            )

            outputs = generate_report("org/repo", [finding], config, output_dir=root / "reports")
            md_path = Path(outputs["markdown_report"])
            json_path = Path(outputs["json_report"])
            self.assertTrue(md_path.exists())
            self.assertTrue(json_path.exists())
            self.assertIn("Test finding", md_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()

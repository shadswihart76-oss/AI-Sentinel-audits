from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from openclaw.report_pack import export_bounty_pack


class ReportPackTests(unittest.TestCase):
    def test_export_bounty_pack_writes_artifacts_and_zip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence_md = root / "openclaw_report.md"
            evidence_json = root / "openclaw_report.json"
            config_yaml = root / "openclaw.localstub.yaml"

            evidence_md.write_text("# report", encoding="utf-8")
            evidence_json.write_text("[]", encoding="utf-8")
            config_yaml.write_text("scope: {}\n", encoding="utf-8")

            findings = [
                {
                    "title": "Potential ownership check gap",
                    "severity": "High",
                    "category": "auth_access",
                    "component": "repo/src/auth/handler.py",
                    "summary": "Potential ownership validation gap in account endpoint.",
                    "recommendations": ["Derive identity from authenticated context."],
                }
            ]
            summary = {
                "config_path": str(config_yaml),
                "report_paths": {
                    "markdown_report": str(evidence_md),
                    "json_report": str(evidence_json),
                },
            }

            outputs = export_bounty_pack(
                output_root=root / "exports",
                target="program/repo/path.ext",
                findings=findings,
                findings_text="1. Potential ownership check gap",
                summary=summary,
                filter_mode="validated_only",
                selected_severities=["Critical", "High", "Medium"],
            )

            pack_dir = Path(outputs["pack_dir"])
            self.assertTrue(pack_dir.exists())
            self.assertTrue(Path(outputs["zip_path"]).exists())
            self.assertTrue((pack_dir / "findings.md").exists())
            self.assertTrue((pack_dir / "findings.json").exists())
            self.assertTrue((pack_dir / "summary.json").exists())
            self.assertTrue((pack_dir / "validation_checklist.md").exists())

            summary_json = json.loads((pack_dir / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary_json["filter_mode"], "validated_only")
            self.assertEqual(summary_json["finding_count"], 1)
            self.assertGreaterEqual(len(summary_json["copied_evidence_files"]), 2)


if __name__ == "__main__":
    unittest.main()

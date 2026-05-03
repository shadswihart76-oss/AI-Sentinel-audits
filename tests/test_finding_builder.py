from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openclaw.finding_builder import normalize_and_rank_findings

from tests.test_utils import make_base_config


class FindingBuilderTests(unittest.TestCase):
    def test_scoring_heuristics_update_severity_and_confidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_base_config(root)

            raw = [
                {
                    "title": "Potential privilege escalation",
                    "summary": "The endpoint could allow privilege escalation and expose financial history.",
                    "severity": "Low",
                    "category": "auth_access",
                    "source": "ai_code_review",
                    "recommendations": ["Bind to authenticated identity."],
                    "component": "svc.py",
                }
            ]
            findings = normalize_and_rank_findings("org/repo", raw, config)
            self.assertEqual(len(findings), 1)
            self.assertIn(findings[0].severity, {"High", "Critical"})
            self.assertGreaterEqual(findings[0].code_confidence, 0.5)

    def test_auth_ownership_precision_gate_drops_when_auth_binding_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_base_config(root)

            component = root / "snippet.php"
            component.write_text(
                "<?php $uid = get_current_user_id(); $u = wp_get_current_user(); ?>",
                encoding="utf-8",
            )
            raw = [
                {
                    "title": "Potential ownership check gap",
                    "summary": "Code appears to use user identifiers; verify ownership binding to authenticated identity.",
                    "severity": "Critical",
                    "category": "auth_access",
                    "source": "ai_code_review",
                    "recommendations": ["Bind identity from auth context."],
                    "component": str(component),
                }
            ]
            findings = normalize_and_rank_findings("org/repo", raw, config)
            self.assertEqual(findings, [])

    def test_auth_ownership_precision_gate_keeps_request_controlled_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_base_config(root)

            component = root / "snippet.php"
            component.write_text(
                "<?php $uid = $_GET['user_id']; $row = lookup_user($uid); ?>",
                encoding="utf-8",
            )
            raw = [
                {
                    "title": "Potential ownership check gap",
                    "summary": "Code appears to use user identifiers; verify ownership binding to authenticated identity.",
                    "severity": "High",
                    "category": "auth_access",
                    "source": "ai_code_review",
                    "recommendations": ["Bind identity from auth context."],
                    "component": str(component),
                }
            ]
            findings = normalize_and_rank_findings("org/repo", raw, config)
            self.assertEqual(len(findings), 1)


if __name__ == "__main__":
    unittest.main()

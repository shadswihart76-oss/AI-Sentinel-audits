from __future__ import annotations

import unittest

from openclaw.ensemble_scoring import merge_findings_with_ensemble


class EnsembleScoringTests(unittest.TestCase):
    def test_ensemble_merges_by_consensus(self) -> None:
        findings = [
            {
                "title": "Missing authorization check",
                "summary": "Access control gap",
                "severity": "High",
                "category": "auth_access",
                "component": "a.py",
                "code_confidence": 0.6,
                "metadata": {"review_model": "m1"},
            },
            {
                "title": "Missing authorization check",
                "summary": "Access control gap",
                "severity": "Critical",
                "category": "auth_access",
                "component": "a.py",
                "code_confidence": 0.7,
                "metadata": {"review_model": "m2"},
            },
        ]
        ensemble_cfg = {
            "enabled": True,
            "models": ["m1", "m2"],
            "model_weights": {"m1": 1.0, "m2": 1.0},
            "require_consensus": False,
        }
        merged = merge_findings_with_ensemble(findings, ensemble_cfg, static_hints=[])
        self.assertEqual(len(merged), 1)
        self.assertIn("consensus_count", merged[0]["metadata"])
        self.assertGreaterEqual(merged[0]["code_confidence"], 0.6)


if __name__ == "__main__":
    unittest.main()

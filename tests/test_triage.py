from __future__ import annotations

import unittest

from openclaw.triage import (
    filter_report_ready_findings,
    filter_validated_ready_findings,
    is_non_production_component,
    validation_checklist_for_finding,
)


class TriageTests(unittest.TestCase):
    def test_non_production_component_detection(self) -> None:
        self.assertTrue(is_non_production_component("C:/repo/examples/demo.ts"))
        self.assertTrue(is_non_production_component("C:/repo/src/service.test.ts"))
        self.assertFalse(is_non_production_component("C:/repo/src/auth/handler.ts"))

    def test_report_ready_filter_removes_chain_and_test_noise(self) -> None:
        findings = [
            {
                "title": "Cross-file ssrf chain candidate",
                "component": "cross_file_reasoning",
                "severity": "Critical",
            },
            {
                "title": "Potential user-influenced outbound request",
                "component": "C:/repo/src/core/http.test.ts",
                "severity": "Medium",
            },
            {
                "title": "Potential ownership check gap",
                "component": "C:/repo/src/auth/handler.ts",
                "severity": "High",
            },
        ]
        filtered = filter_report_ready_findings(findings)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["title"], "Potential ownership check gap")

    def test_validation_checklist_is_category_specific(self) -> None:
        checks = validation_checklist_for_finding({"category": "auth_access"})
        joined = " ".join(checks).lower()
        self.assertIn("authenticated context", joined)
        self.assertIn("ownership", joined)

    def test_validated_ready_filter_keeps_actionable_medium_plus(self) -> None:
        findings = [
            {
                "title": "Cross-file chain candidate",
                "component": "cross_file_reasoning",
                "severity": "Critical",
                "summary": "cross-file placeholder",
                "recommendations": ["do x"],
            },
            {
                "title": "Low severity info leak",
                "component": "C:/repo/src/api/handler.py",
                "severity": "Low",
                "summary": "Returns banner value in an error payload.",
                "recommendations": ["mask internal values"],
            },
            {
                "title": "Missing rec list",
                "component": "C:/repo/src/auth/handler.py",
                "severity": "High",
                "summary": "Potentially bypassable ownership check in account endpoint.",
                "recommendations": [],
            },
            {
                "title": "Actionable auth gap",
                "component": "C:/repo/src/auth/handler.py",
                "severity": "High",
                "summary": "Potential ownership validation gap in account retrieval endpoint.",
                "recommendations": ["Bind identity to authenticated session before query."],
            },
        ]
        filtered = filter_validated_ready_findings(findings)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["title"], "Actionable auth gap")


if __name__ == "__main__":
    unittest.main()

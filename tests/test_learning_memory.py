from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openclaw.learning_memory import build_learning_context, update_learning_memory


class LearningMemoryTests(unittest.TestCase):
    def test_update_and_build_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            memory_path = Path(tmp) / "learning_memory.json"
            update_learning_memory(
                memory_path=str(memory_path),
                findings=[
                    {
                        "title": "Missing ownership check",
                        "category": "auth_access",
                        "severity": "High",
                        "summary": "Authorization missing.",
                        "recommendations": ["Bind to authenticated user."],
                    }
                ],
            )
            self.assertTrue(memory_path.exists())
            context = build_learning_context(memory_path=str(memory_path), max_entries=10)
            self.assertIn("auth_access", context)
            self.assertIn("Missing ownership check", context)


if __name__ == "__main__":
    unittest.main()

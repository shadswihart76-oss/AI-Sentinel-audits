from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openclaw.passive_recon import run_passive_recon

from tests.test_utils import make_base_config


class PassiveReconTests(unittest.TestCase):
    def test_passive_recon_collects_code_doc_and_js_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_base_config(root)

            repo = root / "repo"
            repo.mkdir()
            (repo / "main.py").write_text("print('x')", encoding="utf-8")
            (repo / "README.md").write_text("# test", encoding="utf-8")
            (repo / "app.js").write_text("console.log('x')", encoding="utf-8")

            result = run_passive_recon("org/repo", repo, config)
            self.assertGreaterEqual(len(result.code_files), 2)  # .py and .js
            self.assertGreaterEqual(len(result.doc_files), 1)
            self.assertGreaterEqual(len(result.js_files), 1)


if __name__ == "__main__":
    unittest.main()

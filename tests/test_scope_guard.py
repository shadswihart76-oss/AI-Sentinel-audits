from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from openclaw.scope_guard import ScopeViolation, is_in_scope, set_scope_config, validate

from tests.test_utils import make_base_config


class ScopeGuardTests(unittest.TestCase):
    def test_validate_accepts_in_scope_repo(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = make_base_config(Path(tmp))
            set_scope_config(config)
            self.assertTrue(validate("org/repo"))
            self.assertTrue(is_in_scope("api.example.com", config))

    def test_validate_rejects_out_of_scope_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = make_base_config(Path(tmp))
            set_scope_config(config)
            with self.assertRaises(ScopeViolation):
                validate("totally-out-of-scope.test")


if __name__ == "__main__":
    unittest.main()

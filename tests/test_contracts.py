from __future__ import annotations

import logging
import tempfile
import unittest
from pathlib import Path

from openclaw import MODEL_PROVIDER_CONTRACT_VERSION, STATIC_TOOL_CONTRACT_VERSION
from openclaw.ai_code_review import parse_ai_response
from openclaw.config import ConfigError, load_config
from openclaw.logging_utils import setup_logging
from openclaw.model_runtime import ModelRuntimeError, register_model_provider
from openclaw.scoring import SCORING_API_VERSION, score_finding
from openclaw.static_analysis import register_static_tool

from tests.test_utils import make_base_config


class ContractLockTests(unittest.TestCase):
    def test_static_tool_registration_rejects_bad_signature(self) -> None:
        def bad_tool(_ctx, _extra):  # type: ignore[no-untyped-def]
            return None

        with self.assertRaises(TypeError):
            register_static_tool("bad_tool_sig", bad_tool, contract_version=STATIC_TOOL_CONTRACT_VERSION)

    def test_model_provider_registration_rejects_bad_version(self) -> None:
        def builder(_cfg):  # type: ignore[no-untyped-def]
            def caller(_model, _prompt):  # type: ignore[no-untyped-def]
                return "[]"

            return caller

        with self.assertRaises(ValueError):
            register_model_provider("bad_provider", builder, contract_version="999")

    def test_model_provider_contract_requires_string_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = make_base_config(Path(tmp))

            def builder(_cfg):  # type: ignore[no-untyped-def]
                def caller(_model, _prompt):  # type: ignore[no-untyped-def]
                    return {"not": "a string"}

                return caller

            register_model_provider("bad_output_provider", builder, contract_version=MODEL_PROVIDER_CONTRACT_VERSION)
            config["modules"]["ai_code_review"]["runtime"]["provider"] = "bad_output_provider"

            from openclaw.model_runtime import build_model_caller_from_config

            caller = build_model_caller_from_config(config)
            with self.assertRaises(ModelRuntimeError):
                caller("m", "p")

    def test_ai_schema_lock_drops_unknown_fields_in_strict_mode(self) -> None:
        response = """
        {
          "findings": [
            {
              "title": "x",
              "summary": "y",
              "severity": "Medium",
              "weird_field": "not allowed"
            }
          ]
        }
        """
        parsed = parse_ai_response(
            ai_response=response,
            target="org/repo",
            component="a.py",
            prompt_key="general_security",
            strict_schema=True,
            allow_unknown_fields=False,
        )
        self.assertEqual(parsed, [])

    def test_scoring_api_exposes_contract_version(self) -> None:
        class FindingLike:
            title = "Potential privilege escalation"
            summary = "Could allow privilege escalation over financial data."
            source = "ai_code_review"
            recommendations = ["Enforce ownership checks."]
            metadata = {}

        scored = score_finding("Low", FindingLike(), 0.4)
        self.assertEqual(scored["scoring_contract_version"], SCORING_API_VERSION)

    def test_locked_logging_format_overrides_custom_format(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = make_base_config(Path(tmp))
            config["logging"]["lock_format"] = True
            config["logging"]["format"] = "CUSTOM %(message)s"
            setup_logging(config)
            root = logging.getLogger()
            formatter = root.handlers[0].formatter
            self.assertIsNotNone(formatter)
            assert formatter is not None
            self.assertIn("[%(name)s]", formatter._fmt)
            self.assertNotIn("CUSTOM", formatter._fmt)

    def test_config_rejects_contract_version_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg = make_base_config(root)
            cfg["contracts"] = {"static_tool": "999"}
            path = root / "bad_contract.yaml"
            import yaml

            path.write_text(yaml.safe_dump({"openclaw": cfg}), encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(path)


if __name__ == "__main__":
    unittest.main()

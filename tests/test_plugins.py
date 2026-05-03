from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from openclaw.model_runtime import build_model_caller_from_config
from openclaw.static_analysis import run_static_analysis

from tests.test_utils import make_base_config


class PluginArchitectureTests(unittest.TestCase):
    def test_static_plugin_module_can_register_new_tool(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_base_config(root)
            repo = root / "repo"
            repo.mkdir()
            (repo / "x.py").write_text("print('x')", encoding="utf-8")

            plugin_path = root / "custom_static_plugin.py"
            plugin_path.write_text(
                "\n".join(
                    [
                        "from openclaw.static_analysis import register_static_tool, StaticToolPluginOutput, ToolRun",
                        "def run_tool(context):",
                        "    return StaticToolPluginOutput(run=ToolRun(tool='custom', status='ok'), findings=[])",
                        "register_static_tool('custom', run_tool)",
                    ]
                ),
                encoding="utf-8",
            )

            config["modules"]["static_analysis"]["plugin_modules"] = [str(plugin_path)]
            config["modules"]["static_analysis"]["tools"] = ["custom"]

            result = run_static_analysis("org/repo", repo, config, root / "reports")
            self.assertEqual(result.tool_runs[0].status, "ok")

    def test_model_plugin_module_can_register_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = make_base_config(root)
            plugin_path = root / "custom_model_provider.py"
            plugin_path.write_text(
                "\n".join(
                    [
                        "import json",
                        "from openclaw.model_runtime import register_model_provider",
                        "def build(_cfg):",
                        "    def caller(_model, _prompt):",
                        "        return json.dumps({'findings': []})",
                        "    return caller",
                        "register_model_provider('test_provider', build)",
                    ]
                ),
                encoding="utf-8",
            )

            runtime_cfg = config["modules"]["ai_code_review"]["runtime"]
            runtime_cfg["plugin_modules"] = [str(plugin_path)]
            runtime_cfg["provider"] = "test_provider"

            caller = build_model_caller_from_config(config)
            response = caller("m", "p")
            self.assertEqual(json.loads(response), {"findings": []})


if __name__ == "__main__":
    unittest.main()

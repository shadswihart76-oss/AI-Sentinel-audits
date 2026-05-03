from __future__ import annotations

import argparse
import json

from . import __version__
from .logging_utils import setup_logging
from .model_runtime import ModelRuntimeError, build_model_caller_from_config
from .pipeline import OpenClawPipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openclaw",
        description="OpenClaw v0.3: Read-only security code review pipeline.",
    )
    parser.add_argument(
        "--config",
        default="openclaw.yaml",
        help="Path to OpenClaw config file.",
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target asset (domain, repo slug, or mobile package).",
    )
    parser.add_argument(
        "--repo-path",
        default=".",
        help="Local repository path for passive recon and static analysis.",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Optional override for report output directory.",
    )
    parser.add_argument(
        "--max-ai-files",
        type=int,
        default=200,
        help="Limit number of files sent to AI review stage.",
    )
    parser.add_argument(
        "--print-json",
        action="store_true",
        help="Print full JSON summary to stdout.",
    )
    parser.add_argument(
        "--json-only",
        action="store_true",
        help="Print final normalized findings JSON only.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce logging output (errors only).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.quiet and args.verbose:
        raise SystemExit("Choose either --quiet or --verbose, not both.")

    pipeline = OpenClawPipeline(config_path=args.config)
    if args.quiet:
        pipeline.config.setdefault("logging", {})["level"] = "ERROR"
    elif args.verbose:
        pipeline.config.setdefault("logging", {})["level"] = "DEBUG"
    elif args.json_only:
        # Keep JSON-only mode machine-readable by suppressing info logs.
        pipeline.config.setdefault("logging", {})["level"] = "ERROR"
    setup_logging(pipeline.config)

    try:
        model_caller = build_model_caller_from_config(pipeline.config)
    except ModelRuntimeError as exc:
        raise SystemExit(f"Invalid AI runtime configuration: {exc}") from exc

    result = pipeline.run(
        target=args.target,
        repo_path=args.repo_path,
        output_dir=args.output_dir,
        model_caller=model_caller,
        max_ai_files=args.max_ai_files,
    )

    if args.json_only:
        print(json.dumps(result.final_findings, indent=2))
        return 0

    summary = {
        "openclaw_version": __version__,
        "target": result.target,
        "repo_path": result.repo_path,
        "config_path": result.config_path,
        "ai_runtime_provider": pipeline.config.get("modules", {}).get("ai_code_review", {}).get("runtime", {}).get("provider", "none"),
        "passive_recon": {
            "code_files": len(result.passive_recon.code_files),
            "doc_files": len(result.passive_recon.doc_files),
            "js_files": len(result.passive_recon.js_files),
            "notes": result.passive_recon.notes,
        },
        "static_tool_runs": [
            {"tool": run.tool, "status": run.status, "output_file": run.output_file}
            for run in result.static_analysis.tool_runs
        ],
        "static_findings": len(result.static_analysis.findings),
        "ai_findings": result.ai_findings_count,
        "cross_file_findings": result.cross_file_findings_count,
        "final_findings": len(result.final_findings),
        "report_paths": result.report_paths,
        "stage_errors": result.stage_errors,
    }

    if args.print_json:
        print(json.dumps(summary, indent=2))
    else:
        print("OpenClaw Run Summary")
        print(f"openclaw_version={summary['openclaw_version']}")
        print(f"target={summary['target']}")
        print(f"repo_path={summary['repo_path']}")
        print(f"ai_runtime_provider={summary['ai_runtime_provider']}")
        print(f"code_files={summary['passive_recon']['code_files']}")
        print(f"doc_files={summary['passive_recon']['doc_files']}")
        print(f"js_files={summary['passive_recon']['js_files']}")
        print(f"static_findings={summary['static_findings']}")
        print(f"ai_findings={summary['ai_findings']}")
        print(f"cross_file_findings={summary['cross_file_findings']}")
        print(f"final_findings={summary['final_findings']}")
        if summary["stage_errors"]:
            print("stage_errors_present=true")
            for stage_name, error in sorted(summary["stage_errors"].items()):
                print(f"stage_error.{stage_name}={error}")
        else:
            print("stage_errors_present=false")
        if "markdown_report" in summary["report_paths"]:
            print(f"markdown_report={summary['report_paths']['markdown_report']}")
        if "json_report" in summary["report_paths"]:
            print(f"json_report={summary['report_paths']['json_report']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .ai_code_review import ModelCaller, run_ai_code_review
from .config import load_config
from .cross_file_reasoning import run_cross_file_reasoning
from .finding_builder import normalize_and_rank_findings
from .learning_memory import build_learning_context, update_learning_memory
from .logging_utils import get_module_logger, setup_logging
from .passive_recon import PassiveReconResult, run_passive_recon
from .report_generator import generate_report
from .scope_guard import set_scope_config, validate
from .static_analysis import StaticAnalysisResult, run_static_analysis


@dataclass
class PipelineResult:
    target: str
    repo_path: str
    config_path: str
    passive_recon: PassiveReconResult
    static_analysis: StaticAnalysisResult
    ai_findings_count: int
    cross_file_findings_count: int
    final_findings: list[dict[str, Any]] = field(default_factory=list)
    report_paths: dict[str, str] = field(default_factory=dict)
    stage_errors: dict[str, str] = field(default_factory=dict)


ProgressCallback = Callable[[str, str, dict[str, Any]], None]


class OpenClawPipeline:
    def __init__(self, config_path: str):
        self.config_path = str(Path(config_path).resolve())
        self.config = load_config(config_path)
        setup_logging(self.config)
        set_scope_config(self.config)
        self.logger = get_module_logger("pipeline")

    def run(
        self,
        target: str,
        repo_path: str,
        output_dir: str | None = None,
        model_caller: ModelCaller | None = None,
        max_ai_files: int | None = None,
        progress_callback: ProgressCallback | None = None,
    ) -> PipelineResult:
        def progress(stage: str, status: str, **details: Any) -> None:
            if progress_callback is not None:
                progress_callback(stage, status, details)

        hardening_cfg = self.config.get("hardening", {})
        graceful_fallback = bool(hardening_cfg.get("graceful_fallback", True))
        stage_errors: dict[str, str] = {}
        progress("config_scope", "start", target=target, repo_path=repo_path)

        self.logger.info("Pipeline started target=%s repo_path=%s", target, repo_path)
        # 0) Config + Scope
        validate(target)

        # 1) Scope Guard (explicit call to preserve stage boundary)
        validate(target)
        progress("config_scope", "done", target=target)

        # 2) Passive Recon (read-only, local-repo analysis)
        passive_enabled = bool(self.config.get("modules", {}).get("passive_recon", {}).get("enabled", True))
        progress("passive_recon", "start", enabled=passive_enabled)
        if passive_enabled:
            try:
                passive = run_passive_recon(target=target, repo_path=repo_path, config=self.config)
            except Exception as exc:
                if not graceful_fallback:
                    raise
                stage_errors["passive_recon"] = str(exc)
                self.logger.exception("Passive recon failed; continuing with graceful fallback.")
                passive = PassiveReconResult(repo_path=str(Path(repo_path).resolve()))
        else:
            self.logger.info("Passive recon disabled by config.")
            passive = PassiveReconResult(repo_path=str(Path(repo_path).resolve()))
        progress(
            "passive_recon",
            "done",
            code_files=len(passive.code_files),
            doc_files=len(passive.doc_files),
            js_files=len(passive.js_files),
        )

        # 3) Static Analysis (local tools only)
        static_out_dir = Path(output_dir or self.config.get("modules", {}).get("reporting", {}).get("output_dir", "./reports"))
        progress("static_analysis", "start", output_dir=str(static_out_dir))
        try:
            static = run_static_analysis(
                target=target,
                repo_path=repo_path,
                config=self.config,
                output_dir=static_out_dir,
            )
        except Exception as exc:
            if not graceful_fallback:
                raise
                stage_errors["static_analysis"] = str(exc)
                self.logger.exception("Static analysis failed; continuing with graceful fallback.")
                static = StaticAnalysisResult()
        progress(
            "static_analysis",
            "done",
            findings=len(static.findings),
            tool_runs=len(static.tool_runs),
        )

        # 4) AI Code Review (prompt-driven, model wrapper injected by caller)
        ai_targets = passive.code_files
        if max_ai_files is not None:
            ai_targets = ai_targets[: max(0, max_ai_files)]

        modules_cfg = self.config.get("modules", {})
        ai_cfg = modules_cfg.get("ai_code_review", {})
        learning_cfg = ai_cfg.get("learning", {}) if isinstance(ai_cfg, dict) else {}
        learning_enabled = bool(learning_cfg.get("enabled", True))
        learning_context = ""
        learning_memory_path = ""
        if learning_enabled:
            reporting_cfg = modules_cfg.get("reporting", {})
            default_memory = Path(str(reporting_cfg.get("output_dir", "./reports"))) / "learning_memory.json"
            configured_memory = str(learning_cfg.get("memory_file", str(default_memory)))
            memory_path = Path(configured_memory)
            if not memory_path.is_absolute():
                memory_path = Path(self.config_path).resolve().parent / memory_path
            learning_memory_path = str(memory_path.resolve())
            progress("learning_memory", "start", memory_file=learning_memory_path)
            try:
                learning_context = build_learning_context(
                    memory_path=learning_memory_path,
                    max_entries=int(learning_cfg.get("max_context_entries", 20)),
                )
            except Exception as exc:
                if not graceful_fallback:
                    raise
                stage_errors["learning_memory"] = str(exc)
                self.logger.exception("Learning memory load failed; continuing without context.")
            progress("learning_memory", "done", context_available=bool(learning_context))

        progress("ai_code_review", "start", files=len(ai_targets))
        try:
            ai_raw_findings = run_ai_code_review(
                target=target,
                file_paths=ai_targets,
                config=self.config,
                model_caller=model_caller,
                static_hints=static.findings,
                learning_context=learning_context,
            )
        except Exception as exc:
            if not graceful_fallback:
                raise
            stage_errors["ai_code_review"] = str(exc)
            self.logger.exception("AI code review failed; continuing with graceful fallback.")
            ai_raw_findings = []
        progress("ai_code_review", "done", findings=len(ai_raw_findings))

        # 5) Finding Normalizer + Report Generator
        progress("cross_file_reasoning", "start", files=len(ai_targets))
        try:
            cross_file_findings = run_cross_file_reasoning(
                target=target,
                file_paths=ai_targets,
                ai_findings=ai_raw_findings,
                static_findings=static.findings,
                config=self.config,
            )
        except Exception as exc:
            if not graceful_fallback:
                raise
                stage_errors["cross_file_reasoning"] = str(exc)
                self.logger.exception("Cross-file reasoning failed; continuing with graceful fallback.")
                cross_file_findings = []
        progress("cross_file_reasoning", "done", findings=len(cross_file_findings))

        # 5) Finding Normalizer
        combined = static.findings + ai_raw_findings + cross_file_findings
        progress("finding_builder", "start", candidate_findings=len(combined))
        try:
            normalized = normalize_and_rank_findings(
                target=target,
                raw_findings=combined,
                config=self.config,
            )
        except Exception as exc:
            if not graceful_fallback:
                raise
                stage_errors["finding_builder"] = str(exc)
                self.logger.exception("Finding builder failed; continuing with empty findings.")
                normalized = []
        progress("finding_builder", "done", final_findings=len(normalized))

        if learning_enabled and learning_memory_path:
            progress("learning_memory", "start", update=True)
            try:
                update_learning_memory(
                    memory_path=learning_memory_path,
                    findings=[item.to_dict() for item in normalized],
                    max_records=int(learning_cfg.get("max_records", 3000)),
                )
            except Exception as exc:
                if not graceful_fallback:
                    raise
                stage_errors["learning_memory_update"] = str(exc)
                self.logger.exception("Learning memory update failed; continuing.")
            progress("learning_memory", "done", update=True)

        reporting_enabled = bool(self.config.get("modules", {}).get("reporting", {}).get("enabled", True))
        progress("report_generator", "start", enabled=reporting_enabled)
        if reporting_enabled:
            try:
                report_paths = generate_report(
                    target=target,
                    findings=normalized,
                    config=self.config,
                    output_dir=output_dir,
                )
            except Exception as exc:
                if not graceful_fallback:
                    raise
                stage_errors["report_generator"] = str(exc)
                self.logger.exception("Report generation failed.")
                report_paths = {}
        else:
            self.logger.info("Report generation disabled by config.")
            report_paths = {}
        progress("report_generator", "done", report_paths=report_paths)
        self.logger.info(
            "Pipeline complete target=%s static_findings=%s ai_findings=%s cross_file_findings=%s final_findings=%s",
            target,
            len(static.findings),
            len(ai_raw_findings),
            len(cross_file_findings),
            len(normalized),
        )
        progress(
            "complete",
            "done",
            static_findings=len(static.findings),
            ai_findings=len(ai_raw_findings),
            cross_file_findings=len(cross_file_findings),
            final_findings=len(normalized),
        )

        return PipelineResult(
            target=target,
            repo_path=str(Path(repo_path).resolve()),
            config_path=self.config_path,
            passive_recon=passive,
            static_analysis=static,
            ai_findings_count=len(ai_raw_findings),
            cross_file_findings_count=len(cross_file_findings),
            final_findings=[item.to_dict() for item in normalized],
            report_paths=report_paths,
            stage_errors=stage_errors,
        )

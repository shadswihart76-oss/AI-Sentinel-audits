from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
from typing import Any, Callable

from .ensemble_scoring import merge_findings_with_ensemble
from .ai_schema import validate_ai_finding
from .logging_utils import get_module_logger, setup_logging
from .scope_guard import set_scope_config, validate

ModelCaller = Callable[[str, str], str]


def chunk_code(file_content: str, max_tokens: int) -> list[str]:
    lines = file_content.splitlines()
    chunks: list[str] = []
    current: list[str] = []
    for line in lines:
        candidate = line if not current else "\n".join(current + [line])
        if len(candidate) > max_tokens and current:
            chunks.append("\n".join(current))
            current = [line]
        else:
            current.append(line)
    if current:
        chunks.append("\n".join(current))
    return chunks


def _extract_json_block(raw: str) -> str:
    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) >= 3:
            return "\n".join(lines[1:-1]).strip()
    return text


def parse_ai_response(
    ai_response: str,
    target: str,
    component: str,
    prompt_key: str,
    strict_schema: bool = False,
    allow_unknown_fields: bool = False,
) -> list[dict[str, Any]]:
    logger = get_module_logger("ai_code_review")
    text = _extract_json_block(ai_response)
    if not text:
        return []

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        logger.warning("AI response was not valid JSON; skipping component=%s", component)
        return []

    if isinstance(parsed, dict):
        items = parsed.get("findings", [])
    elif isinstance(parsed, list):
        items = parsed
    else:
        logger.warning("AI response JSON root was not object/list; skipping component=%s", component)
        return []

    output: list[dict[str, Any]] = []
    for item in items:
        normalized, errors = validate_ai_finding(
            item,
            target=target,
            component=component,
            prompt_key=prompt_key,
            allow_unknown_fields=allow_unknown_fields,
        )
        if normalized is None:
            logger.debug("Dropped invalid AI finding item: errors=%s", errors)
            continue
        if strict_schema and errors:
            logger.debug(
                "Strict schema enabled; dropped AI finding due to validation errors: %s",
                errors,
            )
            continue
        output.append(normalized)
    return output


def _default_model_caller(_model: str, _prompt: str) -> str:
    return "[]"


def _load_prompts(config: dict, learning_context: str = "") -> dict[str, str]:
    prompt_paths = config.get("modules", {}).get("ai_code_review", {}).get("prompts", {})
    loaded: dict[str, str] = {}
    for key, path_value in prompt_paths.items():
        base_prompt = Path(str(path_value)).read_text(encoding="utf-8")
        if learning_context.strip():
            loaded[str(key)] = (
                base_prompt
                + "\n\n"
                + "Use this prior-pattern context to improve signal and confidence calibration:\n"
                + learning_context
            )
        else:
            loaded[str(key)] = base_prompt
    return loaded


def _auto_chunk_size(file_paths: list[str], module_cfg: dict) -> int:
    base = int(module_cfg.get("max_chunk_size", 4000))
    chunking_cfg = module_cfg.get("chunking", {})
    mode = str(chunking_cfg.get("mode", "auto")).strip().lower()
    if mode != "auto":
        return max(400, base)

    min_chunk = int(chunking_cfg.get("min_chunk_size", 1200))
    max_chunk = int(chunking_cfg.get("max_chunk_size", 8000))
    total_files = len(file_paths)
    total_bytes = 0
    for path in file_paths:
        try:
            total_bytes += Path(path).stat().st_size
        except Exception:
            continue

    # Small repos get larger chunks for flow. Large repos use smaller chunks for context density.
    if total_files <= 60 and total_bytes <= 1_500_000:
        tuned = int(base * 1.35)
    elif total_files >= 300 or total_bytes >= 10_000_000:
        tuned = int(base * 0.65)
    else:
        tuned = base
    return max(min_chunk, min(max_chunk, tuned))


def _models_for_prompt(prompt_key: str, module_cfg: dict) -> list[str]:
    default_model = str(module_cfg.get("model", "local_model"))
    specialization = module_cfg.get("model_specialization", {})
    specialized = str(specialization.get(prompt_key, default_model))

    ensemble_cfg = module_cfg.get("ensemble", {})
    if not bool(ensemble_cfg.get("enabled", False)):
        return [specialized]

    prompt_models_map = ensemble_cfg.get("models_by_prompt", {})
    if isinstance(prompt_models_map, dict) and prompt_key in prompt_models_map:
        candidate = prompt_models_map.get(prompt_key, [])
    else:
        candidate = ensemble_cfg.get("models", [])

    models = [str(x).strip() for x in candidate if str(x).strip()]
    if not models:
        models = [specialized]
    if specialized not in models:
        models.insert(0, specialized)
    # Preserve order and uniqueness.
    seen: set[str] = set()
    ordered: list[str] = []
    for model in models:
        if model in seen:
            continue
        seen.add(model)
        ordered.append(model)
    return ordered


def _fallback_models_for_prompt(prompt_key: str, module_cfg: dict, used_model: str) -> list[str]:
    fallback_cfg = module_cfg.get("model_fallback", {})
    prompt_map = fallback_cfg.get("by_prompt", {})
    if isinstance(prompt_map, dict) and prompt_key in prompt_map:
        candidates = prompt_map.get(prompt_key, [])
    else:
        candidates = fallback_cfg.get("default", [])

    out: list[str] = []
    for item in candidates if isinstance(candidates, list) else []:
        value = str(item).strip()
        if not value or value == used_model:
            continue
        if value not in out:
            out.append(value)
    return out


def _run_single_review_task(
    *,
    model: str,
    caller: ModelCaller,
    prompt_template: str,
    prompt_key: str,
    chunk: str,
    target: str,
    component: str,
    strict_schema: bool,
    allow_unknown_fields: bool,
    fallback_models: list[str],
) -> list[dict[str, Any]]:
    logger = get_module_logger("ai_code_review")
    prompt = prompt_template.replace("<CODE_SNIPPET>", chunk)
    used_model = model
    try:
        ai_response = caller(used_model, prompt)
    except Exception:
        ai_response = ""
        for fallback_model in fallback_models:
            try:
                used_model = fallback_model
                ai_response = caller(used_model, prompt)
                logger.warning(
                    "Model fallback used component=%s prompt=%s from=%s to=%s",
                    component,
                    prompt_key,
                    model,
                    fallback_model,
                )
                break
            except Exception:
                continue
        if not ai_response:
            logger.exception("Model caller failed for component=%s prompt=%s model=%s", component, prompt_key, model)
            return []

    parsed = parse_ai_response(
        ai_response=ai_response,
        target=target,
        component=component,
        prompt_key=prompt_key,
        strict_schema=strict_schema,
        allow_unknown_fields=allow_unknown_fields,
    )
    for item in parsed:
        metadata = dict(item.get("metadata") or {})
        metadata.setdefault("review_model", used_model)
        metadata.setdefault("prompt_key", prompt_key)
        item["metadata"] = metadata
    return parsed


def _ai_review_file(
    file_path: Path,
    prompts: dict[str, str],
    max_chunk_size: int,
    caller: ModelCaller,
    target: str,
    strict_schema: bool,
    allow_unknown_fields: bool,
    max_workers: int,
    module_cfg: dict,
) -> list[dict[str, Any]]:
    logger = get_module_logger("ai_code_review")
    code = file_path.read_text(encoding="utf-8", errors="ignore")
    chunks = chunk_code(code, max_tokens=max_chunk_size)
    logger.debug("Prepared %s chunks for component=%s chunk_size=%s", len(chunks), str(file_path), max_chunk_size)

    tasks: list[tuple[str, str, str, str, list[str]]] = []
    for prompt_key, prompt_template in prompts.items():
        for model in _models_for_prompt(prompt_key, module_cfg):
            fallbacks = _fallback_models_for_prompt(prompt_key, module_cfg, model)
            for chunk in chunks:
                tasks.append((prompt_key, prompt_template, chunk, model, fallbacks))

    if not tasks:
        return []

    findings: list[dict[str, Any]] = []
    if max_workers <= 1:
        for prompt_key, prompt_template, chunk, model, fallbacks in tasks:
            findings.extend(
                _run_single_review_task(
                    model=model,
                    caller=caller,
                    prompt_template=prompt_template,
                    prompt_key=prompt_key,
                    chunk=chunk,
                    target=target,
                    component=str(file_path),
                    strict_schema=strict_schema,
                    allow_unknown_fields=allow_unknown_fields,
                    fallback_models=fallbacks,
                )
            )
        return findings

    def _runner(task: tuple[str, str, str, str, list[str]]) -> list[dict[str, Any]]:
        prompt_key, prompt_template, chunk, model, fallbacks = task
        return _run_single_review_task(
            model=model,
            caller=caller,
            prompt_template=prompt_template,
            prompt_key=prompt_key,
            chunk=chunk,
            target=target,
            component=str(file_path),
            strict_schema=strict_schema,
            allow_unknown_fields=allow_unknown_fields,
            fallback_models=fallbacks,
        )

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for parsed in executor.map(_runner, tasks):
            findings.extend(parsed)
    return findings


def run_ai_code_review(
    target: str,
    file_paths: list[str],
    config: dict,
    model_caller: ModelCaller | None = None,
    static_hints: list[dict[str, Any]] | None = None,
    learning_context: str = "",
) -> list[dict[str, Any]]:
    logger = get_module_logger("ai_code_review")
    setup_logging(config)
    set_scope_config(config)
    validate(target)

    module_cfg = config.get("modules", {}).get("ai_code_review", {})
    if not module_cfg.get("enabled", True):
        logger.info("AI code review disabled for target=%s", target)
        return []

    prompts = _load_prompts(config, learning_context=learning_context)
    tuned_chunk_size = _auto_chunk_size(file_paths, module_cfg)
    strict_schema = bool(module_cfg.get("schema_validation", {}).get("strict", False))
    allow_unknown_fields = bool(module_cfg.get("schema_validation", {}).get("allow_unknown_fields", False))
    parallel_cfg = module_cfg.get("parallel", {})
    max_workers = int(parallel_cfg.get("max_workers", 4))
    if not parallel_cfg.get("enabled", True):
        max_workers = 1
    max_workers = max(1, max_workers)
    caller = model_caller or _default_model_caller

    logger.info(
        "Starting AI code review target=%s files=%s prompts=%s workers=%s strict_schema=%s chunk_size=%s",
        target,
        len(file_paths),
        len(prompts),
        max_workers,
        strict_schema,
        tuned_chunk_size,
    )
    findings: list[dict[str, Any]] = []
    for file_name in file_paths:
        findings.extend(
            _ai_review_file(
                file_path=Path(file_name),
                prompts=prompts,
                max_chunk_size=tuned_chunk_size,
                caller=caller,
                target=target,
                strict_schema=strict_schema,
                allow_unknown_fields=allow_unknown_fields,
                max_workers=max_workers,
                module_cfg=module_cfg,
            )
        )
    findings = merge_findings_with_ensemble(
        findings=findings,
        ensemble_cfg=module_cfg.get("ensemble", {}),
        static_hints=static_hints,
    )
    logger.info("AI code review complete target=%s findings=%s", target, len(findings))
    return findings

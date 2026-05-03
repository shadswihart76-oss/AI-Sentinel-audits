from __future__ import annotations

import importlib
import importlib.util
import inspect
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable

from .contracts import MODEL_PROVIDER_CONTRACT_VERSION
from .logging_utils import get_module_logger

ModelCaller = Callable[[str, str], str]
ModelProviderBuilder = Callable[[dict], ModelCaller]

MODEL_PROVIDER_REGISTRY: dict[str, ModelProviderBuilder] = {}


class ModelRuntimeError(Exception):
    """Raised when local model runtime invocation fails."""


def _validate_model_caller_signature(caller: Callable[..., object]) -> None:
    if not callable(caller):
        raise TypeError("Model caller must be callable.")
    sig = inspect.signature(caller)
    positional = [
        p
        for p in sig.parameters.values()
        if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    if len(positional) != 2:
        raise TypeError(
            "Model caller contract requires exactly two positional parameters: model, prompt."
        )


def _validate_model_builder_signature(builder: Callable[..., object]) -> None:
    if not callable(builder):
        raise TypeError("Model provider builder must be callable.")
    sig = inspect.signature(builder)
    positional = [
        p
        for p in sig.parameters.values()
        if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    if len(positional) != 1:
        raise TypeError(
            "Model provider builder contract requires exactly one positional parameter: runtime_cfg."
        )


def register_model_provider(
    name: str,
    builder: ModelProviderBuilder,
    *,
    contract_version: str = MODEL_PROVIDER_CONTRACT_VERSION,
) -> None:
    if contract_version != MODEL_PROVIDER_CONTRACT_VERSION:
        raise ValueError(
            f"Unsupported model provider contract_version={contract_version}. "
            f"Expected {MODEL_PROVIDER_CONTRACT_VERSION}."
        )
    clean_name = name.strip().lower()
    if not clean_name:
        raise ValueError("Model provider name cannot be empty.")
    _validate_model_builder_signature(builder)
    MODEL_PROVIDER_REGISTRY[clean_name] = builder


def _as_list(value: object, field_name: str) -> list[str]:
    if not isinstance(value, list):
        raise ModelRuntimeError(f"`{field_name}` must be a list of command tokens.")
    return [str(token) for token in value]


def _run_subprocess(
    cmd: list[str],
    timeout_seconds: int,
    input_text: str | None = None,
    workdir: str | None = None,
    env: dict[str, str] | None = None,
) -> str:
    completed = subprocess.run(
        cmd,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
        encoding="utf-8",
        errors="replace",
        cwd=workdir,
        env=env,
        timeout=timeout_seconds,
    )
    if completed.returncode != 0:
        raise ModelRuntimeError(
            f"Model runtime command failed (exit={completed.returncode}): "
            f"{' '.join(cmd)}\nSTDERR:\n{completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def _resolve_executable(token: str) -> str:
    lowered = token.strip().lower()
    if lowered == "python":
        if shutil.which("python"):
            return token
        if shutil.which("python3"):
            return "python3"
    if lowered == "python3":
        if shutil.which("python3"):
            return token
        if shutil.which("python"):
            return "python"
    return token


def _alternate_python_exec(token: str) -> str | None:
    lowered = token.strip().lower()
    if lowered == "python3":
        return "python"
    if lowered == "python":
        return "python3"
    return None


def _build_runtime_env(runtime_cfg: dict) -> dict[str, str]:
    isolation_cfg = runtime_cfg.get("isolation", {})
    clean_env = bool(isolation_cfg.get("clean_env", False))
    env_overrides = runtime_cfg.get("env", {})
    if env_overrides and not isinstance(env_overrides, dict):
        raise ModelRuntimeError("`modules.ai_code_review.runtime.env` must be a mapping.")

    if clean_env:
        allowed = isolation_cfg.get("allowed_env", ["PATH", "HOME", "TMP", "TEMP", "SYSTEMROOT"])
        if not isinstance(allowed, list):
            raise ModelRuntimeError("`runtime.isolation.allowed_env` must be a list.")
        env = {str(k): os.environ.get(str(k), "") for k in allowed}
    else:
        env = os.environ.copy()

    for k, v in dict(env_overrides).items():
        env[str(k)] = str(v)
    return env


def _build_none_caller(_runtime_cfg: dict) -> ModelCaller:
    def _caller(_model: str, _prompt: str) -> str:
        return "[]"

    return _caller


def _build_ollama_caller(runtime_cfg: dict) -> ModelCaller:
    if shutil.which("ollama") is None:
        raise ModelRuntimeError("`ollama` executable not found in PATH.")

    timeout_seconds = int(runtime_cfg.get("timeout_seconds", 90))
    extra_args = runtime_cfg.get("extra_args", [])
    extra_tokens = _as_list(extra_args, "modules.ai_code_review.runtime.extra_args")
    runtime_env = _build_runtime_env(runtime_cfg)

    def _caller(model: str, prompt: str) -> str:
        cmd = ["ollama", "run", model] + extra_tokens
        output = _run_subprocess(
            cmd,
            timeout_seconds=timeout_seconds,
            input_text=prompt,
            env=runtime_env,
        )
        return output or "[]"

    return _caller


def _build_command_caller(runtime_cfg: dict) -> ModelCaller:
    command = runtime_cfg.get("command")
    command_tokens = _as_list(command, "modules.ai_code_review.runtime.command")
    if not command_tokens:
        raise ModelRuntimeError("Runtime command token list cannot be empty.")

    timeout_seconds = int(runtime_cfg.get("timeout_seconds", 120))
    prompt_mode = str(runtime_cfg.get("prompt_mode", "stdin")).strip().lower()
    workdir = runtime_cfg.get("workdir")
    isolation_cfg = runtime_cfg.get("isolation", {})
    use_temp_workdir = bool(isolation_cfg.get("use_temp_workdir", False))
    runtime_env = _build_runtime_env(runtime_cfg)

    def _caller(model: str, prompt: str) -> str:
        needs_prompt_file = any("{prompt_file}" in token for token in command_tokens)
        use_prompt_file = prompt_mode == "file" or needs_prompt_file

        with tempfile.TemporaryDirectory(prefix="openclaw_runtime_") as tmp_dir:
            run_cwd = str(Path(workdir).resolve()) if workdir else None
            if use_temp_workdir:
                run_cwd = tmp_dir

            prompt_file_path: str | None = None
            input_text: str | None = prompt if prompt_mode == "stdin" else None

            if use_prompt_file:
                prompt_file = Path(tmp_dir) / "prompt.txt"
                prompt_file.write_text(prompt, encoding="utf-8")
                prompt_file_path = str(prompt_file)
                if prompt_mode == "file":
                    input_text = None

            prepared: list[str] = []
            for token in command_tokens:
                value = token.replace("{model}", model)
                value = value.replace("{prompt_file}", prompt_file_path or "")
                prepared.append(value)
            if prepared:
                prepared[0] = _resolve_executable(prepared[0])

            try:
                output = _run_subprocess(
                    prepared,
                    timeout_seconds=timeout_seconds,
                    input_text=input_text,
                    workdir=run_cwd,
                    env=runtime_env,
                )
            except ModelRuntimeError as first_error:
                alt = _alternate_python_exec(prepared[0]) if prepared else None
                if alt:
                    retry = list(prepared)
                    retry[0] = alt
                    output = _run_subprocess(
                        retry,
                        timeout_seconds=timeout_seconds,
                        input_text=input_text,
                        workdir=run_cwd,
                        env=runtime_env,
                    )
                else:
                    raise first_error
            return output or "[]"

    return _caller


register_model_provider("none", _build_none_caller)
register_model_provider("disabled", _build_none_caller)
register_model_provider("off", _build_none_caller)
register_model_provider("ollama_cli", _build_ollama_caller)
register_model_provider("command", _build_command_caller)


def _load_model_plugins(runtime_cfg: dict) -> None:
    logger = get_module_logger("model_runtime")
    plugin_entries = runtime_cfg.get("plugin_modules", [])
    if not isinstance(plugin_entries, list):
        logger.warning("runtime.plugin_modules must be a list.")
        return

    for idx, entry in enumerate(plugin_entries):
        plugin_ref = str(entry).strip()
        if not plugin_ref:
            continue
        try:
            if plugin_ref.endswith(".py"):
                path = Path(plugin_ref).resolve()
                module_name = f"openclaw_ext_model_plugin_{idx}"
                spec = importlib.util.spec_from_file_location(module_name, path)
                if spec is None or spec.loader is None:
                    raise ImportError(f"Unable to load plugin path: {path}")
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
            else:
                importlib.import_module(plugin_ref)
            logger.info("Loaded model runtime plugin module: %s", plugin_ref)
        except Exception:
            logger.exception("Failed to load model runtime plugin module: %s", plugin_ref)


def build_model_caller_from_config(config: dict) -> ModelCaller:
    logger = get_module_logger("model_runtime")
    ai_cfg = config.get("modules", {}).get("ai_code_review", {})
    runtime_cfg = ai_cfg.get("runtime", {})
    _load_model_plugins(runtime_cfg)

    provider = str(runtime_cfg.get("provider", "none")).strip().lower()
    graceful_fallback = bool(runtime_cfg.get("graceful_fallback", True))
    builder = MODEL_PROVIDER_REGISTRY.get(provider)
    if builder is None:
        raise ModelRuntimeError(
            "Unsupported local model runtime provider. "
            "Use one of: none, ollama_cli, command, or a registered plugin provider."
        )

    try:
        caller = builder(runtime_cfg)
        _validate_model_caller_signature(caller)
        def _contract_enforced_caller(model: str, prompt: str) -> str:
            output = caller(model, prompt)
            if not isinstance(output, str):
                raise ModelRuntimeError(
                    f"Model provider '{provider}' returned non-string response. "
                    f"Contract {MODEL_PROVIDER_CONTRACT_VERSION} requires string output."
                )
            return output

        return _contract_enforced_caller
    except Exception as exc:
        if graceful_fallback:
            logger.exception(
                "Model runtime provider '%s' failed to initialize. Falling back to provider='none'.",
                provider,
            )
            return _build_none_caller(runtime_cfg)
        if isinstance(exc, ModelRuntimeError):
            raise
        raise ModelRuntimeError(str(exc)) from exc

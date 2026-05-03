from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import random
import subprocess
import threading
from typing import Any, Callable

TK_AVAILABLE = True
_TK_IMPORT_ERROR: Exception | None = None
try:
    from tkinter import (
        BOTH,
        Canvas,
        END,
        LEFT,
        Menu,
        NW,
        PhotoImage,
        RIGHT,
        TOP,
        X,
        BooleanVar,
        DoubleVar,
        StringVar,
        Tk,
        filedialog,
        messagebox,
    )
    from tkinter import ttk
    from tkinter.scrolledtext import ScrolledText
except Exception as exc:  # pragma: no cover - environment-dependent
    TK_AVAILABLE = False
    _TK_IMPORT_ERROR = exc

from .auto_register import AutoRegisterError, auto_register_repo_from_zip
from .config import ConfigError, load_config
from .snippet_runner import (
    format_hackerone_findings,
    run_file_pipeline,
    run_repo_pipeline,
    run_snippet_pipeline,
    run_zip_pipeline,
)
from .report_pack import export_bounty_pack
from .scope_guard import is_in_scope
from .triage import (
    filter_report_ready_findings,
    filter_validated_ready_findings,
    validation_checklist_for_finding,
)

SEVERITY_ORDER = ("Critical", "High", "Medium", "Low", "Info")
STAGE_PROGRESS = {
    "snippet_input": 8,
    "file_input": 8,
    "folder_input": 8,
    "zip_extract": 12,
    "archive_extract": 12,
    "detect_repo_root": 18,
    "config_scope": 22,
    "passive_recon": 35,
    "static_analysis": 55,
    "ai_code_review": 74,
    "cross_file_reasoning": 84,
    "finding_builder": 91,
    "report_generator": 97,
    "complete": 100,
}
STAGE_LABELS = {
    "snippet_input": "Preparing snippet input",
    "file_input": "Preparing uploaded file",
    "folder_input": "Loading local folder",
    "zip_extract": "Extracting ZIP",
    "archive_extract": "Extracting archive",
    "detect_repo_root": "Detecting repo root",
    "config_scope": "Validating scope",
    "passive_recon": "Collecting passive code inventory",
    "static_analysis": "Running static analysis",
    "ai_code_review": "Running AI models",
    "cross_file_reasoning": "Cross-file reasoning",
    "finding_builder": "Merging and scoring findings",
    "report_generator": "Generating report",
    "complete": "Run complete",
}


class OpenClawDashboard:
    def __init__(self, root: Tk) -> None:
        self.root = root
        self.base_title = "OpenClaw Dashboard (Paste/ZIP/Folder -> Run -> Copy Findings)"
        self.root.title(self.base_title)
        self.root.geometry("1400x930")

        self.config_var = StringVar(value=str((Path.cwd() / "openclaw.localstub.yaml").resolve()))
        self.target_var = StringVar(value="program/repo/path.ext")
        self.file_var = StringVar(value="snippet.py")
        self.zip_var = StringVar(value="")
        self.folder_var = StringVar(value=str(Path.cwd()))
        self.history_var = StringVar(value="")
        self.progress_text_var = StringVar(value="Idle.")
        self.operator_var = StringVar(value="")
        self.accent_var = StringVar(value="#39ff88")
        self.banner_text_var = StringVar(value="OPENCLAW // BOUNTY MODE")
        self.background_image_var = StringVar(value="")
        self.binary_background_var = BooleanVar(value=True)
        self.matrix_rain_var = BooleanVar(value=True)
        self.whole_screen_rain_var = BooleanVar(value=False)
        self.rain_speed_var = DoubleVar(value=1.0)
        self.rain_density_var = DoubleVar(value=1.0)
        self.rain_speed_text_var = StringVar(value="1.00x")
        self.rain_density_text_var = StringVar(value="1.00x")
        self.glass_panels_var = BooleanVar(value=True)
        self.expanded_background_var = BooleanVar(value=False)
        self.zero_knowledge_var = BooleanVar(value=False)
        self.report_ready_var = BooleanVar(value=True)
        self.validated_only_var = BooleanVar(value=False)
        self.severity_vars = {sev: BooleanVar(value=True) for sev in SEVERITY_ORDER}
        self.personalization_path = (Path.cwd() / ".openclaw_dashboard_prefs.json").resolve()
        self._accent_color = "#39ff88"
        self._banner_image: PhotoImage | None = None
        self._rain_job: str | None = None
        self._rain_columns = 0
        self._rain_rows = 0
        self._rain_drops: list[dict[str, float]] = []
        self._last_whole_screen_height = 0

        self.last_copy_text = ""
        self.last_json_text = ""
        self.last_report_path = ""
        self.last_findings: list[dict[str, Any]] = []
        self.last_summary: dict[str, Any] = {}
        self.last_rendered_text = ""
        self.history_entries: list[dict[str, Any]] = []
        self.history_label_to_index: dict[str, int] = {}

        self._load_personalization()
        self._autofill_target_from_config(force=False, quiet=True)
        self._build_layout()
        self._refresh_history()
        self._apply_personalization(initial=True)

    def _build_layout(self) -> None:
        top = ttk.Frame(self.root, padding=10)
        top.pack(side=TOP, fill=X)
        top.grid_columnconfigure(1, weight=1)

        ttk.Label(top, text="Config").grid(row=0, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.config_var, width=95).grid(row=0, column=1, padx=6, sticky="we")
        ttk.Button(top, text="Browse", command=self._browse_config).grid(row=0, column=2, padx=6)
        ttk.Button(top, text="Paste", command=self._paste_config_path).grid(row=0, column=3, padx=4)

        ttk.Label(top, text="Target").grid(row=1, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.target_var, width=95).grid(row=1, column=1, padx=6, sticky="we")
        ttk.Button(top, text="Use In-Scope", command=self._set_scope_target).grid(row=1, column=2, padx=6)
        ttk.Button(top, text="Paste", command=lambda: self._paste_clipboard_to_var(self.target_var)).grid(row=1, column=3, padx=4)

        ttk.Label(top, text="Snippet File").grid(row=2, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.file_var, width=42).grid(row=2, column=1, padx=6, sticky="w")

        ttk.Label(top, text="Upload File").grid(row=3, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.zip_var, width=95).grid(row=3, column=1, padx=6, sticky="we")
        ttk.Button(top, text="Browse File", command=self._browse_zip).grid(row=3, column=2, padx=6)
        ttk.Button(top, text="Paste", command=lambda: self._paste_clipboard_to_var(self.zip_var)).grid(row=3, column=3, padx=4)

        ttk.Label(top, text="Load Folder").grid(row=4, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.folder_var, width=95).grid(row=4, column=1, padx=6, sticky="we")
        ttk.Button(top, text="Browse Folder", command=self._browse_folder).grid(row=4, column=2, padx=6)
        ttk.Button(top, text="Paste", command=lambda: self._paste_clipboard_to_var(self.folder_var)).grid(row=4, column=3, padx=4)

        personal_frame = ttk.Frame(top)
        personal_frame.grid(row=5, column=1, pady=4, sticky="w")
        ttk.Label(personal_frame, text="Operator").pack(side=LEFT, padx=(0, 6))
        ttk.Entry(personal_frame, textvariable=self.operator_var, width=16).pack(side=LEFT, padx=(0, 8))
        ttk.Label(personal_frame, text="Accent").pack(side=LEFT, padx=(0, 6))
        ttk.Entry(personal_frame, textvariable=self.accent_var, width=10).pack(side=LEFT, padx=(0, 8))
        ttk.Label(personal_frame, text="Banner").pack(side=LEFT, padx=(0, 6))
        ttk.Entry(personal_frame, textvariable=self.banner_text_var, width=28).pack(side=LEFT, padx=(0, 8))
        ttk.Checkbutton(
            personal_frame,
            text="Binary Background",
            variable=self.binary_background_var,
            command=self._apply_personalization,
        ).pack(side=LEFT, padx=(0, 8))
        ttk.Checkbutton(
            personal_frame,
            text="Matrix Rain",
            variable=self.matrix_rain_var,
            command=self._apply_personalization,
        ).pack(side=LEFT, padx=(0, 8))
        ttk.Checkbutton(
            personal_frame,
            text="Glass Panels",
            variable=self.glass_panels_var,
            command=self._apply_personalization,
        ).pack(side=LEFT, padx=(0, 8))
        ttk.Checkbutton(
            personal_frame,
            text="Big Background",
            variable=self.expanded_background_var,
            command=self._apply_personalization,
        ).pack(side=LEFT, padx=(0, 8))
        ttk.Checkbutton(
            personal_frame,
            text="Whole Screen Rain",
            variable=self.whole_screen_rain_var,
            command=self._apply_personalization,
        ).pack(side=LEFT, padx=(0, 8))
        ttk.Button(personal_frame, text="Browse BG", command=self._browse_background_image).pack(side=LEFT, padx=(0, 8))
        ttk.Button(personal_frame, text="Apply Theme", command=self._apply_personalization).pack(side=LEFT, padx=(0, 8))
        ttk.Button(personal_frame, text="Save Theme", command=self._save_personalization).pack(side=LEFT)

        rain_controls = ttk.Frame(top)
        rain_controls.grid(row=6, column=1, pady=2, sticky="w")
        ttk.Label(rain_controls, text="Rain Speed").pack(side=LEFT, padx=(0, 6))
        ttk.Scale(
            rain_controls,
            from_=0.3,
            to=3.0,
            variable=self.rain_speed_var,
            command=self._on_rain_control_change,
            length=130,
        ).pack(side=LEFT, padx=(0, 4))
        ttk.Label(rain_controls, textvariable=self.rain_speed_text_var, width=6).pack(side=LEFT, padx=(0, 14))
        ttk.Label(rain_controls, text="Rain Density").pack(side=LEFT, padx=(0, 6))
        ttk.Scale(
            rain_controls,
            from_=0.5,
            to=2.5,
            variable=self.rain_density_var,
            command=self._on_rain_control_change,
            length=130,
        ).pack(side=LEFT, padx=(0, 4))
        ttk.Label(rain_controls, textvariable=self.rain_density_text_var, width=6).pack(side=LEFT, padx=(0, 14))

        run_btns = ttk.Frame(top)
        run_btns.grid(row=7, column=1, pady=8, sticky="w")
        self.run_snippet_button = ttk.Button(run_btns, text="Run Snippet Review", command=self._run_snippet_review)
        self.run_snippet_button.pack(side=LEFT, padx=(0, 8))
        self.run_zip_button = ttk.Button(run_btns, text="Run ZIP Review", command=self._run_zip_review)
        self.run_zip_button.pack(side=LEFT, padx=(0, 8))
        self.run_file_button = ttk.Button(run_btns, text="Run File Review (Any)", command=self._run_file_review)
        self.run_file_button.pack(side=LEFT, padx=(0, 8))
        self.run_folder_button = ttk.Button(run_btns, text="Run Folder Review", command=self._run_folder_review)
        self.run_folder_button.pack(side=LEFT, padx=(0, 8))
        self.auto_register_button = ttk.Button(
            run_btns, text="Auto Register ZIP Target", command=self._auto_register_zip_target
        )
        self.auto_register_button.pack(side=LEFT, padx=(0, 8))

        action_btns = ttk.Frame(top)
        action_btns.grid(row=8, column=1, pady=4, sticky="w")
        ttk.Button(action_btns, text="Copy Findings", command=self._copy_findings).pack(side=LEFT, padx=(0, 8))
        ttk.Button(action_btns, text="Copy Full JSON", command=self._copy_json).pack(side=LEFT, padx=(0, 8))
        ttk.Button(action_btns, text="Save Report", command=self._save_report).pack(side=LEFT, padx=(0, 8))
        ttk.Button(action_btns, text="Export Bounty Pack", command=self._export_bounty_pack).pack(side=LEFT, padx=(0, 8))
        ttk.Button(action_btns, text="Open Report Folder", command=self._open_report_folder).pack(side=LEFT, padx=(0, 8))
        ttk.Button(action_btns, text="Clear Chat", command=self._clear_chat).pack(side=LEFT)

        filter_frame = ttk.Frame(top)
        filter_frame.grid(row=9, column=1, pady=4, sticky="w")
        ttk.Label(filter_frame, text="Severity Filter").pack(side=LEFT, padx=(0, 8))
        for sev in SEVERITY_ORDER:
            ttk.Checkbutton(filter_frame, text=sev, variable=self.severity_vars[sev], command=self._apply_filters).pack(
                side=LEFT, padx=(0, 4)
            )
        ttk.Checkbutton(
            filter_frame,
            text="Zero-Knowledge Mode",
            variable=self.zero_knowledge_var,
            command=self._apply_filters,
        ).pack(side=LEFT, padx=(8, 8))
        ttk.Checkbutton(
            filter_frame,
            text="Report-Ready Mode",
            variable=self.report_ready_var,
            command=self._apply_filters,
        ).pack(side=LEFT, padx=(0, 8))
        ttk.Checkbutton(
            filter_frame,
            text="Validated-Only Queue",
            variable=self.validated_only_var,
            command=self._apply_filters,
        ).pack(side=LEFT, padx=(0, 8))
        ttk.Button(filter_frame, text="Apply Filters", command=self._apply_filters).pack(side=LEFT, padx=(0, 8))
        ttk.Button(filter_frame, text="Show Validation Guide", command=self._show_validation_guide).pack(side=LEFT, padx=(0, 8))

        history_frame = ttk.Frame(top)
        history_frame.grid(row=10, column=1, pady=4, sticky="w")
        ttk.Label(history_frame, text="Session History").pack(side=LEFT, padx=(0, 8))
        self.history_combo = ttk.Combobox(history_frame, textvariable=self.history_var, width=90, state="readonly")
        self.history_combo.pack(side=LEFT, padx=(0, 8))
        ttk.Button(history_frame, text="Refresh History", command=self._refresh_history).pack(side=LEFT, padx=(0, 8))
        ttk.Button(history_frame, text="Load Selected", command=self._load_selected_history).pack(side=LEFT)

        progress_frame = ttk.Frame(top)
        progress_frame.grid(row=11, column=1, pady=6, sticky="we")
        self.progress_bar = ttk.Progressbar(progress_frame, orient="horizontal", mode="determinate", length=620)
        self.progress_bar.pack(side=LEFT, padx=(0, 10))
        ttk.Label(progress_frame, textvariable=self.progress_text_var).pack(side=LEFT)

        self.binary_canvas = Canvas(self.root, height=110, highlightthickness=0, bd=0)
        self.binary_canvas.pack(fill=X, padx=10, pady=(0, 8))
        self.binary_canvas.bind("<Configure>", self._on_binary_canvas_resize)
        self.root.bind("<Configure>", self._on_root_resize)

        center = ttk.Panedwindow(self.root, orient="horizontal")
        center.pack(fill=BOTH, expand=True, padx=10, pady=(0, 10))

        left_frame = ttk.Frame(center, padding=6)
        right_frame = ttk.Frame(center, padding=6)
        center.add(left_frame, weight=1)
        center.add(right_frame, weight=1)

        snippet_header = ttk.Frame(left_frame)
        snippet_header.pack(fill=X, anchor="w")
        ttk.Label(snippet_header, text="Paste In-Scope Code Snippet").pack(side=LEFT)
        ttk.Button(snippet_header, text="Paste Snippet", command=self._paste_snippet).pack(side=RIGHT, padx=(6, 0))
        ttk.Button(snippet_header, text="Clear Snippet", command=self._clear_snippet).pack(side=RIGHT)
        self.snippet_box = ScrolledText(left_frame, wrap="none", height=34)
        self.snippet_box.pack(fill=BOTH, expand=True)
        self.snippet_context_menu = Menu(self.root, tearoff=0)
        self.snippet_context_menu.add_command(label="Paste", command=self._paste_snippet)
        self.snippet_context_menu.add_command(label="Copy", command=self._copy_snippet_selection)
        self.snippet_context_menu.add_command(label="Cut", command=self._cut_snippet_selection)
        self.snippet_context_menu.add_separator()
        self.snippet_context_menu.add_command(label="Select All", command=self._select_all_snippet)
        self.snippet_box.bind("<Control-v>", self._on_snippet_paste_shortcut)
        self.snippet_box.bind("<Control-V>", self._on_snippet_paste_shortcut)
        self.snippet_box.bind("<Control-Shift-V>", self._on_snippet_paste_shortcut)
        self.snippet_box.bind("<Shift-Insert>", self._on_snippet_paste_shortcut)
        self.snippet_box.bind("<Button-3>", self._show_snippet_context_menu)
        self.snippet_box.bind("<Button-2>", self._show_snippet_context_menu)

        ttk.Label(right_frame, text="Pipeline Chat / Output").pack(anchor="w")
        self.chat_box = ScrolledText(right_frame, wrap="word", state="disabled", height=34)
        self.chat_box.pack(fill=BOTH, expand=True)

        self._append_chat(
            "System",
            "Use snippet, ZIP, or folder mode. Findings appear here in copy-ready format. "
            "Use severity filters, Report-Ready/Validated-Only modes, Zero-Knowledge mode, and Validation Guide for safer triage.",
        )

    def _browse_config(self) -> None:
        path = filedialog.askopenfilename(
            title="Select OpenClaw Config",
            filetypes=[("YAML", "*.yaml *.yml"), ("All files", "*.*")],
        )
        if path:
            self.config_var.set(path)
            self._autofill_target_from_config(force=False, quiet=False)

    def _paste_clipboard_to_var(self, var: StringVar) -> None:
        try:
            clip = self.root.clipboard_get()
        except Exception:
            messagebox.showwarning("OpenClaw", "Clipboard is empty or unavailable.")
            return
        text = str(clip).strip()
        if not text:
            messagebox.showwarning("OpenClaw", "Clipboard is empty.")
            return
        var.set(text)

    def _paste_config_path(self) -> None:
        self._paste_clipboard_to_var(self.config_var)
        self._autofill_target_from_config(force=False, quiet=False)

    def _clear_snippet(self) -> None:
        self.snippet_box.delete("1.0", END)

    def _paste_snippet(self) -> None:
        try:
            clip = self.root.clipboard_get()
        except Exception:
            messagebox.showwarning("OpenClaw", "Clipboard is empty or unavailable.")
            return
        text = str(clip)
        if not text:
            return
        self.snippet_box.focus_set()
        try:
            self.snippet_box.delete("sel.first", "sel.last")
        except Exception:
            pass
        self.snippet_box.insert("insert", text)
        self.snippet_box.see("insert")

    def _copy_snippet_selection(self) -> None:
        try:
            self.snippet_box.event_generate("<<Copy>>")
        except Exception:
            pass

    def _cut_snippet_selection(self) -> None:
        try:
            self.snippet_box.event_generate("<<Cut>>")
        except Exception:
            pass

    def _select_all_snippet(self) -> None:
        self.snippet_box.focus_set()
        self.snippet_box.tag_add("sel", "1.0", END)
        self.snippet_box.mark_set("insert", "1.0")
        self.snippet_box.see("insert")

    def _on_snippet_paste_shortcut(self, _event: Any) -> str:
        self._paste_snippet()
        return "break"

    def _show_snippet_context_menu(self, event: Any) -> str:
        try:
            self.snippet_context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.snippet_context_menu.grab_release()
        return "break"

    def _browse_zip(self) -> None:
        path = filedialog.askopenfilename(
            title="Select Upload File (Archive or Any File)",
            filetypes=[("All files", "*.*"), ("ZIP", "*.zip")],
        )
        if path:
            self.zip_var.set(path)

    def _browse_folder(self) -> None:
        path = filedialog.askdirectory(title="Select Local Repository Folder")
        if path:
            self.folder_var.set(path)

    def _browse_background_image(self) -> None:
        path = filedialog.askopenfilename(
            title="Select Banner Background Image",
            filetypes=[("Image", "*.png *.gif *.ppm *.pgm"), ("All files", "*.*")],
        )
        if path:
            self.background_image_var.set(path)
            self._apply_personalization()

    def _load_scope_config(self) -> dict[str, Any] | None:
        config_path = self.config_var.get().strip()
        if not config_path:
            return None
        try:
            return load_config(config_path)
        except (ConfigError, FileNotFoundError, OSError):
            return None

    def _candidate_scope_target(self, preferred_prefix: str = "") -> str | None:
        config = self._load_scope_config()
        if not isinstance(config, dict):
            return None
        scope = config.get("scope", {})
        if not isinstance(scope, dict):
            return None
        preferred_prefix = preferred_prefix.strip().lower()
        repos = scope.get("github_repos", [])
        if isinstance(repos, list):
            if preferred_prefix:
                for item in repos:
                    value = str(item or "").strip()
                    if value and ("<" not in value and ">" not in value) and value.lower().startswith(preferred_prefix + "/"):
                        return value
            for item in repos:
                value = str(item or "").strip()
                if value and ("<" not in value and ">" not in value):
                    return value
            # Fallback only if every entry is placeholder-like.
            for item in repos:
                value = str(item or "").strip()
                if value:
                    return value
        domains = scope.get("domains", [])
        if isinstance(domains, list):
            for item in domains:
                value = str(item or "").strip()
                if value:
                    return value
        packages = scope.get("mobile_packages", [])
        if isinstance(packages, list):
            for item in packages:
                value = str(item or "").strip()
                if value:
                    return value
        return None

    def _is_target_currently_in_scope(self, target: str) -> bool:
        config = self._load_scope_config()
        if not isinstance(config, dict):
            return False
        return is_in_scope(target, config)

    def _autofill_target_from_config(self, *, force: bool, quiet: bool) -> str:
        current = self.target_var.get().strip()
        placeholders = {"", "program/repo/path.ext", "coinbase/<IN_SCOPE_REPO_1>"}
        needs_update = force or current in placeholders or (current and not self._is_target_currently_in_scope(current))
        if not needs_update:
            return current
        prefix = current.split("/", maxsplit=1)[0].strip() if "/" in current else ""
        candidate = self._candidate_scope_target(preferred_prefix=prefix)
        if candidate and candidate != current:
            self.target_var.set(candidate)
            if not quiet and hasattr(self, "chat_box"):
                self._append_chat("System", f"Target auto-set to in-scope value: {candidate}")
            return candidate
        return current

    def _set_scope_target(self) -> None:
        updated = self._autofill_target_from_config(force=True, quiet=False)
        if not updated or updated == self.target_var.get().strip():
            # If no candidate was found, give a clean hint.
            if not self._candidate_scope_target():
                messagebox.showinfo(
                    "OpenClaw",
                    "No in-scope target found in config. Add one under openclaw.scope.github_repos/domains/mobile_packages.",
                )

    def _normalize_hex_color(self, value: str, fallback: str) -> str:
        text = value.strip()
        if text.startswith("#") and len(text) == 4:
            text = "#" + "".join(ch * 2 for ch in text[1:])
        is_hex = text.startswith("#") and len(text) == 7 and all(ch in "0123456789abcdefABCDEF" for ch in text[1:])
        if not is_hex:
            return fallback
        return text.lower()

    def _load_personalization(self) -> None:
        if not self.personalization_path.exists():
            return
        try:
            payload = json.loads(self.personalization_path.read_text(encoding="utf-8"))
        except Exception:
            return
        if not isinstance(payload, dict):
            return
        self.operator_var.set(str(payload.get("operator", "")).strip())
        self.accent_var.set(str(payload.get("accent", "#39ff88")).strip() or "#39ff88")
        self.banner_text_var.set(str(payload.get("banner_text", "OPENCLAW // BOUNTY MODE")).strip() or "OPENCLAW // BOUNTY MODE")
        self.background_image_var.set(str(payload.get("background_image", "")).strip())
        self.binary_background_var.set(bool(payload.get("binary_background", True)))
        self.matrix_rain_var.set(bool(payload.get("matrix_rain", True)))
        self.rain_speed_var.set(float(payload.get("rain_speed", 1.0) or 1.0))
        self.rain_density_var.set(float(payload.get("rain_density", 1.0) or 1.0))
        self.glass_panels_var.set(bool(payload.get("glass_panels", True)))
        self.expanded_background_var.set(bool(payload.get("expanded_background", False)))
        self.whole_screen_rain_var.set(bool(payload.get("whole_screen_rain", False)))
        self._sync_rain_control_labels()

    def _save_personalization(self) -> None:
        self._apply_personalization(initial=True)
        payload = {
            "operator": self.operator_var.get().strip(),
            "accent": self._accent_color,
            "banner_text": self.banner_text_var.get().strip(),
            "background_image": self.background_image_var.get().strip(),
            "binary_background": bool(self.binary_background_var.get()),
            "matrix_rain": bool(self.matrix_rain_var.get()),
            "rain_speed": round(float(self.rain_speed_var.get()), 3),
            "rain_density": round(float(self.rain_density_var.get()), 3),
            "glass_panels": bool(self.glass_panels_var.get()),
            "expanded_background": bool(self.expanded_background_var.get()),
            "whole_screen_rain": bool(self.whole_screen_rain_var.get()),
            "saved_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            self.personalization_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception as exc:
            messagebox.showwarning("OpenClaw", f"Could not save personalization: {exc}")
            return
        self._append_chat("System", f"Theme saved to: {self.personalization_path}")

    def _sync_rain_control_labels(self) -> None:
        speed = max(0.3, min(3.0, float(self.rain_speed_var.get() or 1.0)))
        density = max(0.5, min(2.5, float(self.rain_density_var.get() or 1.0)))
        self.rain_speed_var.set(speed)
        self.rain_density_var.set(density)
        self.rain_speed_text_var.set(f"{speed:.2f}x")
        self.rain_density_text_var.set(f"{density:.2f}x")

    def _on_rain_control_change(self, _value: str = "") -> None:
        self._sync_rain_control_labels()
        self._rain_columns = 0
        if self.binary_background_var.get() and self.matrix_rain_var.get():
            if self._rain_job is None:
                self._start_rain_loop()
        else:
            self._draw_binary_banner()

    def _init_rain_state(self, width: int, height: int) -> None:
        density_boost = 1.35 if self.expanded_background_var.get() else 1.0
        density_boost *= float(self.rain_density_var.get() or 1.0)
        if self.whole_screen_rain_var.get():
            density_boost *= 1.2
        columns = max(20, int((width / 10) * density_boost))
        rows = max(8, int(height / 16) + 2)
        if columns == self._rain_columns and rows == self._rain_rows and self._rain_drops:
            return
        self._rain_columns = columns
        self._rain_rows = rows
        self._rain_drops = []
        for _ in range(columns):
            self._rain_drops.append(
                {
                    "y": random.uniform(-rows, rows),
                    "speed": random.uniform(0.45, 1.75),
                    "trail": random.uniform(6, 16),
                }
            )

    def _draw_binary_banner(self) -> None:
        canvas = self.binary_canvas
        width = max(canvas.winfo_width(), 1)
        height = max(canvas.winfo_height(), 1)
        canvas.delete("all")
        canvas.configure(background="#040913")

        if self._banner_image is not None:
            canvas.create_image(width // 2, height // 2, image=self._banner_image, anchor="center")
            canvas.create_rectangle(0, 0, width, height, fill="#040913", stipple="gray50", outline="")

        if self.binary_background_var.get():
            if self.matrix_rain_var.get():
                self._init_rain_state(width, height)
                col_step = width / max(self._rain_columns, 1)
                speed_multiplier = float(self.rain_speed_var.get() or 1.0)
                for idx, drop in enumerate(self._rain_drops):
                    drop["y"] += drop["speed"] * speed_multiplier
                    if drop["y"] * 16 > height + (drop["trail"] * 16):
                        drop["y"] = random.uniform(-self._rain_rows, 0)
                        drop["speed"] = random.uniform(0.45, 1.75)
                        drop["trail"] = random.uniform(6, 16)
                    x = int(idx * col_step) + 3
                    head_row = int(drop["y"])
                    trail_len = int(drop["trail"])
                    for trail_idx in range(trail_len):
                        row = head_row - trail_idx
                        if row < 0 or row > self._rain_rows:
                            continue
                        y = row * 16
                        if trail_idx == 0:
                            color = "#f5fff7"
                        elif trail_idx <= 2:
                            color = self._accent_color
                        elif trail_idx <= 6:
                            color = "#49b783"
                        else:
                            color = "#24384e"
                        canvas.create_text(x, y, text=random.choice("01"), anchor=NW, fill=color, font=("Consolas", 11))
            else:
                density_boost = 1.45 if self.expanded_background_var.get() else 1.0
                cols = max(12, int((width // 46) * density_boost))
                rows = max(3, int((height // 16) * density_boost))
                col_step = width / max(cols, 1)
                for col in range(cols):
                    x = int(col * col_step) + 4
                    for row in range(rows):
                        y = 4 + row * 16
                        bits = "".join(random.choice("01") for _ in range(8))
                        color = self._accent_color if (col + row) % 5 == 0 else "#314059"
                        canvas.create_text(x, y, text=bits, anchor=NW, fill=color, font=("Consolas", 8))

        caption = self.banner_text_var.get().strip() or "OPENCLAW // BOUNTY MODE"
        operator = self.operator_var.get().strip()
        canvas.create_text(12, height - 10, text=caption, anchor="sw", fill=self._accent_color, font=("Consolas", 11, "bold"))
        if operator:
            canvas.create_text(width - 12, height - 10, text=f"OPERATOR: {operator.upper()}", anchor="se", fill="#d3ddf4", font=("Consolas", 10))

    def _on_binary_canvas_resize(self, _event: Any) -> None:
        self._rain_columns = 0
        self._draw_binary_banner()

    def _on_root_resize(self, _event: Any) -> None:
        if self.whole_screen_rain_var.get():
            now_h = self.root.winfo_height()
            if abs(now_h - self._last_whole_screen_height) >= 18:
                self._last_whole_screen_height = now_h
                self._apply_personalization(initial=True)

    def _stop_rain_loop(self) -> None:
        if self._rain_job is not None:
            try:
                self.root.after_cancel(self._rain_job)
            except Exception:
                pass
            self._rain_job = None

    def _start_rain_loop(self) -> None:
        self._stop_rain_loop()
        self._rain_tick()

    def _rain_tick(self) -> None:
        self._draw_binary_banner()
        if self.binary_background_var.get() and self.matrix_rain_var.get():
            speed_multiplier = max(0.3, min(3.0, float(self.rain_speed_var.get() or 1.0)))
            delay_ms = int(max(22, min(130, 85 / speed_multiplier)))
            self._rain_job = self.root.after(delay_ms, self._rain_tick)
        else:
            self._rain_job = None

    def _apply_personalization(self, initial: bool = False) -> None:
        self._accent_color = self._normalize_hex_color(self.accent_var.get(), "#39ff88")
        self.accent_var.set(self._accent_color)
        self._sync_rain_control_labels()

        operator = self.operator_var.get().strip()
        self.root.title(f"{self.base_title} - {operator}" if operator else self.base_title)

        self._banner_image = None
        image_path = self.background_image_var.get().strip()
        if image_path:
            image_file = Path(image_path)
            if image_file.exists():
                try:
                    self._banner_image = PhotoImage(file=str(image_file))
                except Exception as exc:
                    if not initial:
                        messagebox.showwarning("OpenClaw", f"Could not load background image: {exc}")
            elif not initial:
                messagebox.showwarning("OpenClaw", f"Background image not found: {image_file}")

        if self.whole_screen_rain_var.get():
            win_h = max(self.root.winfo_height(), 920)
            banner_height = max(240, min(640, win_h - 320))
        else:
            banner_height = 220 if self.expanded_background_var.get() else 110
        self.binary_canvas.configure(height=banner_height)
        self._apply_panel_look()
        if self.binary_background_var.get() and self.matrix_rain_var.get():
            self._start_rain_loop()
        else:
            self._stop_rain_loop()
            self._draw_binary_banner()
        if not initial:
            mode = "ON" if self.binary_background_var.get() else "OFF"
            rain = "ON" if self.matrix_rain_var.get() else "OFF"
            glass = "ON" if self.glass_panels_var.get() else "OFF"
            full = "ON" if self.whole_screen_rain_var.get() else "OFF"
            self._append_chat(
                "System",
                f"Theme applied. Accent {self._accent_color}, binary background {mode}, rain {rain}, speed {self.rain_speed_text_var.get()}, density {self.rain_density_text_var.get()}, glass panels {glass}, whole screen rain {full}, operator {operator or 'default'}.",
            )

    def _apply_panel_look(self) -> None:
        if self.glass_panels_var.get():
            bg = "#0b1220"
            fg = "#d8e2f7"
            caret = self._accent_color
            select = "#1a365f"
        else:
            bg = "white"
            fg = "black"
            caret = "black"
            select = "#c9def5"
        self.snippet_box.configure(
            bg=bg,
            fg=fg,
            insertbackground=caret,
            selectbackground=select,
            selectforeground=fg,
            relief="flat",
            borderwidth=0,
            highlightthickness=1,
            highlightbackground="#1a2336",
            highlightcolor=self._accent_color,
        )
        self.chat_box.configure(
            bg=bg,
            fg=fg,
            insertbackground=caret,
            selectbackground=select,
            selectforeground=fg,
            relief="flat",
            borderwidth=0,
            highlightthickness=1,
            highlightbackground="#1a2336",
            highlightcolor=self._accent_color,
        )

    def _append_chat(self, role: str, message: str) -> None:
        self.chat_box.configure(state="normal")
        self.chat_box.insert(END, f"{role}:\n{message}\n\n")
        self.chat_box.see(END)
        self.chat_box.configure(state="disabled")

    def _set_busy(self, busy: bool) -> None:
        state = "disabled" if busy else "normal"
        self.run_snippet_button.configure(state=state)
        self.run_zip_button.configure(state=state)
        self.run_file_button.configure(state=state)
        self.run_folder_button.configure(state=state)
        self.auto_register_button.configure(state=state)

    def _set_progress(self, value: int, text: str) -> None:
        self.progress_bar["value"] = max(0, min(100, value))
        self.progress_text_var.set(text)

    def _normalize_severity(self, value: Any) -> str:
        text = str(value or "Medium").strip().lower()
        mapping = {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Info",
            "informational": "Info",
        }
        return mapping.get(text, "Medium")

    def _active_severities(self) -> set[str]:
        selected = {sev for sev, var in self.severity_vars.items() if bool(var.get())}
        if not selected:
            return set(SEVERITY_ORDER)
        return selected

    def _current_filter_mode(self) -> str:
        if self.validated_only_var.get():
            return "validated_only"
        if self.report_ready_var.get():
            return "report_ready"
        return "all_findings"

    def _sorted_selected_severities(self) -> list[str]:
        active = self._active_severities()
        return [sev for sev in SEVERITY_ORDER if sev in active]

    def _filtered_findings(self) -> list[dict[str, Any]]:
        allowed = self._active_severities()
        base = list(self.last_findings)
        if self.validated_only_var.get():
            base = filter_validated_ready_findings(base)
        elif self.report_ready_var.get():
            base = filter_report_ready_findings(base)
        out: list[dict[str, Any]] = []
        for item in base:
            sev = self._normalize_severity(item.get("severity"))
            if sev in allowed:
                out.append(item)
        return out

    def _format_zero_knowledge_findings(self, findings: list[dict[str, Any]]) -> str:
        if not findings:
            return "No findings were generated."
        lines: list[str] = []
        for idx, item in enumerate(findings, start=1):
            bug = str(item.get("title", "Untitled finding"))
            impact = str(item.get("summary", ""))
            severity = self._normalize_severity(item.get("severity"))
            recs = item.get("recommendations", [])
            if isinstance(recs, list) and recs:
                fix = str(recs[0])
            else:
                fix = "Apply least-privilege checks, strict validation, and safe defaults."
            lines.append(f"{idx}. Bug: {bug}")
            lines.append(f"Impact: {impact}")
            lines.append(f"Severity: {severity}")
            lines.append(f"Fix: {fix}")
            lines.append("")
        return "\n".join(lines).strip()

    def _render_findings_for_current_filters(self) -> tuple[str, str]:
        filtered = self._filtered_findings()
        if self.zero_knowledge_var.get():
            findings_text = self._format_zero_knowledge_findings(filtered)
        else:
            findings_text = format_hackerone_findings(filtered)
        json_text = json.dumps(filtered, indent=2)
        return findings_text, json_text

    def _apply_filters(self) -> None:
        if not self.last_findings:
            return
        findings_text, json_text = self._render_findings_for_current_filters()
        self.last_copy_text = findings_text
        self.last_json_text = json_text
        self.last_rendered_text = findings_text
        self._append_chat(
            "System",
            f"Filters applied ({self._current_filter_mode()}). "
            f"Showing {len(self._filtered_findings())} of {len(self.last_findings)} findings.",
        )

    def _show_validation_guide(self) -> None:
        if not self.last_findings:
            messagebox.showinfo("OpenClaw", "No findings yet. Run a review first.")
            return
        findings = self._filtered_findings()
        if not findings:
            self._append_chat("OpenClaw", "Validation guide: no findings in the current filter set.")
            return
        lines: list[str] = ["Validation Guide (safe manual review checklist):", ""]
        for idx, item in enumerate(findings, start=1):
            lines.append(f"{idx}. {item.get('title', 'Untitled finding')}")
            lines.append(f"Category: {item.get('category', 'general_security')}")
            lines.append(f"Component: {item.get('component', '')}")
            for check in validation_checklist_for_finding(item):
                lines.append(f"- {check}")
            lines.append("")
        self._append_chat("OpenClaw", "\n".join(lines).strip())

    def _stage_text(self, stage: str, status: str, details: dict[str, Any]) -> str:
        label = STAGE_LABELS.get(stage, stage.replace("_", " ").title())
        if status == "start":
            return f"{label}..."
        if stage == "complete":
            final = details.get("final_findings")
            if final is not None:
                return f"Run complete. Final findings: {final}."
        return f"{label} complete."

    def _on_progress_event(self, stage: str, status: str, details: dict[str, Any]) -> None:
        if status == "done":
            pct = STAGE_PROGRESS.get(stage, int(self.progress_bar["value"]))
            self.progress_bar["value"] = max(int(self.progress_bar["value"]), pct)
        elif status == "start":
            pct = STAGE_PROGRESS.get(stage, int(self.progress_bar["value"]))
            self.progress_bar["value"] = max(0, min(100, pct - 4))
        self.progress_text_var.set(self._stage_text(stage, status, details))

    def _handle_run_success(self, mode: str, result: Any, input_ref: str) -> None:
        self.last_findings = list(result.findings)
        self.last_summary = dict(result.summary)
        self.last_report_path = result.markdown_report or result.summary.get("session_dir", "")

        findings_text, json_text = self._render_findings_for_current_filters()
        self.last_copy_text = findings_text
        self.last_json_text = json_text
        self.last_rendered_text = findings_text

        summary_text = json.dumps(result.summary, indent=2)
        stage_errors = result.summary.get("stage_errors", {}) if isinstance(result.summary, dict) else {}
        stage_error_text = ""
        if isinstance(stage_errors, dict) and stage_errors:
            stage_error_text = f"\nStage errors (graceful fallback applied):\n{json.dumps(stage_errors, indent=2)}\n"

        self._append_chat(
            "OpenClaw",
            f"{mode} run complete.\n\nSummary:\n{summary_text}\n\n{stage_error_text}"
            f"Copy/Paste Findings:\n{findings_text}\n",
        )
        self._set_progress(100, "Run complete.")
        self._record_history_entry(mode=mode, input_ref=input_ref)
        self._refresh_history()

    def _run_in_background(
        self,
        *,
        mode: str,
        user_message: str,
        system_message: str,
        input_ref: str,
        run_callable: Callable[[Callable[[str, str, dict[str, Any]], None]], Any],
    ) -> None:
        self._append_chat("You", user_message)
        self._append_chat("System", system_message)
        self._set_busy(True)
        self._set_progress(0, "Starting run...")

        def progress_callback(stage: str, status: str, details: dict[str, Any]) -> None:
            self.root.after(
                0,
                lambda stage=stage, status=status, details=dict(details): self._on_progress_event(stage, status, details),
            )

        def worker() -> None:
            try:
                result = run_callable(progress_callback)
                self.root.after(
                    0,
                    lambda result=result, mode=mode, input_ref=input_ref: self._handle_run_success(mode, result, input_ref),
                )
            except Exception as exc:
                err = str(exc)
                self.root.after(0, lambda err=err: self._append_chat("OpenClaw", f"{mode} run failed: {err}"))
                self.root.after(0, lambda: self._set_progress(0, "Run failed."))
            finally:
                self.root.after(0, lambda: self._set_busy(False))

        threading.Thread(target=worker, daemon=True).start()

    def _run_snippet_review(self) -> None:
        self._autofill_target_from_config(force=False, quiet=False)
        snippet = self.snippet_box.get("1.0", END).strip()
        if not snippet:
            messagebox.showwarning("OpenClaw", "Paste a code snippet first.")
            return

        config_path = self.config_var.get().strip()
        target = self.target_var.get().strip()
        file_name = self.file_var.get().strip() or "snippet.py"
        if not config_path or not target:
            messagebox.showwarning("OpenClaw", "Config path and target are required.")
            return

        self._run_in_background(
            mode="Snippet",
            user_message=f"Run snippet review for target `{target}` with pasted snippet `{file_name}`.",
            system_message="Running snippet pipeline now.",
            input_ref=file_name,
            run_callable=lambda progress_cb: run_snippet_pipeline(
                config_path=config_path,
                target=target,
                code_snippet=snippet,
                file_name=file_name,
                progress_callback=progress_cb,
            ),
        )

    def _run_zip_review(self) -> None:
        self._autofill_target_from_config(force=False, quiet=False)
        zip_path = self.zip_var.get().strip()
        config_path = self.config_var.get().strip()
        target = self.target_var.get().strip()
        if not zip_path:
            messagebox.showwarning("OpenClaw", "Select a ZIP file first.")
            return
        if not config_path or not target:
            messagebox.showwarning("OpenClaw", "Config path and target are required.")
            return

        self._run_in_background(
            mode="ZIP",
            user_message=f"Run ZIP review for target `{target}` using archive `{zip_path}`.",
            system_message="Running ZIP pipeline now. Large repos can take several minutes.",
            input_ref=zip_path,
            run_callable=lambda progress_cb: run_zip_pipeline(
                config_path=config_path,
                target=target,
                zip_path=zip_path,
                progress_callback=progress_cb,
            ),
        )

    def _run_file_review(self) -> None:
        self._autofill_target_from_config(force=False, quiet=False)
        file_path = self.zip_var.get().strip()
        config_path = self.config_var.get().strip()
        target = self.target_var.get().strip()
        if not file_path:
            messagebox.showwarning("OpenClaw", "Select an upload file first.")
            return
        if not config_path or not target:
            messagebox.showwarning("OpenClaw", "Config path and target are required.")
            return

        self._run_in_background(
            mode="File",
            user_message=f"Run file review for target `{target}` using upload `{file_path}`.",
            system_message=(
                "Running file pipeline now. Supported archives are extracted safely "
                "(.zip/.tar/.tar.gz/.tgz/.tar.bz2/.tar.xz); other files are analyzed in isolated workspace."
            ),
            input_ref=file_path,
            run_callable=lambda progress_cb: run_file_pipeline(
                config_path=config_path,
                target=target,
                file_path=file_path,
                progress_callback=progress_cb,
            ),
        )

    def _run_folder_review(self) -> None:
        self._autofill_target_from_config(force=False, quiet=False)
        folder_path = self.folder_var.get().strip()
        config_path = self.config_var.get().strip()
        target = self.target_var.get().strip()
        if not folder_path:
            messagebox.showwarning("OpenClaw", "Select a local folder first.")
            return
        if not config_path or not target:
            messagebox.showwarning("OpenClaw", "Config path and target are required.")
            return

        self._run_in_background(
            mode="Folder",
            user_message=f"Run folder review for target `{target}` using repo path `{folder_path}`.",
            system_message="Running folder pipeline now.",
            input_ref=folder_path,
            run_callable=lambda progress_cb: run_repo_pipeline(
                config_path=config_path,
                target=target,
                repo_path=folder_path,
                progress_callback=progress_cb,
            ),
        )

    def _auto_register_zip_target(self) -> None:
        zip_path = self.zip_var.get().strip()
        config_path = self.config_var.get().strip()
        current_target = self.target_var.get().strip()
        if not zip_path:
            messagebox.showwarning("OpenClaw", "Select a ZIP file first.")
            return
        if Path(zip_path).suffix.lower() != ".zip":
            self._append_chat(
                "OpenClaw",
                "Auto-register supports ZIP only. For non-ZIP uploads, set Target manually or click 'Use In-Scope'.",
            )
            return
        if not config_path:
            messagebox.showwarning("OpenClaw", "Config path is required.")
            return

        try:
            result = auto_register_repo_from_zip(
                config_path=config_path,
                zip_path=zip_path,
                current_target=current_target,
            )
        except AutoRegisterError as exc:
            self._append_chat("OpenClaw", f"Auto-register failed: {exc}")
            return
        except Exception as exc:
            self._append_chat("OpenClaw", f"Auto-register failed unexpectedly: {exc}")
            return

        self.target_var.set(result.target)
        action = "added to scope config" if result.added_to_scope else "already present in scope config"
        self._append_chat(
            "OpenClaw",
            "Auto-register complete.\n\n"
            f"Target set to: {result.target}\n"
            f"Repo slug: {result.repo_slug} ({action})\n"
            f"Config backup: {result.backup_path}",
        )

    def _copy_findings(self) -> None:
        if not self.last_copy_text:
            messagebox.showinfo("OpenClaw", "No findings yet. Run a review first.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(self.last_copy_text)
        self._append_chat("System", "Findings copied to clipboard.")

    def _copy_json(self) -> None:
        if not self.last_json_text:
            messagebox.showinfo("OpenClaw", "No JSON findings yet. Run a review first.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(self.last_json_text)
        self._append_chat("System", "JSON findings copied to clipboard.")

    def _save_report(self) -> None:
        if not self.last_findings:
            messagebox.showinfo("OpenClaw", "No findings yet. Run a review first.")
            return
        output_path = filedialog.asksaveasfilename(
            title="Save Report",
            defaultextension=".md",
            filetypes=[("Markdown", "*.md"), ("JSON", "*.json"), ("All files", "*.*")],
        )
        if not output_path:
            return
        save_path = Path(output_path)
        if save_path.suffix.lower() == ".json":
            save_path.write_text(self.last_json_text, encoding="utf-8")
        else:
            content = (
                f"# OpenClaw Findings Export\n\n"
                f"- Generated: {datetime.now(timezone.utc).isoformat()}\n"
                f"- Target: {self.target_var.get().strip()}\n"
                f"- Displayed findings: {len(self._filtered_findings())}\n\n"
                f"{self.last_rendered_text}\n"
            )
            save_path.write_text(content, encoding="utf-8")
        self._append_chat("System", f"Saved report to: {save_path}")

    def _export_bounty_pack(self) -> None:
        if not self.last_findings:
            messagebox.showinfo("OpenClaw", "No findings yet. Run a review first.")
            return
        out_dir = filedialog.askdirectory(
            title="Select Export Folder for Bounty Pack",
            initialdir=str((Path.cwd() / "reports").resolve()),
        )
        if not out_dir:
            return
        findings = self._filtered_findings()
        findings_text, _ = self._render_findings_for_current_filters()
        artifacts = export_bounty_pack(
            output_root=out_dir,
            target=self.target_var.get().strip(),
            findings=findings,
            findings_text=findings_text,
            summary=self.last_summary,
            filter_mode=self._current_filter_mode(),
            selected_severities=self._sorted_selected_severities(),
        )
        self._append_chat(
            "System",
            "Bounty pack exported.\n\n"
            f"Folder: {artifacts['pack_dir']}\n"
            f"ZIP: {artifacts['zip_path']}\n"
            f"Findings: {artifacts['findings_markdown']}\n"
            f"Checklist: {artifacts['checklist_markdown']}",
        )

    def _open_report_folder(self) -> None:
        if not self.last_report_path:
            messagebox.showinfo("OpenClaw", "No report path available yet.")
            return
        path = Path(self.last_report_path)
        folder = path if path.is_dir() else path.parent
        if not folder.exists():
            messagebox.showwarning("OpenClaw", f"Path not found: {folder}")
            return
        try:
            import os

            if hasattr(os, "startfile"):
                os.startfile(str(folder))  # type: ignore[attr-defined]
            else:
                subprocess.run(["xdg-open", str(folder)], check=False)
        except Exception as exc:
            messagebox.showwarning("OpenClaw", f"Could not open folder: {exc}")

    def _history_file_path(self) -> Path:
        base = Path.cwd() / "reports"
        base.mkdir(parents=True, exist_ok=True)
        return (base / "dashboard_history.jsonl").resolve()

    def _severity_counts(self, findings: list[dict[str, Any]]) -> dict[str, int]:
        counts = {sev: 0 for sev in SEVERITY_ORDER}
        for item in findings:
            counts[self._normalize_severity(item.get("severity"))] += 1
        return counts

    def _record_history_entry(self, *, mode: str, input_ref: str) -> None:
        entry = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "mode": mode,
            "target": self.target_var.get().strip(),
            "config_path": self.config_var.get().strip(),
            "input_ref": input_ref,
            "report_path": self.last_report_path,
            "summary": self.last_summary,
            "findings_count": len(self.last_findings),
            "severity_counts": self._severity_counts(self.last_findings),
        }
        history_path = self._history_file_path()
        with history_path.open("a", encoding="utf-8") as fp:
            fp.write(json.dumps(entry) + "\n")

    def _refresh_history(self) -> None:
        history_path = self._history_file_path()
        entries: list[dict[str, Any]] = []
        if history_path.exists():
            for line in history_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                text = line.strip()
                if not text:
                    continue
                try:
                    parsed = json.loads(text)
                except Exception:
                    continue
                if isinstance(parsed, dict):
                    entries.append(parsed)
        entries = entries[-100:]
        entries.reverse()
        self.history_entries = entries
        labels: list[str] = []
        self.history_label_to_index = {}
        for idx, entry in enumerate(entries):
            label = (
                f"[{idx + 1}] {entry.get('created_at', '')} | "
                f"{entry.get('mode', '?')} | {entry.get('target', '?')} | "
                f"findings={entry.get('findings_count', 0)}"
            )
            labels.append(label)
            self.history_label_to_index[label] = idx
        self.history_combo["values"] = labels
        if labels:
            self.history_var.set(labels[0])

    def _load_selected_history(self) -> None:
        label = self.history_var.get().strip()
        if not label:
            messagebox.showinfo("OpenClaw", "No history session selected.")
            return
        idx = self.history_label_to_index.get(label)
        if idx is None:
            messagebox.showwarning("OpenClaw", "Selected history item not found.")
            return
        entry = self.history_entries[idx]
        self.target_var.set(str(entry.get("target", self.target_var.get())))
        report_path = str(entry.get("report_path", ""))
        summary = entry.get("summary", {})
        findings: list[dict[str, Any]] = []
        if isinstance(summary, dict):
            json_path = summary.get("report_paths", {}).get("json_report", "")
            if json_path and Path(str(json_path)).exists():
                try:
                    loaded = json.loads(Path(str(json_path)).read_text(encoding="utf-8"))
                    if isinstance(loaded, list):
                        findings = [item for item in loaded if isinstance(item, dict)]
                except Exception:
                    findings = []
        self.last_findings = findings
        self.last_summary = summary if isinstance(summary, dict) else {}
        self.last_report_path = report_path
        if findings:
            findings_text, json_text = self._render_findings_for_current_filters()
            self.last_copy_text = findings_text
            self.last_json_text = json_text
            self.last_rendered_text = findings_text
            self._append_chat(
                "OpenClaw",
                f"Loaded session from history.\nTarget: {self.target_var.get().strip()}\n"
                f"Findings loaded: {len(findings)}",
            )
        else:
            self._append_chat("OpenClaw", "Loaded history metadata, but no JSON findings file was found.")

    def _clear_chat(self) -> None:
        self.chat_box.configure(state="normal")
        self.chat_box.delete("1.0", END)
        self.chat_box.configure(state="disabled")
        self._append_chat("System", "Chat cleared.")


def main() -> int:
    if not TK_AVAILABLE:
        raise SystemExit(
            "Tkinter is not available in this Python runtime. "
            "On Ubuntu/WSL run: sudo apt update && sudo apt install -y python3-tk\n"
            f"Original error: {_TK_IMPORT_ERROR}"
        )
    root = Tk()
    OpenClawDashboard(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

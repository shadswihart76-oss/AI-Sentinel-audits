from __future__ import annotations

import argparse
import json
from pathlib import Path


def read_prompt(args: argparse.Namespace) -> str:
    if args.prompt_file:
        return Path(args.prompt_file).read_text(encoding="utf-8", errors="ignore")
    return input_stream()


def input_stream() -> str:
    import sys

    return sys.stdin.read()


def build_response(prompt: str) -> dict:
    findings: list[dict] = []

    lowered = prompt.lower()
    auth_binding_tokens = [
        "get_current_user_id(",
        "wp_get_current_user(",
        "current_user_can(",
        "req.user",
        "request.user",
        "auth()->id(",
    ]
    request_identity_tokens = [
        "$_get['user_id'",
        "$_post['user_id'",
        "$_request['user_id'",
        "req.params.user",
        "req.query.user",
        "req.body.user",
        "request.args.get('user_id'",
        "request.get('user_id'",
        "params['user_id']",
    ]

    has_auth_binding = any(token in lowered for token in auth_binding_tokens)
    has_request_identity = any(token in lowered for token in request_identity_tokens)

    if has_request_identity and not has_auth_binding:
        findings.append(
            {
                "title": "Potential ownership check gap",
                "summary": "Code appears to use user identifiers; verify ownership binding to authenticated identity.",
                "severity": "Medium",
                "category": "auth_access",
                "recommendations": [
                    "Derive identity from authenticated context instead of request parameters.",
                    "Enforce per-resource authorization before returning data.",
                ],
            }
        )
    if "http://" in lowered or "requests.get(" in lowered:
        findings.append(
            {
                "title": "Potential user-influenced outbound request",
                "summary": "Review destination validation and allowlist checks for outbound HTTP requests.",
                "severity": "Medium",
                "category": "ssrf",
                "recommendations": [
                    "Restrict outbound schemes and hosts using explicit allowlists.",
                    "Reject private or loopback IP resolution results before request dispatch.",
                ],
            }
        )

    return {"findings": findings}


def main() -> int:
    parser = argparse.ArgumentParser(description="Local OpenClaw model stub.")
    parser.add_argument("--model", default="stub-model")
    parser.add_argument("--prompt-file", default=None)
    args = parser.parse_args()

    prompt = read_prompt(args)
    response = build_response(prompt)
    print(json.dumps(response))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

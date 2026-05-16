#!/usr/bin/env python3
"""Render a sanitized ghappjwt JSON report as Markdown."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def code(value: Any) -> str:
    return f"`{value}`"


def result_section(result: dict[str, Any]) -> list[str]:
    token = result.get("token")
    lines = [f"### {result.get('request', 'request')}"]
    lines.append("")
    lines.append(f"- HTTP status: {code(result.get('http_status'))}")

    if not isinstance(token, dict):
        body = result.get("body", {})
        message = body.get("message") if isinstance(body, dict) else None
        if message:
            lines.append(f"- API message: {code(message)}")
        return lines

    lines.extend(
        [
            f"- Prefix: {code(token.get('prefix'))}",
            f"- Length: {code(token.get('length'))}",
            f"- Dots after `ghs_`: {code(token.get('dots_after_prefix'))}",
            f"- JWT-like: {code(token.get('jwt_like'))}",
            f"- Compatible with recommended regex: {code(token.get('recommended_regex_match'))}",
        ]
    )

    decoded = result.get("decoded_jwt")
    if isinstance(decoded, dict):
        safe_decoded = {
            "header": decoded.get("header"),
            "payload": decoded.get("payload"),
            "signature": decoded.get("signature"),
        }
        lines.append("")
        lines.append("<details>")
        lines.append("<summary>Decoded JWT header/payload</summary>")
        lines.append("")
        lines.append("```json")
        lines.append(json.dumps(safe_decoded, indent=2, sort_keys=True))
        lines.append("```")
        lines.append("</details>")
    else:
        lines.append(f"- Decoded JWT: {code(decoded)}")

    return lines


def render(report: dict[str, Any]) -> str:
    app = report.get("app", {})
    lines = [
        "## GitHub App Installation Token Format Capture",
        "",
        f"- Captured at: {code(report.get('captured_at'))}",
        f"- App ID: {code(app.get('app_id'))}",
        f"- Installation ID: {code(app.get('installation_id'))}",
        f"- API version: {code(app.get('api_version'))}",
        "",
    ]

    for result in report.get("results", []):
        if isinstance(result, dict):
            lines.extend(result_section(result))
            lines.append("")

    lines.append("_Full installation tokens are not printed by this workflow._")
    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: render_issue_comment.py <capture-output.json>", file=sys.stderr)
        return 2

    report = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
    print(render(report), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

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
    response_headers = result.get("response_headers", {})
    lines = [f"### {result.get('request', 'request')}"]
    lines.append("")
    if "attempt" in result:
        lines.append(f"- Attempt: {code(result.get('attempt'))}")
    lines.append(f"- HTTP status: {code(result.get('http_status'))}")
    if isinstance(response_headers, dict):
        request_id = response_headers.get("x-github-request-id")
        if request_id:
            lines.append(f"- GitHub request ID: {code(request_id)}")

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
            f"- Token format: {code(token.get('token_format'))}",
            f"- JWT-like: {code(token.get('jwt_like'))}",
            f"- Compatible with recommended regex: {code(token.get('recommended_regex_match'))}",
        ]
    )
    if token.get("embedded_app_id"):
        lines.append(f"- Embedded App ID: {code(token.get('embedded_app_id'))}")
    if result.get("sha256"):
        lines.append(f"- SHA-256: {code(result.get('sha256'))}")

    decoded = result.get("decoded_jwt")
    if isinstance(decoded, dict):
        safe_decoded = {
            "token_format": decoded.get("token_format"),
            "embedded_app_id": decoded.get("embedded_app_id"),
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
        specimen = result.get("redacted_jwt_specimen")
        if isinstance(specimen, dict):
            lines.append("")
            lines.append("<details>")
            lines.append("<summary>JWT specimen with signature redacted</summary>")
            lines.append("")
            lines.append("```text")
            lines.append(str(specimen.get("value")))
            lines.append("```")
            lines.append(str(specimen.get("note")))
            lines.append("</details>")
    else:
        lines.append(f"- Decoded JWT: {code(decoded)}")

    return lines


def provided_token_section(result: dict[str, Any]) -> list[str]:
    lines = [f"### Provided token: {result.get('source', 'unknown')}"]
    lines.append("")

    error = result.get("error")
    if error:
        lines.append(f"- Error: {code(error)}")
        return lines

    token = result.get("token")
    if not isinstance(token, dict):
        lines.append("- Token summary unavailable")
        return lines

    lines.extend(
        [
            f"- Prefix: {code(token.get('prefix'))}",
            f"- Length: {code(token.get('length'))}",
            f"- Dots after `ghs_`: {code(token.get('dots_after_prefix'))}",
            f"- Token format: {code(token.get('token_format'))}",
            f"- JWT-like: {code(token.get('jwt_like'))}",
            f"- Compatible with recommended regex: {code(token.get('recommended_regex_match'))}",
        ]
    )
    if token.get("embedded_app_id"):
        lines.append(f"- Embedded App ID: {code(token.get('embedded_app_id'))}")
    if result.get("sha256"):
        lines.append(f"- SHA-256: {code(result.get('sha256'))}")

    decoded = result.get("decoded_jwt")
    if isinstance(decoded, dict):
        safe_decoded = {
            "token_format": decoded.get("token_format"),
            "embedded_app_id": decoded.get("embedded_app_id"),
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
        specimen = result.get("redacted_jwt_specimen")
        if isinstance(specimen, dict):
            lines.append("")
            lines.append("<details>")
            lines.append("<summary>JWT specimen with signature redacted</summary>")
            lines.append("")
            lines.append("```text")
            lines.append(str(specimen.get("value")))
            lines.append("```")
            lines.append(str(specimen.get("note")))
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
        f"- JWT-shaped custom App installation token found: {code(report.get('jwt_like_installation_token_found'))}",
        f"- JWT-shaped provided token found: {code(report.get('jwt_like_provided_token_found'))}",
        f"- JWT-shaped token found in any source: {code(report.get('jwt_like_token_found'))}",
        "",
    ]

    for result in report.get("results", []):
        if isinstance(result, dict):
            lines.extend(result_section(result))
            lines.append("")

    for result in report.get("provided_tokens", []):
        if isinstance(result, dict):
            lines.extend(provided_token_section(result))
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

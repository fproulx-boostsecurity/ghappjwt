#!/usr/bin/env python3
"""Exit 0 only when a capture report contains any JWT-shaped token."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def has_jwt_like_installation_token(report: dict[str, Any]) -> bool:
    if report.get("jwt_like_token_found") is True:
        return True

    if report.get("jwt_like_installation_token_found") is True:
        return True

    for result in report.get("results", []):
        if not isinstance(result, dict):
            continue
        token = result.get("token")
        if isinstance(token, dict) and token.get("jwt_like") is True:
            return True

    for provided in report.get("provided_tokens", []):
        if not isinstance(provided, dict):
            continue
        token = provided.get("token")
        if isinstance(token, dict) and token.get("jwt_like") is True:
            return True

    return False


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: assert_jwt_found.py <capture-output.json>", file=sys.stderr)
        return 2

    report = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
    if has_jwt_like_installation_token(report):
        print("JWT-shaped token observed.")
        return 0

    print("No JWT-shaped token observed.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

#!/usr/bin/env python3
"""Write selected capture report values to GitHub step outputs."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: write_report_outputs.py <capture-output.json>", file=sys.stderr)
        return 2

    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        print("GITHUB_OUTPUT is not set", file=sys.stderr)
        return 2

    report = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
    found = "true" if report.get("jwt_like_token_found") is True else "false"

    with Path(output_path).open("a", encoding="utf-8") as handle:
        handle.write(f"jwt_like_token_found={found}\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

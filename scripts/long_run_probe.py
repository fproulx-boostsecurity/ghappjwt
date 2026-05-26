#!/usr/bin/env python3
"""Single probe for the long-running GITHUB_TOKEN refresh experiment.

Reads tokens from on-disk files (paths supplied via env), classifies them,
hits GET /repos/$GITHUB_REPOSITORY with each, and appends a sanitized JSON
record to the JSONL report at $PROBE_REPORT.

Tokens are never printed, never written to the report, and never returned.
The script always exits 0 unless its inputs are missing.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


KEEP_RESPONSE_HEADERS = {
    "date",
    "x-github-request-id",
    "x-accepted-github-permissions",
    "x-oauth-scopes",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "x-ratelimit-resource",
}


def b64url_decode(seg: str) -> bytes:
    pad = (4 - len(seg) % 4) % 4
    return base64.urlsafe_b64decode(seg + "=" * pad)


def try_decode_jwt(segments: list[str]) -> dict[str, Any] | None:
    if len(segments) != 3:
        return None
    try:
        return {
            "header": json.loads(b64url_decode(segments[0])),
            "payload": json.loads(b64url_decode(segments[1])),
            "signature_b64url_length": len(segments[2]),
        }
    except (ValueError, json.JSONDecodeError):
        return None


def classify(token: str) -> dict[str, Any]:
    if not token:
        return {"present": False, "format": "absent"}

    record: dict[str, Any] = {
        "present": True,
        "prefix": token[:4],
        "length": len(token),
        "sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
        "format": "non_ghs",
    }

    if not token.startswith("ghs_"):
        return record

    body = token.removeprefix("ghs_")
    aid, sep, rest = body.partition("_")

    if sep and aid.isdigit():
        decoded = try_decode_jwt(rest.split("."))
        if decoded:
            payload = decoded["payload"]
            record["format"] = "ghs_appid_jwt"
            record["embedded_app_id"] = aid
            record["decoded_jwt"] = decoded
            record["jwt_iat"] = payload.get("iat")
            record["jwt_exp"] = payload.get("exp")
            record["jwt_jti"] = payload.get("jti")
            record["jwt_aud"] = payload.get("aud")
            record["jwt_azc"] = payload.get("azc")
            if isinstance(payload.get("iat"), int) and isinstance(payload.get("exp"), int):
                record["jwt_lifetime_seconds"] = payload["exp"] - payload["iat"]
            return record

    decoded = try_decode_jwt(body.split("."))
    if decoded:
        record["format"] = "ghs_jwt"
        record["decoded_jwt"] = decoded
        return record

    record["format"] = "ghs_opaque"
    return record


def read_token_file(env_name: str) -> str:
    path = os.environ.get(env_name)
    if not path:
        return ""
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def filter_headers(headers: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    for name in KEEP_RESPONSE_HEADERS:
        value = headers.get(name)
        if value is not None:
            out[name] = str(value)
    return out


def probe_api(token: str, repo: str) -> dict[str, Any]:
    url = f"https://api.github.com/repos/{repo}"
    request = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "ghappjwt-long-run-probe",
        },
    )
    started = time.time()
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            response.read()
            return {
                "status": response.status,
                "elapsed_ms": int((time.time() - started) * 1000),
                "headers": filter_headers(response.headers),
            }
    except urllib.error.HTTPError as exc:
        api_message: str | None = None
        try:
            body = json.loads(exc.read().decode("utf-8"))
            if isinstance(body, dict):
                api_message = body.get("message")
        except (ValueError, json.JSONDecodeError):
            api_message = None
        return {
            "status": exc.code,
            "elapsed_ms": int((time.time() - started) * 1000),
            "headers": filter_headers(exc.headers),
            "api_message": api_message,
        }
    except urllib.error.URLError as exc:
        return {
            "status": None,
            "elapsed_ms": int((time.time() - started) * 1000),
            "url_error": str(exc),
        }


def main() -> int:
    label = os.environ.get("STEP_LABEL")
    if not label:
        print("STEP_LABEL is required", file=sys.stderr)
        return 2
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        print("GITHUB_REPOSITORY is required", file=sys.stderr)
        return 2
    report_path = os.environ.get("PROBE_REPORT")
    if not report_path:
        print("PROBE_REPORT is required", file=sys.stderr)
        return 2

    current_token = read_token_file("CURRENT_TOKEN_FILE")
    original_token = read_token_file("ORIGINAL_TOKEN_FILE")

    record: dict[str, Any] = {
        "label": label,
        "iso_ts": datetime.now(UTC).isoformat(),
        "epoch": int(time.time()),
        "current_token": classify(current_token),
        "original_token": classify(original_token),
    }

    baseline_epoch_raw = os.environ.get("BASELINE_EPOCH")
    if baseline_epoch_raw:
        try:
            record["seconds_since_baseline"] = record["epoch"] - int(baseline_epoch_raw)
        except ValueError:
            pass

    original_exp = record["original_token"].get("jwt_exp")
    if isinstance(original_exp, int):
        record["seconds_relative_to_original_exp"] = record["epoch"] - original_exp

    current_sha = record["current_token"].get("sha256")
    original_sha = record["original_token"].get("sha256")
    if current_sha and original_sha:
        record["current_matches_original"] = current_sha == original_sha

    if current_token:
        record["probe_with_current"] = probe_api(current_token, repo)

    if original_token:
        if original_token == current_token:
            record["probe_with_original"] = {"skipped": "same_as_current"}
        else:
            record["probe_with_original"] = probe_api(original_token, repo)

    line = json.dumps(record, sort_keys=True)
    print(line)
    with open(report_path, "a", encoding="utf-8") as handle:
        handle.write(line + "\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

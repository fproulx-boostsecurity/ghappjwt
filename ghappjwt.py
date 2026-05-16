#!/usr/bin/env python3
"""Capture GitHub App installation token format behavior.

The tool intentionally prints sanitized token metadata, not full installation
tokens. If GitHub returns a stateless ghs_-prefixed JWT token, the tool decodes
the JWT header and payload without verifying or printing the signature.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


DEFAULT_CONFIG_PATH = ".ghappjwt.json"
DEFAULT_API_URL = "https://api.github.com"
DEFAULT_API_VERSION = "2026-03-10"
TOKEN_PATTERN_NOTE = r"ghs_[A-Za-z0-9\._]{36,}"


@dataclass(frozen=True)
class Config:
    app_id: str
    installation_id: str
    private_key: Path
    api_url: str
    api_version: str
    override: str
    output: Path | None
    timeout: int


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64url_decode(segment: str) -> bytes:
    padding_len = (4 - len(segment) % 4) % 4
    return base64.urlsafe_b64decode(segment + ("=" * padding_len))


def load_json_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON config {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise SystemExit(f"Invalid JSON config {path}: top-level value must be an object")

    return data


def resolve_value(
    name: str,
    args: argparse.Namespace,
    config: dict[str, Any],
    env_name: str,
    default: str | None = None,
) -> str | None:
    cli_value = getattr(args, name)
    if cli_value not in (None, ""):
        return str(cli_value)

    env_value = os.environ.get(env_name)
    if env_value not in (None, ""):
        return env_value

    config_value = config.get(name)
    if config_value not in (None, ""):
        return str(config_value)

    return default


def parse_args(argv: list[str]) -> Config:
    parser = argparse.ArgumentParser(
        description="Capture GitHub App installation token format behavior."
    )
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="JSON config path")
    parser.add_argument("--app-id", dest="app_id", help="GitHub App ID")
    parser.add_argument("--installation-id", dest="installation_id", help="Installation ID")
    parser.add_argument("--private-key", dest="private_key", help="Path to app private key PEM")
    parser.add_argument("--api-url", dest="api_url", help="GitHub API base URL")
    parser.add_argument("--api-version", dest="api_version", help="GitHub REST API version")
    parser.add_argument(
        "--override",
        choices=("enabled", "disabled", "both", "absent"),
        help="Override header value to test; default tests enabled and disabled",
    )
    parser.add_argument(
        "--output",
        help="Optional path for sanitized JSON report. Full tokens are never written.",
    )
    parser.add_argument("--timeout", type=int, help="HTTP timeout in seconds")

    args = parser.parse_args(argv)
    config_path = Path(args.config)
    config = load_json_file(config_path)

    app_id = resolve_value("app_id", args, config, "GITHUB_APP_ID")
    installation_id = resolve_value(
        "installation_id", args, config, "GITHUB_INSTALLATION_ID"
    )
    private_key = resolve_value("private_key", args, config, "GITHUB_APP_PRIVATE_KEY")
    api_url = resolve_value(
        "api_url", args, config, "GITHUB_API_URL", DEFAULT_API_URL
    )
    api_version = resolve_value(
        "api_version", args, config, "GITHUB_API_VERSION", DEFAULT_API_VERSION
    )
    override = resolve_value("override", args, config, "GHAPPJWT_OVERRIDE", "both")
    timeout_raw = resolve_value("timeout", args, config, "GHAPPJWT_TIMEOUT", "30")
    output = resolve_value("output", args, config, "GHAPPJWT_OUTPUT")

    missing = [
        label
        for label, value in (
            ("app_id", app_id),
            ("installation_id", installation_id),
            ("private_key", private_key),
        )
        if not value
    ]
    if missing:
        raise SystemExit(
            "Missing required config: "
            + ", ".join(missing)
            + ". Provide flags, env vars, or .ghappjwt.json."
        )

    if override not in ("enabled", "disabled", "both", "absent"):
        raise SystemExit("override must be one of: enabled, disabled, both, absent")

    try:
        timeout = int(timeout_raw or "30")
    except ValueError as exc:
        raise SystemExit("timeout must be an integer") from exc

    return Config(
        app_id=str(app_id),
        installation_id=str(installation_id),
        private_key=Path(str(private_key)).expanduser(),
        api_url=str(api_url).rstrip("/"),
        api_version=str(api_version),
        override=str(override),
        output=Path(output).expanduser() if output else None,
        timeout=timeout,
    )


def make_app_jwt(app_id: str, private_key_path: Path) -> tuple[str, dict[str, Any]]:
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"iat": now - 60, "exp": now + 9 * 60, "iss": app_id}

    signing_input = ".".join(
        [
            b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8")),
            b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
        ]
    )

    try:
        key_bytes = private_key_path.read_bytes()
    except OSError as exc:
        raise SystemExit(f"Could not read private key {private_key_path}: {exc}") from exc

    private_key = serialization.load_pem_private_key(key_bytes, password=None)
    signature = private_key.sign(
        signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256()
    )

    return f"{signing_input}.{b64url_encode(signature)}", {
        "header": header,
        "payload": payload,
    }


def request_installation_token(
    cfg: Config, app_jwt: str, override: str | None
) -> tuple[int, dict[str, Any]]:
    url = f"{cfg.api_url}/app/installations/{cfg.installation_id}/access_tokens"
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {app_jwt}",
        "X-GitHub-Api-Version": cfg.api_version,
        "User-Agent": "ghappjwt-token-format-capture",
    }
    if override is not None:
        headers["X-GitHub-Stateless-S2S-Token"] = override

    request = urllib.request.Request(url, method="POST", headers=headers, data=b"")

    try:
        with urllib.request.urlopen(request, timeout=cfg.timeout) as response:
            body = response.read().decode("utf-8")
            return response.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        try:
            parsed = json.loads(body) if body else {}
        except json.JSONDecodeError:
            parsed = {"raw_body": body}
        return exc.code, parsed
    except urllib.error.URLError as exc:
        raise SystemExit(f"Network error calling GitHub API: {exc}") from exc


def classify_token(token: str) -> dict[str, Any]:
    without_prefix = token.removeprefix("ghs_")
    segments = without_prefix.split(".")
    regex_match = token.startswith("ghs_") and len(token) >= 40 and all(
        char.isalnum() or char in "._" for char in token[4:]
    )

    return {
        "prefix": token[:4],
        "length": len(token),
        "dots_after_prefix": without_prefix.count("."),
        "jwt_like": len(segments) == 3,
        "recommended_regex_match": regex_match,
        "recommended_regex": TOKEN_PATTERN_NOTE,
        "redacted": f"{token[:12]}...{token[-8:]}",
    }


def decode_ghs_jwt(token: str) -> dict[str, Any] | None:
    without_prefix = token.removeprefix("ghs_")
    segments = without_prefix.split(".")
    if len(segments) != 3:
        return None

    try:
        return {
            "header": json.loads(b64url_decode(segments[0])),
            "payload": json.loads(b64url_decode(segments[1])),
            "signature": {
                "present": bool(segments[2]),
                "base64url_length": len(segments[2]),
            },
        }
    except (ValueError, json.JSONDecodeError):
        return None


def sanitize_error_body(body: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in body.items() if key != "token"}


def summarize_response(label: str, status: int, body: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"request": label, "http_status": status}
    token = body.get("token")
    if not isinstance(token, str):
        result["body"] = sanitize_error_body(body)
        return result

    result["token"] = classify_token(token)
    decoded = decode_ghs_jwt(token)
    result["decoded_jwt"] = decoded if decoded else "not JWT-shaped"
    expires_at = body.get("expires_at")
    if expires_at:
        result["expires_at"] = expires_at
    return result


def overrides_to_run(value: str) -> list[str | None]:
    if value == "both":
        return ["enabled", "disabled"]
    if value == "absent":
        return [None]
    return [value]


def main(argv: list[str]) -> int:
    cfg = parse_args(argv)
    app_jwt, jwt_shape = make_app_jwt(cfg.app_id, cfg.private_key)

    report: dict[str, Any] = {
        "captured_at": datetime.now(UTC).isoformat(),
        "app": {
            "app_id": cfg.app_id,
            "installation_id": cfg.installation_id,
            "private_key_file": cfg.private_key.name,
            "api_url": cfg.api_url,
            "api_version": cfg.api_version,
        },
        "app_auth_jwt": jwt_shape,
        "results": [],
    }

    for override in overrides_to_run(cfg.override):
        label = (
            "X-GitHub-Stateless-S2S-Token: absent"
            if override is None
            else f"X-GitHub-Stateless-S2S-Token: {override}"
        )
        status, body = request_installation_token(cfg, app_jwt, override)
        report["results"].append(summarize_response(label, status, body))

    rendered = json.dumps(report, indent=2, sort_keys=True)
    print(rendered)

    if cfg.output:
        cfg.output.parent.mkdir(parents=True, exist_ok=True)
        cfg.output.write_text(rendered + "\n", encoding="utf-8")
        print(f"\nWrote sanitized report: {cfg.output}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

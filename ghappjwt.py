#!/usr/bin/env python3
"""Capture GitHub App installation token format behavior.

The tool intentionally prints sanitized token metadata, not full installation
tokens. If GitHub returns a stateless ghs_-prefixed JWT token, the tool decodes
the JWT header and payload without verifying or printing the signature.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
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
    attempts: int
    delay_seconds: float
    stop_on_jwt: bool
    classify_token_env: list[str]


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


def resolve_list(
    name: str,
    args: argparse.Namespace,
    config: dict[str, Any],
    env_name: str,
) -> list[str]:
    cli_value = getattr(args, name)
    if cli_value:
        return [str(item) for item in cli_value]

    env_value = os.environ.get(env_name)
    if env_value:
        return [item.strip() for item in env_value.split(",") if item.strip()]

    config_value = config.get(name)
    if isinstance(config_value, list):
        return [str(item) for item in config_value if str(item)]
    if isinstance(config_value, str) and config_value:
        return [item.strip() for item in config_value.split(",") if item.strip()]

    return []


def parse_bool(value: str | bool | None, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value

    normalized = value.strip().lower()
    if normalized in ("1", "true", "yes", "on"):
        return True
    if normalized in ("0", "false", "no", "off"):
        return False

    raise SystemExit(f"Invalid boolean value: {value}")


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
    parser.add_argument("--attempts", type=int, help="Requests to make per override")
    parser.add_argument(
        "--delay-seconds",
        dest="delay_seconds",
        type=float,
        help="Delay between attempts",
    )
    parser.add_argument(
        "--stop-on-jwt",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Stop early when a JWT-shaped installation token is observed",
    )
    parser.add_argument(
        "--classify-token-env",
        action="append",
        default=[],
        help="Classify a token from this environment variable without printing it",
    )

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
    attempts_raw = resolve_value("attempts", args, config, "GHAPPJWT_ATTEMPTS", "1")
    delay_seconds_raw = resolve_value(
        "delay_seconds", args, config, "GHAPPJWT_DELAY_SECONDS", "0"
    )
    stop_on_jwt_raw = resolve_value(
        "stop_on_jwt", args, config, "GHAPPJWT_STOP_ON_JWT", "true"
    )
    classify_token_env = resolve_list(
        "classify_token_env", args, config, "GHAPPJWT_CLASSIFY_TOKEN_ENV"
    )
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

    try:
        attempts = int(attempts_raw or "1")
    except ValueError as exc:
        raise SystemExit("attempts must be an integer") from exc
    if attempts < 1:
        raise SystemExit("attempts must be at least 1")

    try:
        delay_seconds = float(delay_seconds_raw or "0")
    except ValueError as exc:
        raise SystemExit("delay-seconds must be a number") from exc
    if delay_seconds < 0:
        raise SystemExit("delay-seconds must not be negative")

    stop_on_jwt = parse_bool(stop_on_jwt_raw, default=True)

    return Config(
        app_id=str(app_id),
        installation_id=str(installation_id),
        private_key=Path(str(private_key)).expanduser(),
        api_url=str(api_url).rstrip("/"),
        api_version=str(api_version),
        override=str(override),
        output=Path(output).expanduser() if output else None,
        timeout=timeout,
        attempts=attempts,
        delay_seconds=delay_seconds,
        stop_on_jwt=stop_on_jwt,
        classify_token_env=classify_token_env,
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
) -> tuple[int, dict[str, Any], dict[str, str]]:
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
            return (
                response.status,
                json.loads(body) if body else {},
                safe_response_headers(response.headers),
            )
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8")
        try:
            parsed = json.loads(body) if body else {}
        except json.JSONDecodeError:
            parsed = {"raw_body": body}
        return exc.code, parsed, safe_response_headers(exc.headers)
    except urllib.error.URLError as exc:
        raise SystemExit(f"Network error calling GitHub API: {exc}") from exc


def safe_response_headers(headers: Any) -> dict[str, str]:
    keep = {
        "date",
        "x-github-api-version-selected",
        "x-github-request-id",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "x-ratelimit-resource",
        "x-ratelimit-used",
    }
    safe: dict[str, str] = {}

    for key in keep:
        value = headers.get(key)
        if value is not None:
            safe[key] = str(value)

    return safe


def decode_jwt_segments(segments: list[str]) -> dict[str, Any] | None:
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


def parse_ghs_token(token: str) -> dict[str, Any]:
    if not token.startswith("ghs_"):
        return {
            "token_format": "unknown",
            "jwt_segments": None,
            "embedded_app_id": None,
            "decoded_jwt": None,
        }

    body = token.removeprefix("ghs_")

    direct_segments = body.split(".")
    direct_decoded = decode_jwt_segments(direct_segments)
    if direct_decoded:
        return {
            "token_format": "ghs_jwt",
            "jwt_segments": direct_segments,
            "embedded_app_id": None,
            "decoded_jwt": direct_decoded,
        }

    app_id, separator, jwt_part = body.partition("_")
    if separator and app_id.isdigit():
        appid_segments = jwt_part.split(".")
        appid_decoded = decode_jwt_segments(appid_segments)
        if appid_decoded:
            return {
                "token_format": "ghs_appid_jwt",
                "jwt_segments": appid_segments,
                "embedded_app_id": app_id,
                "decoded_jwt": appid_decoded,
            }

    return {
        "token_format": "ghs_opaque",
        "jwt_segments": None,
        "embedded_app_id": None,
        "decoded_jwt": None,
    }


def classify_token(token: str) -> dict[str, Any]:
    without_prefix = token.removeprefix("ghs_")
    has_ghs_prefix = token.startswith("ghs_")
    parsed = parse_ghs_token(token)
    regex_match = token.startswith("ghs_") and len(token) >= 40 and all(
        char.isalnum() or char in "._" for char in token[4:]
    )

    return {
        "prefix": token[:4],
        "length": len(token),
        "dots_after_prefix": without_prefix.count("."),
        "token_format": parsed["token_format"],
        "embedded_app_id": parsed["embedded_app_id"],
        "jwt_like": has_ghs_prefix and parsed["jwt_segments"] is not None,
        "recommended_regex_match": regex_match,
        "recommended_regex": TOKEN_PATTERN_NOTE,
    }


def decode_ghs_jwt(token: str) -> dict[str, Any] | None:
    parsed = parse_ghs_token(token)
    decoded = parsed["decoded_jwt"]
    if not decoded:
        return None

    return {
        "token_format": parsed["token_format"],
        "embedded_app_id": parsed["embedded_app_id"],
        **decoded,
    }


def redacted_jwt_specimen(token: str) -> dict[str, str] | None:
    parsed = parse_ghs_token(token)
    segments = parsed["jwt_segments"]
    if not segments:
        return None

    if parsed["token_format"] == "ghs_appid_jwt":
        specimen = (
            f"ghs_{parsed['embedded_app_id']}_"
            f"{segments[0]}.{segments[1]}.[signature-redacted]"
        )
    else:
        specimen = f"ghs_{segments[0]}.{segments[1]}.[signature-redacted]"

    return {
        "format": "compact-jwt-signature-redacted",
        "value": specimen,
        "note": "Signature is removed; this is not a usable token.",
    }


def token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def sanitize_error_body(body: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in body.items() if key != "token"}


def summarize_existing_token(source: str, token: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "source": source,
        "token": classify_token(token),
        "sha256": token_fingerprint(token),
    }
    decoded = decode_ghs_jwt(token)
    result["decoded_jwt"] = decoded if decoded else "not JWT-shaped"
    specimen = redacted_jwt_specimen(token)
    if specimen:
        result["redacted_jwt_specimen"] = specimen
    return result


def summarize_response(
    label: str,
    attempt: int,
    status: int,
    body: dict[str, Any],
    response_headers: dict[str, str],
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "request": label,
        "attempt": attempt,
        "http_status": status,
        "response_headers": response_headers,
    }
    token = body.get("token")
    if not isinstance(token, str):
        result["body"] = sanitize_error_body(body)
        return result

    result["token"] = classify_token(token)
    result["sha256"] = token_fingerprint(token)
    decoded = decode_ghs_jwt(token)
    result["decoded_jwt"] = decoded if decoded else "not JWT-shaped"
    specimen = redacted_jwt_specimen(token)
    if specimen:
        result["redacted_jwt_specimen"] = specimen
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
    app_jwt_exp = jwt_shape["payload"]["exp"]

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
        "capture_options": {
            "override": cfg.override,
            "attempts": cfg.attempts,
            "delay_seconds": cfg.delay_seconds,
            "stop_on_jwt": cfg.stop_on_jwt,
            "classify_token_env": cfg.classify_token_env,
        },
        "results": [],
        "provided_tokens": [],
    }

    jwt_like_found = False
    for attempt in range(1, cfg.attempts + 1):
        for override in overrides_to_run(cfg.override):
            if int(time.time()) >= app_jwt_exp - 60:
                app_jwt, jwt_shape = make_app_jwt(cfg.app_id, cfg.private_key)
                app_jwt_exp = jwt_shape["payload"]["exp"]

            label = (
                "X-GitHub-Stateless-S2S-Token: absent"
                if override is None
                else f"X-GitHub-Stateless-S2S-Token: {override}"
            )
            status, body, response_headers = request_installation_token(
                cfg, app_jwt, override
            )
            result = summarize_response(label, attempt, status, body, response_headers)
            report["results"].append(result)

            token = result.get("token")
            if isinstance(token, dict) and token.get("jwt_like"):
                jwt_like_found = True
                if cfg.stop_on_jwt:
                    break

        if jwt_like_found and cfg.stop_on_jwt:
            break

        if attempt < cfg.attempts and cfg.delay_seconds:
            time.sleep(cfg.delay_seconds)

    report["jwt_like_installation_token_found"] = jwt_like_found

    provided_token_jwt_like_found = False
    for env_name in cfg.classify_token_env:
        token = os.environ.get(env_name)
        if not token:
            report["provided_tokens"].append(
                {"source": env_name, "error": "environment variable was empty or unset"}
            )
            continue

        provided = summarize_existing_token(env_name, token)
        report["provided_tokens"].append(provided)
        token_summary = provided.get("token")
        if isinstance(token_summary, dict) and token_summary.get("jwt_like"):
            provided_token_jwt_like_found = True

    report["jwt_like_provided_token_found"] = provided_token_jwt_like_found
    report["jwt_like_token_found"] = (
        jwt_like_found or provided_token_jwt_like_found
    )

    rendered = json.dumps(report, indent=2, sort_keys=True)
    print(rendered)

    if cfg.output:
        cfg.output.parent.mkdir(parents=True, exist_ok=True)
        cfg.output.write_text(rendered + "\n", encoding="utf-8")
        print(f"\nWrote sanitized report: {cfg.output}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

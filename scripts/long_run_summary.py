#!/usr/bin/env python3
"""Render the long-run probe JSONL into a Markdown summary."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def code(value: Any) -> str:
    if value is None or value == "":
        return "_n/a_"
    return f"`{value}`"


def format_probe(probe: Any) -> str:
    if not isinstance(probe, dict):
        return "_n/a_"
    if probe.get("skipped"):
        return "_= current_"
    status = probe.get("status")
    message = probe.get("api_message")
    if status is None:
        return f"_err: {probe.get('url_error', 'unknown')}_"
    if message:
        return f"{status} ({message})"
    return f"{status}"


def status_of(probe: Any) -> int | None:
    if isinstance(probe, dict) and not probe.get("skipped"):
        status = probe.get("status")
        if isinstance(status, int):
            return status
    return None


def render(records: list[dict[str, Any]]) -> str:
    if not records:
        return "_No probe records found._\n"

    baseline = records[0]
    baseline_curr = baseline.get("current_token") or {}
    baseline_sha = baseline_curr.get("sha256")
    original_iat = baseline_curr.get("jwt_iat")
    original_exp = baseline_curr.get("jwt_exp")

    lines = [
        "# Long-running GITHUB_TOKEN refresh probe",
        "",
        "## Baseline",
        "",
        f"- Format: {code(baseline_curr.get('format'))}",
        f"- Length: {code(baseline_curr.get('length'))}",
        f"- Embedded App ID: {code(baseline_curr.get('embedded_app_id'))}",
        f"- JWT `iat`: {code(original_iat)}",
        f"- JWT `exp`: {code(original_exp)}",
        f"- Lifetime (s): {code(baseline_curr.get('jwt_lifetime_seconds'))}",
        f"- JWT `aud`: {code(baseline_curr.get('jwt_aud'))}",
        f"- JWT `azc`: {code(baseline_curr.get('jwt_azc'))}",
        f"- Baseline SHA-256: {code(baseline_sha)}",
        "",
        "## Probes",
        "",
        "| Label | Δ-baseline (s) | Δ-orig-exp (s) | current==baseline | probe(current) | probe(original) |",
        "|---|---:|---:|---|---|---|",
    ]

    for record in records:
        cur = record.get("current_token") or {}
        cur_sha = cur.get("sha256")
        if cur_sha is None:
            match_label = "_n/a_"
        elif cur_sha == baseline_sha:
            match_label = "yes"
        else:
            match_label = f"**no — rotated, new sha {cur_sha[:12]}…**"
        delta_baseline = record.get("seconds_since_baseline", "")
        delta_exp = record.get("seconds_relative_to_original_exp", "")
        lines.append(
            f"| {record.get('label', '?')} "
            f"| {delta_baseline} "
            f"| {delta_exp} "
            f"| {match_label} "
            f"| {format_probe(record.get('probe_with_current'))} "
            f"| {format_probe(record.get('probe_with_original'))} |"
        )

    lines.append("")
    lines.append("## Observations")
    lines.append("")

    rotated = any(
        (record.get("current_token") or {}).get("sha256") not in (None, baseline_sha)
        for record in records[1:]
    )
    final = records[-1]
    final_curr_status = status_of(final.get("probe_with_current"))
    final_orig_status = status_of(final.get("probe_with_original"))

    past_exp_records = [
        record
        for record in records
        if isinstance(record.get("seconds_relative_to_original_exp"), int)
        and record["seconds_relative_to_original_exp"] > 0
    ]
    have_post_exp_data = bool(past_exp_records)

    lines.append(f"- Token SHA-256 rotated mid-job: {code(rotated)}")
    lines.append(f"- Probes recorded past original `exp`: {code(len(past_exp_records))}")
    lines.append(f"- Final `${{{{ github.token }}}}` probe status: {code(final_curr_status)}")
    lines.append(f"- Final originally-captured-token probe status: {code(final_orig_status)}")
    lines.append("")

    lines.append("## Interpretation")
    lines.append("")
    if not have_post_exp_data:
        lines.append("- No probes ran past the original `exp`; experiment incomplete.")
    elif rotated:
        lines.append(
            "- Token was rotated at least once during the job. Some refresh mechanism is "
            "live — either the runner is replacing `system.github.token` from a service "
            "channel, or the listener heartbeat now ships a refreshed token. Inspect the "
            "earliest rotated row above to find when refresh kicked in."
        )
    elif final_curr_status == 200 and final_orig_status == 200:
        lines.append(
            "- Token did NOT rotate, but the originally captured token is still accepted "
            "past its JWT `exp`. The github.com auth layer is ignoring the JWT `exp` for "
            "in-flight Actions jobs — the stateless `exp` claim is advisory, not enforced, "
            "in this path."
        )
    elif final_curr_status and final_curr_status >= 400:
        lines.append(
            "- Token did NOT rotate and is rejected past `exp`. "
            "**Long-running jobs using `GITHUB_TOKEN` past 60 minutes are broken under the "
            "new stateless format.** This is the worst-case outcome from the public-evidence "
            "hypothesis space."
        )
    else:
        lines.append("- Mixed signals — inspect the probe table directly.")

    lines.append("")
    lines.append("_Raw bearer tokens are never written to the report or this summary._")
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: long_run_summary.py <probe-report.jsonl>", file=sys.stderr)
        return 2
    text = Path(argv[0]).read_text(encoding="utf-8")
    records = [json.loads(line) for line in text.splitlines() if line.strip()]
    sys.stdout.write(render(records))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

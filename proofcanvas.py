#!/usr/bin/env python3
"""ProofCanvas: offline, redacted evidence cards for MCP conformance transcripts.

Never executes the input, calls a remote endpoint, or signs an attestation.
Python 3.10+; standard library only.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

MAX_INPUT_BYTES = 1_000_000
MAX_DETAIL_LENGTH = 220
LINE_RE = re.compile(r"^\s*([A-Z][A-Z0-9_]{1,60})\s*=\s*(PASS|FAIL|ERROR|SKIP)(?:\s*\|\s*(.*))?\s*$")
STATUS_CSS = {"PASS": "pass", "FAIL": "fail", "ERROR": "fail", "SKIP": "skip"}
# Privacy first: only known generic test labels are printed. No input details are
# reproduced in public cards, even if an unfamiliar credential format is used.
SAFE_DESCRIPTIONS = {
    "INITIALIZE": "Initialize the MCP client session",
    "TOOL_DISCOVERY": "Discover tools through the MCP protocol",
    "PLAN_IMPORT": "Prepare a proposed change without executing it",
    "UNAPPROVED_BLOCK": "Prevent an unapproved effect",
    "WRONG_PHRASE_REJECT": "Reject a non-matching confirmation phrase",
    "VOICE_APPROVAL": "Interpret a plan-bound spoken confirmation",
    "EXECUTE": "Apply an approved plan",
    "VERIFY": "Compare the resulting state with the planned result",
    "ROUTINE_REVIEW": "Allow a low-risk routine action",
    "DRIFT_BLOCK": "Refuse an approval when state has changed",
    "GATED_DELETE": "Protect a consequential delete operation",
    "AUDIT_CHAIN": "Validate the sequence of audit events",
}


def redact(value: str) -> str:
    """Default-deny common secret, personal, and infrastructure patterns."""
    text = str(value)
    text = re.sub(r"(?i)\b(?:authorization|x-api-key|api[_-]?key|access[_-]?token|password|secret|bearer)\s*[:=]\s*(?:['\"])?[^\s,'\"]+",
                  "[CREDENTIAL REDACTED]", text)
    text = re.sub(r"(?i)\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,}|AKIA[0-9A-Z]{16})\b",
                  "[CREDENTIAL REDACTED]", text)
    text = re.sub(r"(?i)\b(?:https?://|wss?://)[^\s<>\"]+", "[URL REDACTED]", text)
    text = re.sub(r"(?i)\b[A-Za-z]:\\[^\s]+|(?:/home/|/Users/)[^\s]+", "[LOCAL PATH REDACTED]", text)
    text = re.sub(r"(?i)\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b", "[EMAIL REDACTED]", text)
    text = re.sub(r"(?i)\b(?:sandbox|sessionid|cookie)\s*[:=]\s*[^\s,]+", "[SESSION REDACTED]", text)
    text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", text)
    return text[:MAX_DETAIL_LENGTH]


def parse_transcript(raw: str) -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        match = LINE_RE.fullmatch(line)
        if not match:
            continue
        name, status, detail = match.groups()
        if name in seen:
            raise ValueError(f"Duplicate check label: {name}")
        seen.add(name)
        public_code = name if name in SAFE_DESCRIPTIONS else f"CHECK_{len(checks) + 1:02d}"
        checks.append({"name": public_code.replace("_", " ").title(),
                       "code": public_code,
                       "status": status,
                       "detail": SAFE_DESCRIPTIONS.get(name, "Result imported; raw details withheld")})
    if not checks:
        raise ValueError("No conformance check lines found. Expected NAME = PASS | detail.")
    return checks


def summarize(checks: list[dict[str, str]]) -> dict[str, object]:
    counts = {status: sum(c["status"] == status for c in checks)
              for status in ("PASS", "FAIL", "ERROR", "SKIP")}
    if counts["FAIL"] or counts["ERROR"]:
        verdict = "FAILED"
    elif counts["SKIP"]:
        verdict = "INCOMPLETE"
    else:
        verdict = "PASSED"
    canonical = "\n".join(f"{c['code']}={c['status']}|{c['detail']}" for c in checks)
    return {"verdict": verdict, "total": len(checks), "counts": counts,
            "report_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest()}


def render_html(checks: list[dict[str, str]], summary: dict[str, object], label: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows = "\n".join(
        '<li class="check"><span class="dot '+STATUS_CSS[c["status"]]+'" aria-hidden="true"></span>'
        '<div class="checkbody"><strong>'+html.escape(c["name"])+'</strong>'
        + ('<small>'+html.escape(c["detail"])+'</small>' if c["detail"] else '')
        + '</div><span class="status '+STATUS_CSS[c["status"]]+'">'+c["status"]+'</span></li>'
        for c in checks
    )
    verdict = str(summary["verdict"])
    pass_count = summary["counts"]["PASS"]
    score = round(100 * int(pass_count) / int(summary["total"]))
    safe_label = html.escape(redact(label), quote=True)
    values = {
        "__LABEL__": safe_label,
        "__STAMP__": html.escape(stamp),
        "__VERDICT__": verdict,
        "__TOTAL__": str(summary["total"]),
        "__PASS_COUNT__": str(pass_count),
        "__RATE__": str(score),
        "__ROWS__": rows,
        "__DIGEST__": html.escape(str(summary["report_sha256"])),
        "__RESULT_CLASS__": "success" if verdict == "PASSED" else "attention",
    }
    page = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<title>ProofCanvas | Evidence card</title>
<style>
:root{color-scheme:dark;font-family:Inter,system-ui,-apple-system,Segoe UI,sans-serif}
*{box-sizing:border-box}body{margin:0;background:#090e1b;color:#e9eefb;line-height:1.5}
.shell{max-width:1000px;margin:auto;padding:54px 26px 72px}
header{display:flex;gap:24px;justify-content:space-between;align-items:center;flex-wrap:wrap}
.brand{font-size:18px;letter-spacing:-.03em;font-weight:800}.brand span{color:#75dddb}
.eyebrow{font-size:12px;text-transform:uppercase;letter-spacing:.18em;color:#9daac5}
h1{font-size:clamp(35px,7vw,64px);letter-spacing:-.055em;line-height:1.04;margin:28px 0 14px}
.lede{max-width:650px;color:#aeb9cf;font-size:17px;margin:0 0 35px}
.card{background:linear-gradient(145deg,#162239,#0c1529);border:1px solid #2a3e5c;border-radius:24px;padding:30px}
.hero{display:grid;grid-template-columns:1fr auto;gap:24px;align-items:center}
.verdict{font-size:32px;font-weight:800;letter-spacing:-.03em}.success .verdict{color:#77e9bf}.attention .verdict{color:#f6ba80}
.metric{font-size:clamp(36px,7vw,62px);font-weight:800;line-height:1}.metric span{font-size:17px;color:#aeb9cf}
.pill{display:inline-block;border:1px solid #335074;color:#bed3f5;border-radius:100px;padding:7px 12px;font-size:12px}
.progress{height:10px;background:#283750;border-radius:30px;overflow:hidden;margin:24px 0 0}
.progress div{height:100%;background:linear-gradient(90deg,#58cbdd,#88e8a6);width:__RATE__%}
.details{display:flex;justify-content:space-between;gap:15px;align-items:flex-end;margin:34px 0 14px;flex-wrap:wrap}
h2{margin:0;font-size:23px;letter-spacing:-.025em}ul{list-style:none;margin:0;padding:0}
.check{padding:16px 4px;border-bottom:1px solid #293750;display:flex;align-items:center;gap:15px}
.dot{height:12px;width:12px;flex:none;border-radius:100%;background:#efb98c}
.dot.pass{background:#75e1ba}.dot.fail{background:#f28b90}
.checkbody{flex:1;min-width:0;overflow-wrap:anywhere}.checkbody strong{font-size:15px}
.checkbody small{display:block;font-size:13px;color:#aeb9cf}
.status{font-size:11px;letter-spacing:.09em;font-weight:800;border-radius:7px;padding:5px 7px}
.status.pass{background:#173e39;color:#8debd0}.status.fail{background:#472b3b;color:#ffb0b5}.status.skip{background:#44372e;color:#f3c9a5}
footer{margin-top:30px;color:#9daac5;font-size:13px}
.hash{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere;color:#c8eaf2;font-size:12px}
.note{margin-top:18px;border-left:3px solid #608eb0;padding-left:14px}
button{background:#1d344a;color:#edf8ff;border:1px solid #547c9f;padding:9px 14px;border-radius:12px;cursor:pointer;font:inherit}
button:hover{background:#294862}button:focus-visible{outline:3px solid #d1f3fd;outline-offset:3px}
@media(max-width:600px){.shell{padding:26px 16px 40px}.card{padding:20px}.hero{grid-template-columns:1fr}h1{margin-top:19px}}
@media print{body{background:#fff;color:#111}.card{background:#fff;border-color:#888}.lede,.checkbody small,footer{color:#333}.pill{color:#333}button{display:none}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{scroll-behavior:auto!important;animation:none!important}}
</style></head><body><div class="shell">
<header><div class="brand">Proof<span>Canvas</span></div><span class="pill">OFFLINE · REDACTED · OPEN SOURCE</span></header>
<main><div class="eyebrow" style="margin-top:45px">Developer evidence / __STAMP__</div>
<h1>Evidence, not<br>assumptions.</h1>
<p class="lede">A human-readable summary of supplied MCP conformance output. Secrets are redacted before rendering. Source: __LABEL__.</p>
<section class="card hero __RESULT_CLASS__" aria-label="Conformance result">
<div><div class="eyebrow">Overall status</div><div class="verdict">__VERDICT__</div><p style="color:#aeb9cf">Status is computed from individual checks, not from the input's claimed summary.</p></div>
<div><div class="metric">__PASS_COUNT__<span> / __TOTAL__</span></div><div class="eyebrow">Checks passed</div></div>
<div class="progress" role="progressbar" aria-label="Percentage of checks passed" aria-valuenow="__RATE__" aria-valuemin="0" aria-valuemax="100"><div></div></div>
</section>
<div class="details"><h2>Conformance timeline</h2><span class="pill">__TOTAL__ checks</span></div>
<section class="card" aria-label="Individual checks"><ul>__ROWS__</ul></section></main>
<footer><div class="eyebrow">Redacted transcript fingerprint (SHA-256)</div>
<div class="hash">__DIGEST__</div>
<p class="note">Important: the hash only identifies the normalized, redacted input to this report. It is <strong>not</strong> a third-party signature, remote endpoint attestation, or proof that a test was genuinely executed. Reviewers should reproduce the checks against a disposable sandbox.</p>
<p>No telemetry · No network requests · No user account · All data remains inside this HTML file.</p>
<button type="button" onclick="window.print()">Print or save as PDF</button></footer></div></body></html>"""
    for marker, val in values.items():
        page = page.replace(marker, val)
    return page


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create redacted, shareable HTML evidence from MCP test logs.")
    parser.add_argument("--input", required=True, type=Path, help="Path to a conformance transcript (text)")
    parser.add_argument("--output", required=True, type=Path, help="New HTML report path")
    parser.add_argument("--label", default="user-supplied conformance output", help="Public-safe source label")
    parser.add_argument("--strict", action="store_true", help="Exit nonzero if any check fails or is skipped")
    args = parser.parse_args(argv)
    try:
        if args.input.stat().st_size > MAX_INPUT_BYTES:
            raise ValueError(f"Input must be at most {MAX_INPUT_BYTES} bytes")
        raw = args.input.read_text(encoding="utf-8-sig")
        checks = parse_transcript(raw)
        summary = summarize(checks)
        if args.output.exists():
            raise ValueError("Output already exists; choose a new file to avoid overwriting")
        if args.output.resolve() == args.input.resolve():
            raise ValueError("Input and output paths must be different")
        args.output.write_text(render_html(checks, summary, args.label), encoding="utf-8")
    except (OSError, ValueError, UnicodeError) as exc:
        print(f"ProofCanvas error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({**summary, "output": str(args.output)}, indent=2))
    return 1 if args.strict and summary["verdict"] != "PASSED" else 0


if __name__ == "__main__":
    raise SystemExit(main())

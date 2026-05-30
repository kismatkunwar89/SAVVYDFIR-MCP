#!/usr/bin/env python3
"""Render a Claude Code session JSONL into a redacted reports/<case_id>/trace.html.

Run-11 trace integration (peer reviewer sign-off). Operator-explicit helper — NOT
auto-fired from generate_report. Failures here cannot poison the existing
report flow.

Usage:
    ./scripts/render_session_trace.py --case-id SRL-2018-WKSTN01 \\
        --session-jsonl ~/.claude/projects/<hash>/<session-id>.jsonl

Defaults:
    --output       reports/<case_id>/trace.html
    --detail       low   (peer reviewer catch: high is too leaky for judges)
    --reports-root ./reports
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
from pathlib import Path


# ---------------------------------------------------------------------------
# Redaction patterns (post-peer reviewer revision).
#
# Operator infrastructure → placeholders. Evidence-side identifiers, framework
# audit IDs (F-NNN / E-NNN / CTX-NNN), MITRE technique IDs, and case-side
# user/email/host names that come from the disk image are NOT touched.
# ---------------------------------------------------------------------------

# Secret shapes (peer reviewer catch).
SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Anthropic / OpenAI / Hugging Face / Slack / GitHub / GitLab tokens
    (re.compile(r"sk-[A-Za-z0-9_-]{20,}"), "<redacted-secret>"),
    (re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"), "<redacted-secret>"),
    (re.compile(r"ghp_[A-Za-z0-9]{36,}"), "<redacted-secret>"),
    (re.compile(r"gho_[A-Za-z0-9]{36,}"), "<redacted-secret>"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{82,}"), "<redacted-secret>"),
    (re.compile(r"glpat-[A-Za-z0-9_-]{20,}"), "<redacted-secret>"),
    (re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}"), "<redacted-secret>"),
    (re.compile(r"hf_[A-Za-z0-9]{30,}"), "<redacted-secret>"),
    (re.compile(r"AKIA[A-Z0-9]{16}"), "<redacted-secret>"),
    # Bearer / Authorization / Cookie headers
    (re.compile(r"(?i)Bearer\s+[A-Za-z0-9._~+/-]{20,}"), "Bearer <redacted-secret>"),
    (re.compile(r"(?i)Authorization:\s*\S+"), "Authorization: <redacted-secret>"),
    (re.compile(r"(?i)Cookie:\s*\S+"), "Cookie: <redacted-secret>"),
    (re.compile(r"(?i)Set-Cookie:\s*\S+"), "Set-Cookie: <redacted-secret>"),
    # Environment-style assignments
    (re.compile(r"(?i)\b(ANTHROPIC|OPENAI|GITHUB|GITLAB|HUGGINGFACE|SLACK|AWS|HF)_[A-Z_]*(KEY|TOKEN|SECRET|PASSWORD|PAT)\s*=\s*\S+"), "<redacted-secret>"),
    (re.compile(r"(?i)\b[A-Z][A-Z0-9_]*_(KEY|TOKEN|SECRET|PASSWORD)\s*=\s*\S+"), "<redacted-secret>"),
    # PEM private key blocks (multi-line)
    (re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----"), "<redacted-secret>"),
    # Signed URL query secrets
    (re.compile(r"(?i)([?&](?:token|sig|signature|api_key|access_key|x-amz-signature))=\S+"), r"\1=<redacted-query-secret>"),
    # sshpass invocations (anywhere in code blocks)
    (re.compile(r"sshpass\s+-p\s+\S+"), "sshpass -p <redacted-secret>"),
]

# Claude session UUID + project hash → consistent hash (preserves cross-refs
# in the document without leaking the raw ID).
UUID_PATTERN = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
PROJECT_HASH_HINT = re.compile(r"/\.claude/projects/([A-Za-z0-9_-]+)/")

MAC_PATTERN = re.compile(r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b")


# ---------------------------------------------------------------------------
# Operator-infra discovery (read-only; never raises).
# ---------------------------------------------------------------------------


def _discover_operator_paths() -> list[tuple[str, str]]:
    """Return (literal, replacement) pairs for operator-side filesystem paths.

    Order matters — longer prefixes come FIRST so we don't replace `/home/foo/`
    before `/home/foo/SAVVYDFIR-MCP/` has had a chance to be replaced.
    """
    home = Path.home()
    pairs: list[tuple[str, str]] = []
    # Project repo location
    pairs.append((str(home / "SAVVYDFIR-MCP") + "/", "<repo>/"))
    pairs.append((str(home / "SAVVYDFIR-MCP"), "<repo>"))
    pairs.append(("/opt/SAVVYDFIR-MCP/", "<install-prefix>/"))
    pairs.append(("/opt/SAVVYDFIR-MCP", "<install-prefix>"))
    # Home dir
    pairs.append((str(home) + "/", "<home>/"))
    pairs.append((str(home), "<home>"))
    return pairs


def _discover_case_paths(case_id: str, manifest_path: Path | None) -> list[tuple[str, str]]:
    """Case + evidence path mappings, agnostic across cases."""
    pairs: list[tuple[str, str]] = []
    pairs.append((f"/cases/{case_id}/", "<case-dir>/"))
    pairs.append((f"/cases/{case_id}", "<case-dir>"))
    # Evidence dataset: try to read from manifest.json's disk_images[0].path
    # else fall back to no-op (we don't blanket-redact /evidence/).
    if manifest_path and manifest_path.is_file():
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            disks = data.get("disk_images") or []
            for disk in disks:
                p = disk.get("path", "")
                # Extract /evidence/<dataset>/ from the disk path
                m = re.match(r"^(/evidence/[^/]+)/", p)
                if m:
                    pairs.append((m.group(1) + "/", "<evidence>/"))
                    pairs.append((m.group(1), "<evidence>"))
        except (json.JSONDecodeError, OSError):
            pass
    return pairs


def _discover_operator_identity() -> list[tuple[str, str]]:
    """Operator USER + HOME basename → <operator> (token-replace via word boundary)."""
    pairs: list[tuple[str, str]] = []
    user = os.environ.get("USER", "")
    home_basename = Path.home().name
    seen = set()
    for token in (user, home_basename):
        if token and token not in seen and len(token) >= 3:
            seen.add(token)
            pairs.append((token, "<operator>"))
    return pairs


def _discover_operator_network(lan_cidr: str | None) -> tuple[str | None, str | None, re.Pattern[str] | None]:
    """Operator host + IP + LAN CIDR regex. None when unknowable."""
    hostname = None
    host_ip = None
    try:
        hostname = socket.gethostname()
    except OSError:
        pass
    try:
        host_ip = socket.gethostbyname(socket.gethostname())
    except OSError:
        pass
    lan_re = None
    if lan_cidr:
        # Very permissive CIDR match (e.g. "10.0.0.0/24" → "10\.0\.0\.\d+")
        m = re.match(r"^(\d+)\.(\d+)\.(\d+)\.\d+/(\d+)$", lan_cidr.strip())
        if m and m.group(4) in {"24"}:
            a, b, c = m.group(1), m.group(2), m.group(3)
            lan_re = re.compile(rf"\b{re.escape(a)}\.{re.escape(b)}\.{re.escape(c)}\.\d{{1,3}}\b")
    return hostname, host_ip, lan_re


# ---------------------------------------------------------------------------
# Redaction pass.
# ---------------------------------------------------------------------------


def _hash_token(token: str) -> str:
    return "<id-" + hashlib.sha256(token.encode("utf-8", errors="ignore")).hexdigest()[:8] + ">"


def redact(html_text: str, *, case_id: str, manifest_path: Path | None,
           extra_tokens: list[str], lan_cidr: str | None) -> str:
    """Apply the layered redaction pass to a rendered HTML string."""

    # 1) Secrets (run first — they may contain path-like fragments we don't want to mask first).
    for pat, repl in SECRET_PATTERNS:
        html_text = pat.sub(repl, html_text)

    # 2) Operator filesystem paths
    for literal, repl in _discover_operator_paths():
        html_text = html_text.replace(literal, repl)

    # 3) Case + evidence paths
    for literal, repl in _discover_case_paths(case_id, manifest_path):
        html_text = html_text.replace(literal, repl)

    # 4) Operator identity (token replacement with word boundary)
    for literal, repl in _discover_operator_identity():
        html_text = re.sub(rf"\b{re.escape(literal)}\b", repl, html_text)

    # 5) Hostname + operator-LAN IPs (NOT blanket RFC1918)
    hostname, host_ip, lan_re = _discover_operator_network(lan_cidr)
    if hostname and len(hostname) >= 3:
        html_text = re.sub(rf"\b{re.escape(hostname)}\b", "<operator-host>", html_text)
    if host_ip:
        html_text = re.sub(rf"\b{re.escape(host_ip)}\b", "<operator-lan>", html_text)
    if lan_re:
        html_text = lan_re.sub("<operator-lan>", html_text)

    # 6) Project hash + Claude session UUID → consistent hash
    for m in PROJECT_HASH_HINT.finditer(html_text):
        token = m.group(1)
        html_text = html_text.replace(f"/.claude/projects/{token}/",
                                       f"/<claude-projects>/{_hash_token(token)}/")

    # Consistent hash for UUIDs (same UUID → same short hash everywhere)
    uuid_replacements: dict[str, str] = {}
    for m in UUID_PATTERN.finditer(html_text):
        token = m.group(0)
        uuid_replacements.setdefault(token, _hash_token(token))
    for raw, repl in uuid_replacements.items():
        html_text = html_text.replace(raw, repl)

    # 7) MAC addresses → placeholder (conservative — we don't try to
    #    distinguish operator vs case MACs; treat all rendered MACs as PII.)
    html_text = MAC_PATTERN.sub("<mac>", html_text)

    # 8) Operator-supplied extras
    for token in extra_tokens:
        if token:
            html_text = html_text.replace(token, "<redacted>")

    return html_text


def _append_attribution_footer(html_text: str) -> str:
    """Add a single MIT-attribution credit footer (best practice)."""
    footer = (
        '\n<div style="margin-top: 2rem; padding: 1rem; '
        'text-align: center; color: #6b7280; font-size: 0.75rem;">'
        'Rendered by '
        '<a href="https://github.com/daaain/claude-code-log" '
        'style="color: #6b7280;">claude-code-log v1.3.0</a> · MIT'
        '</div>\n'
    )
    if "</body>" in html_text:
        return html_text.replace("</body>", footer + "</body>", 1)
    return html_text + footer


# ---------------------------------------------------------------------------
# Session JSONL auto-discovery.
# ---------------------------------------------------------------------------


def _autodiscover_session_jsonl() -> Path | None:
    """Pick the most-recent .jsonl under ~/.claude/projects/*/, if any."""
    projects_root = Path.home() / ".claude" / "projects"
    if not projects_root.is_dir():
        return None
    candidates = list(projects_root.glob("*/*.jsonl"))
    if not candidates:
        return None
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0]


# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Render a Claude Code session JSONL into a redacted trace.html.",
    )
    parser.add_argument("--case-id", required=True,
                        help="Case identifier (e.g. SRL-2018-WKSTN01). Used as the reports subdir.")
    parser.add_argument("--session-jsonl", default=None,
                        help="Explicit path to the Claude Code session JSONL. "
                             "If omitted, auto-discovers the most recent in ~/.claude/projects/*/.")
    parser.add_argument("--output", default=None,
                        help="Output HTML path. Default: reports/<case-id>/trace.html")
    parser.add_argument("--reports-root", default="./reports",
                        help="Reports root directory (default: ./reports).")
    parser.add_argument("--detail", default="low",
                        choices=("full", "high", "low", "minimal", "user-only"),
                        help="claude-code-log --detail level. Default 'low' (peer reviewer sign-off; "
                             "'high' is opt-in for internal audit/demo prep, NOT public submission).")
    parser.add_argument("--manifest", default=None,
                        help="Path to manifest.json (for evidence dataset discovery).")
    parser.add_argument("--redact-lan", default=None,
                        help="Operator-LAN CIDR (e.g. 10.0.0.0/24) to redact. "
                             "Also accepts env var SAVVYDFIR_OPERATOR_LAN.")
    parser.add_argument("--redact-extra", action="append", default=[],
                        help="Additional literal tokens to scrub. Repeatable.")
    args = parser.parse_args()

    # Preflight: claude-code-log must be importable in the venv.
    try:
        import claude_code_log  # noqa: F401
    except ImportError:
        sys.stderr.write(
            "ERROR: claude-code-log not installed. Install with:\n"
            "  pip install claude-code-log==1.3.0\n"
        )
        return 1

    # Resolve session JSONL
    if args.session_jsonl:
        session_jsonl = Path(args.session_jsonl).expanduser().resolve()
    else:
        discovered = _autodiscover_session_jsonl()
        if discovered is None:
            sys.stderr.write(
                "ERROR: --session-jsonl not given and no JSONL found under "
                "~/.claude/projects/*/. Pass --session-jsonl explicitly.\n"
            )
            return 1
        session_jsonl = discovered.resolve()
        sys.stderr.write(f"INFO: auto-discovered session: {session_jsonl}\n")
    if not session_jsonl.is_file():
        sys.stderr.write(f"ERROR: session JSONL does not exist: {session_jsonl}\n")
        return 1

    # Output path
    if args.output:
        output_path = Path(args.output).expanduser().resolve()
    else:
        output_path = (Path(args.reports_root) / args.case_id / "trace.html").resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Resolve LAN CIDR (CLI > env)
    lan_cidr = args.redact_lan or os.environ.get("SAVVYDFIR_OPERATOR_LAN") or None

    # Manifest for evidence-path discovery
    manifest_path = Path(args.manifest).expanduser().resolve() if args.manifest else None
    if manifest_path is None:
        # Try the canonical case-templates/manifest.json next to the script
        candidate = Path("/cases") / args.case_id / "manifest.json"
        if candidate.is_file():
            manifest_path = candidate

    # Step 1: render via claude-code-log to a temp HTML file.
    # The package does not expose a -m entry point; use the console script
    # installed in the same venv as the running interpreter.
    cli_path = Path(sys.executable).with_name("claude-code-log")
    if not cli_path.is_file():
        sys.stderr.write(
            f"ERROR: console script not found at {cli_path}. "
            f"Reinstall with: pip install claude-code-log==1.3.0\n"
        )
        return 1
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        cmd = [
            str(cli_path),
            str(session_jsonl),
            "--output", str(tmp_path),
            "--format", "html",
            "--detail", args.detail,
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if proc.returncode != 0:
            sys.stderr.write(
                f"ERROR: claude-code-log failed (exit {proc.returncode}).\n"
                f"  stderr: {proc.stderr.strip()[:500]}\n"
                f"  hint:   try a different --detail (low|minimal|user-only) or "
                f"pass --session-jsonl explicitly.\n"
            )
            return 1

        # Step 2: read rendered HTML
        if not tmp_path.is_file() or tmp_path.stat().st_size == 0:
            sys.stderr.write("ERROR: claude-code-log produced an empty file.\n")
            return 1
        rendered = tmp_path.read_text(encoding="utf-8", errors="replace")

        # Step 3: redact
        redacted = redact(
            rendered,
            case_id=args.case_id,
            manifest_path=manifest_path,
            extra_tokens=args.redact_extra,
            lan_cidr=lan_cidr,
        )

        # Step 4: attribution footer
        final_html = _append_attribution_footer(redacted)

        # Step 5: write
        output_path.write_text(final_html, encoding="utf-8")
        sys.stderr.write(
            f"OK: wrote {output_path} ({len(final_html)} bytes, "
            f"detail={args.detail})\n"
            "NEXT: open it in a browser and eyeball-scan before publishing — "
            "redaction is best-effort; trust nothing.\n"
        )
        return 0
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())

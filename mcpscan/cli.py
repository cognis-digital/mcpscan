"""Command-line interface for mcpscan."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    Report,
    ScanError,
    SEVERITY_ORDER,
    probe_endpoint,
    scan_path,
    scan_url,
    to_badge,
    to_html,
    to_json,
    to_sarif,
)

_SEV_LABEL = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
    "info": "INFO",
}


def _render_table(report: Report) -> str:
    lines: List[str] = []
    kind = {"endpoint": "live endpoint", "url": "remote url"}.get(
        report.target_kind, "source")
    lines.append(f"mcpscan — {kind}: {report.source}")
    if report.target_kind in ("source", "url"):
        lines.append(f"files scanned: {report.files_scanned}")
    if report.ai_used:
        lines.append("AI: enabled (findings tagged [ai])")
    if report.ai_note:
        lines.append(f"AI note: {report.ai_note}")
    lines.append("=" * 70)
    if not report.findings:
        lines.append("No findings.")
    else:
        for f in report.findings:
            label = _SEV_LABEL.get(f.severity, f.severity.upper())
            src = " [ai]" if f.source == "ai" else ""
            novel = " (NOVEL)" if f.novel else ""
            tags = []
            if f.cwe:
                tags.append(f.cwe)
            if f.owasp_llm:
                tags.append(f"OWASP {f.owasp_llm}")
            if f.ms_taxonomy:
                tags.append(f"MS:{f.ms_taxonomy}")
            tag_str = ("  {" + ", ".join(tags) + "}") if tags else ""
            lines.append(f"[{label}] {f.rule}{src}{novel}{tag_str}")
            lines.append(f"        {f.message}")
            if f.location:
                lines.append(f"        at:  {f.location}")
            if f.remediation:
                lines.append(f"        fix: {f.remediation}")
    c = report.counts
    lines.append("-" * 70)
    lines.append(
        f"score={report.score}/100  "
        f"critical={c['critical']} high={c['high']} medium={c['medium']} "
        f"low={c['low']} info={c['info']}"
    )
    return "\n".join(lines)


def _emit(report: Report, fmt: str, out_path: Optional[str]) -> None:
    if fmt == "json":
        text = to_json(report)
    elif fmt == "sarif":
        text = to_sarif(report)
    elif fmt == "html":
        text = to_html(report)
    elif fmt == "badge":
        text = to_badge(report)
    else:
        text = _render_table(report)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"wrote {fmt} report to {out_path}", file=sys.stderr)
    else:
        _print_unicode_safe(text)


def _print_unicode_safe(text: str) -> None:
    """Print to stdout, tolerating consoles whose encoding (e.g. Windows
    cp1252) can't represent every character in the report."""
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # py3.7+; no-op if already
    except Exception:
        pass
    try:
        print(text)
    except UnicodeEncodeError:
        enc = getattr(sys.stdout, "encoding", None) or "ascii"
        sys.stdout.write(text.encode(enc, "replace").decode(enc) + "\n")


_FORMATS = ("table", "json", "sarif", "html", "badge")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Scan MCP servers for the OWASP-LLM-Top-10 + MCP/agent "
                    "threat surface (RCE/SSRF/path-traversal/deserialization/"
                    "SSTI/secrets/tool-poisoning/confused-deputy/excessive-"
                    "agency) — static source analysis (with AST taint "
                    "dataflow) + live endpoint probe + remote URL scan, plus an "
                    "opt-in AI review layer.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    def _common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--format", choices=_FORMATS,
                        default="table", help="Output format (default: table).")
        sp.add_argument("--out", metavar="PATH",
                        help="Write the report to PATH instead of stdout.")
        sp.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER), default=None,
                        help="Exit non-zero if any finding is at/above this "
                             "severity (e.g. --fail-on high).")

    def _ai(sp: argparse.ArgumentParser) -> None:
        sp.add_argument(
            "--ai", action="store_true",
            help="OPT-IN: also run the configured Cognis fleet AI backend "
                 "(env COGNIS_AI_BACKEND / COGNIS_AI_ENDPOINT) over the same "
                 "source and merge novel findings tagged [ai]. OFF by default; "
                 "without --ai the scan is byte-for-byte deterministic. If the "
                 "backend is unreachable the scan continues on rules only.")
        sp.add_argument(
            "--ai-focus", metavar="TEXT", default=None,
            help="Extra guidance handed to the AI reviewer (optional).")

    sc = sub.add_parser("scan",
                        help="Statically scan a file/dir of MCP server source.")
    sc.add_argument("path", help="Path to MCP server source (file or dir).")
    _common(sc)
    _ai(sc)

    su = sub.add_parser(
        "scan-url",
        help="Fetch a public GitHub / raw URL of an MCP server file and scan it.")
    su.add_argument("url", help="github.com/.../blob/... or raw.githubusercontent URL.")
    su.add_argument("--timeout", type=float, default=10.0,
                    help="Network timeout in seconds (default: 10).")
    _common(su)
    _ai(su)

    pr = sub.add_parser("probe",
                        help="Probe a live HTTP MCP endpoint (tools/list).")
    pr.add_argument("url", help="http(s):// MCP endpoint URL.")
    pr.add_argument("--token", help="Bearer token to use when probing.")
    pr.add_argument("--timeout", type=float, default=6.0,
                    help="Network timeout in seconds (default: 6).")
    _common(pr)

    return p


def _exit_code(report: Report, fail_on: Optional[str]) -> int:
    if fail_on and report.fail(fail_on):
        return 1
    return 0


def _run_scan(args: argparse.Namespace) -> int:
    try:
        report = scan_path(args.path, use_ai=getattr(args, "ai", False),
                           ai_focus=getattr(args, "ai_focus", None))
    except ScanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if report.ai_note and getattr(args, "ai", False):
        # surface the note on stderr too (visible regardless of --format)
        print(f"note: {report.ai_note}", file=sys.stderr)
    _emit(report, args.format, args.out)
    return _exit_code(report, args.fail_on)


def _run_scan_url(args: argparse.Namespace) -> int:
    try:
        report = scan_url(args.url, timeout=args.timeout,
                          use_ai=getattr(args, "ai", False),
                          ai_focus=getattr(args, "ai_focus", None))
    except ScanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if report.ai_note:
        print(f"note: {report.ai_note}", file=sys.stderr)
    _emit(report, args.format, args.out)
    return _exit_code(report, args.fail_on)


def _run_probe(args: argparse.Namespace) -> int:
    try:
        report = probe_endpoint(
            args.url,
            token=args.token,
            timeout=args.timeout,
        )
    except ScanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _emit(report, args.format, args.out)
    return _exit_code(report, args.fail_on)


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "scan-url":
        return _run_scan_url(args)
    if args.command == "probe":
        return _run_probe(args)
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

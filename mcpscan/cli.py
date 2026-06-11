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
    kind = "live endpoint" if report.target_kind == "endpoint" else "source"
    lines.append(f"mcpscan — {kind}: {report.source}")
    if report.target_kind == "source":
        lines.append(f"files scanned: {report.files_scanned}")
    lines.append("=" * 70)
    if not report.findings:
        lines.append("No findings.")
    else:
        for f in report.findings:
            label = _SEV_LABEL.get(f.severity, f.severity.upper())
            lines.append(f"[{label}] {f.rule}")
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
    else:
        text = _render_table(report)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print(f"wrote {fmt} report to {out_path}", file=sys.stderr)
    else:
        print(text)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Scan MCP servers for RCE/SSRF/no-auth/tool-poisoning "
                    "vulnerabilities — static source analysis + live probe.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    def _common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--format", choices=("table", "json", "sarif"),
                        default="table", help="Output format (default: table).")
        sp.add_argument("--out", metavar="PATH",
                        help="Write the report to PATH instead of stdout.")
        sp.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER), default=None,
                        help="Exit non-zero if any finding is at/above this "
                             "severity (e.g. --fail-on high).")

    sc = sub.add_parser("scan",
                        help="Statically scan a file/dir of MCP server source.")
    sc.add_argument("path", help="Path to MCP server source (file or dir).")
    _common(sc)

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
        report = scan_path(args.path)
    except ScanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _emit(report, args.format, args.out)
    return _exit_code(report, args.fail_on)


def _run_probe(args: argparse.Namespace) -> int:
    headers = None
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
    if args.command == "probe":
        return _run_probe(args)
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

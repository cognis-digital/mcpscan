"""Command-line interface for MCPHARDEN."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    ManifestError,
    Report,
    SEVERITY_ORDER,
    audit_manifest,
    load_manifest,
    scan,
    scan_to_dict,
    to_html,
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
    lines.append(f"MCPHARDEN audit — {report.server_name}  (source: {report.source})")
    lines.append("=" * 68)
    if not report.findings:
        lines.append("No findings. Manifest passes hardening checks.")
    else:
        for f in report.findings:
            label = _SEV_LABEL.get(f.severity, f.severity.upper())
            lines.append(f"[{label}] {f.rule}")
            lines.append(f"        {f.message}")
            if f.location:
                lines.append(f"        at: {f.location}")
            if f.remediation:
                lines.append(f"        fix: {f.remediation}")
    c = report.counts
    lines.append("-" * 68)
    lines.append(
        f"score={report.score}/100  "
        f"critical={c['critical']} high={c['high']} medium={c['medium']} "
        f"low={c['low']} info={c['info']}"
    )
    lines.append("RESULT: " + ("FAIL" if report.failed else "PASS"))
    return "\n".join(lines)


def _render_scan_table(reports: List[Report]) -> str:
    if not reports:
        return "No manifests found to scan."
    blocks = [_render_table(r) for r in reports]
    failing = sum(1 for r in reports if r.failed)
    blocks.append("=" * 68)
    blocks.append(
        f"SCAN SUMMARY: {len(reports)} server(s), {failing} failing, "
        f"{sum(len(r.findings) for r in reports)} finding(s)."
    )
    return "\n\n".join(blocks)


def _fails_gate(reports: List[Report], fail_on: Optional[str]) -> bool:
    """A scan/audit "fails" if any finding is at or above the gate severity.

    With no ``--fail-on`` the default policy is the historical one: any
    critical or high finding fails (``Report.failed``).
    """
    if not fail_on:
        return any(r.failed for r in reports)
    threshold = SEVERITY_ORDER[fail_on]
    return any(
        SEVERITY_ORDER.get(f.severity, 99) <= threshold
        for r in reports for f in r.findings
    )


def _emit(text: str, out: Optional[str]) -> None:
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text if text.endswith("\n") else text + "\n")
        print(f"wrote {out}", file=sys.stderr)
    else:
        print(text)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="MCP server hardening linter — audits capability "
                    "declarations, transport, and tool descriptions.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    # audit: single manifest, human-first (kept for back-compat).
    audit = sub.add_parser(
        "audit", help="Audit a single MCP server manifest (JSON) for weaknesses.")
    audit.add_argument("manifest", help="Path to the MCP server manifest JSON.")
    audit.add_argument("--format", choices=("table", "json", "sarif", "html"),
                       default="table", help="Output format (default: table).")
    audit.add_argument("--min-severity", choices=tuple(SEVERITY_ORDER),
                       default="info",
                       help="Only report findings at or above this severity.")
    audit.add_argument("--out", help="Write output to this file instead of stdout.")
    audit.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER), default=None,
                       help="Exit non-zero if a finding at/above this severity exists.")

    # scan: file OR directory (fleet), all formats.
    sc = sub.add_parser(
        "scan", help="Scan a manifest file or a directory of manifests.")
    sc.add_argument("target", help="Manifest file or directory to scan.")
    sc.add_argument("--format", choices=("table", "json", "sarif", "html"),
                    default="table", help="Output format (default: table).")
    sc.add_argument("--min-severity", choices=tuple(SEVERITY_ORDER), default="info",
                    help="Only report findings at or above this severity.")
    sc.add_argument("--out", help="Write output to this file instead of stdout.")
    sc.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER), default=None,
                    help="Exit non-zero if a finding at/above this severity exists.")

    # configscan: audit a real MCP *client* config (Claude Desktop / Cursor / …).
    cfg = sub.add_parser(
        "configscan",
        help="Audit an MCP client config (Claude Desktop/Cursor/Cline/VSCode) for risky servers.")
    cfg.add_argument("config", nargs="?",
                     help="Path to the config JSON (default: auto-detect common locations).")
    cfg.add_argument("--format", choices=("table", "json", "sarif", "html"), default="table")
    cfg.add_argument("--min-severity", choices=tuple(SEVERITY_ORDER), default="info")
    cfg.add_argument("--out", help="Write output to this file instead of stdout.")
    cfg.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER), default=None)

    # baseline: pin trusted tool definitions for rug-pull detection.
    bl = sub.add_parser("baseline", help="Pin a manifest's tool definitions to a baseline file.")
    bl.add_argument("manifest", help="Path to the trusted MCP server manifest JSON.")
    bl.add_argument("-o", "--out", required=True, help="Baseline JSON path to write.")

    # diff: detect drift (rug pull) vs a saved baseline.
    df = sub.add_parser("diff", help="Diff a manifest against a baseline to detect tool rug-pulls.")
    df.add_argument("manifest", help="Path to the current MCP server manifest JSON.")
    df.add_argument("--baseline", required=True, help="Baseline JSON written by 'baseline'.")
    df.add_argument("--format", choices=("table", "json", "sarif", "html"), default="table")
    df.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER), default=None)

    # posture: fleet-wide cross-server correlation (collisions, shared secrets,
    # lateral-movement surface, trust-tier inconsistency, fleet grade).
    pos = sub.add_parser(
        "posture",
        help="Correlate a fleet of MCP servers: cross-server risks a per-server audit can't see.")
    pos.add_argument("target", help="Directory (or file) of MCP server manifests.")
    pos.add_argument("--format", choices=("table", "json", "html"), default="table",
                     help="Output format (default: table).")
    pos.add_argument("--out", help="Write output to this file instead of stdout.")
    pos.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER), default=None,
                     help="Exit non-zero if a correlation finding at/above this severity exists.")
    pos.add_argument("--min-grade", choices=("A", "B", "C", "D", "F"), default=None,
                     help="Exit non-zero if the fleet grade is below this letter.")

    # mcp: expose as an MCP server over stdio.
    mcp = sub.add_parser("mcp", help="Run as an MCP server (stdio JSON-RPC).")
    mcp.add_argument("--host", default=None, help="Reserved; stdio transport only.")

    # rules: list the detection catalogue.
    sub.add_parser("rules", help="List the built-in detection rules.")

    # vulndb: the MCP vulnerability taxonomy (classes + CVEs).
    vdb = sub.add_parser("vulndb",
                         help="Show the MCP vulnerability catalog (classes, CVEs, refs).")
    vdb.add_argument("--cve", help="Show entries citing this CVE (e.g. CVE-2025-54136).")
    vdb.add_argument("--id", help="Show one class by id (e.g. MCP-CI-01).")
    vdb.add_argument("--format", choices=("table", "json"), default="table")
    return p


def _apply_min_severity(report: Report, min_sev: str) -> None:
    threshold = SEVERITY_ORDER[min_sev]
    report.findings = [
        f for f in report.findings
        if SEVERITY_ORDER.get(f.severity, 99) <= threshold
    ]


def _run_audit(args: argparse.Namespace) -> int:
    try:
        manifest = load_manifest(args.manifest)
    except (OSError, ManifestError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = audit_manifest(manifest, source=args.manifest)
    _apply_min_severity(report, args.min_severity)

    fmt = args.format
    if fmt == "json":
        _emit(json.dumps(report.to_dict(), indent=2), args.out)
    elif fmt == "sarif":
        _emit(json.dumps(to_sarif([report]), indent=2), args.out)
    elif fmt == "html":
        _emit(to_html([report]), args.out)
    else:
        _emit(_render_table(report), args.out)

    return 1 if _fails_gate([report], args.fail_on) else 0


def _run_scan(args: argparse.Namespace) -> int:
    try:
        reports = scan(args.target)
    except (OSError, ManifestError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    for r in reports:
        _apply_min_severity(r, args.min_severity)

    fmt = args.format
    if fmt == "json":
        # Recompute aggregate from the (possibly severity-filtered) reports.
        payload = scan_to_dict(args.target)
        payload["reports"] = [r.to_dict() for r in reports]
        _emit(json.dumps(payload, indent=2), args.out)
    elif fmt == "sarif":
        _emit(json.dumps(to_sarif(reports), indent=2), args.out)
    elif fmt == "html":
        _emit(to_html(reports), args.out)
    else:
        _emit(_render_scan_table(reports), args.out)

    return 1 if _fails_gate(reports, args.fail_on) else 0


def _run_rules() -> int:
    from .core import _DANGEROUS_VERBS  # noqa: F401  (kept local; informational)
    catalogue = [
        ("transport.bind_all", "critical", "HTTP transport bound to all interfaces."),
        ("transport.no_tls", "high", "Network transport without TLS."),
        ("transport.no_auth", "high", "Network transport without an auth declaration."),
        ("transport.undeclared", "medium", "No transport type declared."),
        ("transport.unknown_type", "low", "Unrecognized transport type."),
        ("transport.wildcard_origin", "medium", "Wildcard allowed_origins (DNS-rebind)."),
        ("transport.malformed", "high", "transport is not an object or known string."),
        ("capability.tools_mismatch", "high", "Tools exposed but capability not advertised."),
        ("capability.undeclared", "medium", "No capabilities block."),
        ("capability.malformed", "high", "capabilities is not an object."),
        ("capability.tools_empty", "low", "Advertises tools capability but exposes none."),
        ("capability.experimental", "low", "Experimental capabilities enabled."),
        ("tool.no_name", "high", "Tool has no name."),
        ("tool.duplicate_name", "high", "Duplicate tool name."),
        ("tool.no_description", "medium", "Tool has no description."),
        ("tool.thin_description", "low", "Tool description is too short."),
        ("tool.injection_in_description", "critical", "Instruction-smuggling in description."),
        ("tool.danger_no_schema", "high", "Side-effecting tool with no inputSchema."),
        ("tool.danger_no_confirm", "medium", "Side-effecting tool without confirmation."),
        ("tool.schema_open", "medium", "inputSchema additionalProperties=true."),
        ("tool.malformed", "high", "Tool entry is malformed."),
        ("manifest.embedded_secret", "critical", "Embedded credential / token in manifest."),
        ("manifest.unreadable", "high", "Manifest could not be parsed during a scan."),
        # 2025-2026 MCP attack classes (see `mcpharden vulndb`):
        ("tool.control_chars", "high", "ANSI/control chars in tool metadata (line jumping)."),
        ("tool.shadowing", "high", "Description references other tools (tool shadowing)."),
        ("tool.shell_exec", "critical", "Tool passes args to a shell (command injection/RCE)."),
        ("tool.mutable_registration", "high", "Dynamic tool registration (rug-pull channel)."),
        ("tool.auto_approve", "high", "Tool/server auto-approves calls (no human review)."),
        ("auth.token_passthrough", "high", "Upstream token forwarded to tools (confused deputy)."),
        ("auth.session_in_url", "high", "Session id carried in a URL (session hijack)."),
        ("auth.oauth_unbound", "high", "OAuth without PKCE/state (CSRF takeover)."),
        ("transport.cors_wildcard", "critical", "Wildcard CORS on network transport (DNS rebinding)."),
        ("transport.unpinned_command", "high", "Unpinned npx/uvx launch (supply-chain RCE)."),
        ("capabilities.sampling_unbounded", "medium", "Sampling exposed without rate limit (DoS/credit drain)."),
        # Cross-server fleet correlations (see `mcpharden posture`):
        ("fleet.shared_secret", "critical", "Same credential reused across servers (blast radius)."),
        ("fleet.tool_collision", "high", "One tool name registered by multiple servers (shadowing precondition)."),
        ("fleet.lateral_movement", "high", "RCE-prone server next to an exposed network peer (pivot surface)."),
        ("fleet.trust_tier_inconsistency", "high", "Some network peers require auth, others don't."),
        ("fleet.tls_inconsistency", "medium", "Cleartext network peer among TLS peers."),
        ("fleet.failure_concentration", "medium", "Majority of the fleet fails its per-server audit."),
    ]
    print(f"{TOOL_NAME} {TOOL_VERSION} — {len(catalogue)} detection rules")
    print("=" * 68)
    for rule, sev, desc in catalogue:
        print(f"[{_SEV_LABEL.get(sev, sev.upper())}] {rule:<34} {desc}")
    return 0


def _run_vulndb(args: argparse.Namespace) -> int:
    from . import vulndb
    if args.cve:
        entries = vulndb.by_cve(args.cve)
    elif args.id:
        one = vulndb.BY_ID.get(args.id.upper())
        entries = [one] if one else []
    else:
        entries = list(vulndb.CATALOG)
    if not entries:
        print("no matching vulnerability classes", file=sys.stderr)
        return 1
    if args.format == "json":
        print(json.dumps([e.to_dict() for e in entries], indent=2))
        return 0
    print(f"{TOOL_NAME} {TOOL_VERSION} — MCP vulnerability catalog "
          f"({len(entries)} classes, {len(vulndb.all_cves())} CVEs)")
    print("=" * 72)
    for e in entries:
        cves = (" [" + ", ".join(e.cves) + "]") if e.cves else ""
        rule = f"  detect: {e.detect_rule}" if e.detect_rule else "  (runtime/operational)"
        print(f"[{_SEV_LABEL.get(e.severity, e.severity.upper())}] {e.id:<12} {e.name}{cves}")
        print(f"      {e.summary}")
        print(f"     {rule}")
    return 0


def _emit_report(report: Report, fmt: str, out) -> None:
    if fmt == "json":
        _emit(json.dumps(report.to_dict(), indent=2), out)
    elif fmt == "sarif":
        _emit(json.dumps(to_sarif([report]), indent=2), out)
    elif fmt == "html":
        _emit(to_html([report]), out)
    else:
        _emit(_render_table(report), out)


def _run_configscan(args: argparse.Namespace) -> int:
    from .configaudit import audit_config_path, default_config_paths
    paths = [args.config] if args.config else [p for p in default_config_paths() if __import__("os").path.exists(p)]
    if not paths:
        print("error: no config given and no known MCP client config found; pass a path.",
              file=sys.stderr)
        return 2
    reports = []
    for p in paths:
        try:
            reports.append(audit_config_path(p))
        except (OSError, ValueError) as exc:
            print(f"error: {p}: {exc}", file=sys.stderr)
            return 2
    # merge into one report for output simplicity
    merged = Report(source=", ".join(paths),
                    server_name="; ".join(r.server_name for r in reports),
                    findings=[f for r in reports for f in r.findings])
    _apply_min_severity(merged, args.min_severity)
    _emit_report(merged, args.format, args.out)
    return 1 if _fails_gate([merged], args.fail_on) else 0


def _run_baseline(args: argparse.Namespace) -> int:
    from .baseline import build_baseline
    try:
        manifest = load_manifest(args.manifest)
    except (OSError, ManifestError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    bl = build_baseline(manifest)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(bl, fh, indent=2, sort_keys=True)
    print(f"baselined {len(bl['tools'])} tool(s) from '{bl['server']}' -> {args.out}",
          file=sys.stderr)
    return 0


def _run_diff(args: argparse.Namespace) -> int:
    from .baseline import diff_baseline
    try:
        manifest = load_manifest(args.manifest)
        with open(args.baseline, "r", encoding="utf-8") as fh:
            baseline = json.load(fh)
    except (OSError, ManifestError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    report = diff_baseline(baseline, manifest, source=args.manifest)
    _emit_report(report, args.format, None)
    return 1 if _fails_gate([report], args.fail_on) else 0


_GRADE_ORDER = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}


def _run_posture(args: argparse.Namespace) -> int:
    from . import posture
    try:
        pr = posture.assess(args.target)
    except (OSError, ManifestError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    fmt = args.format
    if fmt == "json":
        _emit(json.dumps(pr.to_dict(), indent=2), args.out)
    elif fmt == "html":
        _emit(posture.render_html(pr), args.out)
    else:
        _emit(posture.render_table(pr), args.out)

    rc = 0
    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER.get(f.severity, 99) <= threshold for f in pr.findings):
            rc = 1
    if args.min_grade and _GRADE_ORDER[pr.grade] > _GRADE_ORDER[args.min_grade]:
        rc = 1
    return rc


def _run_mcp() -> int:
    from .mcp_server import run_mcp_server
    run_mcp_server()
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "audit":
        return _run_audit(args)
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "rules":
        return _run_rules()
    if args.command == "vulndb":
        return _run_vulndb(args)
    if args.command == "configscan":
        return _run_configscan(args)
    if args.command == "baseline":
        return _run_baseline(args)
    if args.command == "diff":
        return _run_diff(args)
    if args.command == "posture":
        return _run_posture(args)
    if args.command == "mcp":
        return _run_mcp()
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

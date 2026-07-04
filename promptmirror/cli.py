"""Command-line interface for PROMPTMIRROR."""
from __future__ import annotations

import argparse
import json
import sys

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    CATEGORIES,
    OWASP_LLM,
    RULES,
    SEVERITY_ORDER,
    ScanResult,
    scan,
)

_VERDICT_GLYPH = {
    "block": "BLOCK", "flag": "FLAG ", "review": "REVW ", "clean": "OK   ",
}


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


# --------------------------------------------------------------------------- #
# Renderers
# --------------------------------------------------------------------------- #
def _render_scan_table(res: ScanResult, source: str) -> str:
    out: list[str] = []
    out.append(f"PROMPTMIRROR scan — {source}")
    out.append("=" * 60)
    out.append(f"verdict      : {res.verdict.upper()}  (risk {res.risk_score}/100)")
    out.append(f"text length  : {res.text_len} chars")
    out.append(f"max severity : {res.max_severity.upper()}")
    if res.decoded_layers:
        out.append(f"decoded      : {', '.join(sorted(set(res.decoded_layers)))}")
    counts = res.counts()
    sev = ", ".join(f"{k}={counts[k]}" for k in reversed(SEVERITY_ORDER) if counts[k]) or "none"
    out.append(f"severities   : {sev}")
    ob = res.owasp_breakdown()
    if ob:
        out.append("owasp        : " + ", ".join(
            f"{k}({OWASP_LLM.get(k, k)})={v}" for k, v in sorted(ob.items())))
    out.append("")

    if not res.matches:
        out.append("No injection signatures detected.")
        return "\n".join(out)

    out.append(f"{len(res.matches)} detection(s):")
    out.append("")
    for m in res.matches:
        out.append(f"  [{m.severity.upper():8}] {m.rule_id:18} {m.owasp}  {m.name}")
        out.append(f"             cat={m.category}  layer={m.layer}  span={m.span[0]}:{m.span[1]}")
        out.append(f"             evidence: {m.evidence}")
        out.append(f"             {m.description}")
        out.append("")
    return "\n".join(out).rstrip()


def _render_rules_table(rules) -> str:
    out = [f"PROMPTMIRROR signature library — {len(rules)} rule(s)", "=" * 60]
    for r in rules:
        out.append(f"[{r.severity.upper():8}] {r.id:18} {r.owasp:6} {r.category:16} {r.name}")
        out.append(f"           {r.description}")
    return "\n".join(out)


def _render_owasp_table() -> str:
    out = ["OWASP Top 10 for LLM Applications (2025) — covered categories", "=" * 60]
    by_owasp: dict[str, list] = {}
    for r in RULES:
        by_owasp.setdefault(r.owasp, []).append(r)
    for code in sorted(by_owasp):
        rs = by_owasp[code]
        out.append(f"{code}  {OWASP_LLM.get(code, code)}  ({len(rs)} rule(s))")
        for r in rs:
            out.append(f"    - {r.id:18} {r.name}")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Scan untrusted text for prompt-injection / LLM-abuse "
                    "signatures (jailbreaks, role hijack, markdown exfil, "
                    "encoding smuggling, tool-call injection) mapped to the "
                    "OWASP Top 10 for LLM Applications.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan a file/stdin/string for injection")
    src = s.add_mutually_exclusive_group(required=True)
    src.add_argument("path", nargs="?", help="file to scan, or '-' for stdin")
    src.add_argument("-t", "--text", help="scan this literal string instead of a file")
    s.add_argument("-c", "--category", action="append", choices=CATEGORIES,
                   help="restrict to category (repeatable; default: all)")
    s.add_argument("--min-severity", choices=SEVERITY_ORDER, default="info",
                   help="ignore matches below this severity")
    s.add_argument("--no-decode", action="store_true",
                   help="do not re-scan base64/hex/rot13-decoded layers")
    s.add_argument("--fail-on", choices=SEVERITY_ORDER, default=None,
                   help="exit non-zero only if a match >= this severity is found "
                        "(default: any match fails)")
    s.add_argument("--format", choices=("table", "json"), default="table")

    r = sub.add_parser("rules", help="list the bundled signature library")
    r.add_argument("-c", "--category", action="append", choices=CATEGORIES,
                   help="filter by category (repeatable)")
    r.add_argument("--format", choices=("table", "json"), default="table")

    o = sub.add_parser("owasp", help="show OWASP LLM Top 10 coverage map")
    o.add_argument("--format", choices=("table", "json"), default="table")
    return p


# --------------------------------------------------------------------------- #
# Command handlers
# --------------------------------------------------------------------------- #
def _cmd_scan(args) -> int:
    if args.text is not None:
        text, source = args.text, "<string>"
    else:
        try:
            text = _read(args.path)
        except OSError as exc:
            print(f"error: cannot read input: {exc}", file=sys.stderr)
            return 2
        source = "stdin" if args.path == "-" else args.path

    res = scan(text, categories=args.category,
               min_severity=args.min_severity, decode=not args.no_decode)

    if args.format == "json":
        out = json.dumps(res.to_dict(), indent=2)
    else:
        out = _render_scan_table(res, source)
    print(out)

    if not res.matches:
        return 0
    if args.fail_on is None:
        return 1
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    worst = max(rank[m.severity] for m in res.matches)
    return 1 if worst >= rank[args.fail_on] else 0


def _cmd_rules(args) -> int:
    rules = RULES
    if args.category:
        cats = set(args.category)
        rules = [r for r in RULES if r.category in cats]
    if args.format == "json":
        print(json.dumps([
            {"id": r.id, "name": r.name, "category": r.category,
             "owasp": r.owasp, "owasp_title": OWASP_LLM.get(r.owasp, r.owasp),
             "severity": r.severity, "description": r.description,
             "pattern": r.pattern}
            for r in rules], indent=2))
    else:
        print(_render_rules_table(rules))
    return 0


def _cmd_owasp(args) -> int:
    if args.format == "json":
        by: dict[str, dict] = {}
        for code, title in OWASP_LLM.items():
            rs = [r.id for r in RULES if r.owasp == code]
            by[code] = {"title": title, "rules": rs, "rule_count": len(rs)}
        print(json.dumps(by, indent=2))
    else:
        print(_render_owasp_table())
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "rules":
        return _cmd_rules(args)
    if args.command == "owasp":
        return _cmd_owasp(args)
    return 2


if __name__ == "__main__":
    sys.exit(main())

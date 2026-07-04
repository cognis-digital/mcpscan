"""Fleet posture correlation for MCPHARDEN.

Per-server auditing (:mod:`mcpharden.core`) answers "is *this* MCP server
hardened?". A real deployment is rarely one server: an agent host (Claude
Desktop, Cursor, an autonomous agent) connects to a *fleet* of MCP servers
that share one model context and one trust boundary. Whole classes of risk
only exist *between* servers and are structurally invisible to a per-manifest
audit:

  * **Tool-name collisions across servers.** Two servers both register
    ``read_file`` / ``search``. The model cannot reliably disambiguate which
    implementation runs — the precondition for cross-server *tool shadowing*
    (Invariant Labs) and confused-deputy tool routing. A per-server audit sees
    one ``read_file`` and shrugs.

  * **Shared / reused credentials.** The same embedded API key appears in
    three manifests. One poisoned server now leaks a credential whose blast
    radius is the whole fleet. Per-server secret scanning flags each copy in
    isolation but never connects them.

  * **Dangerous-capability concentration.** Individually a shell-exec tool and
    a bind-all transport are findings; *together, across a fleet*, they form a
    lateral-movement surface (RCE on one host + a network-reachable peer = a
    pivot). Posture quantifies how concentrated the dangerous surface is.

  * **Trust-tier inconsistency.** On the same transport family, some servers
    require auth and TLS and peers do not. The fleet is only as strong as its
    weakest network-reachable member; the unauth'd peer is the way in.

  * **Fleet rollup.** A single hardening grade for the deployment plus the one
    highest-leverage remediation, so an operator knows what to fix *first*.

No network, no exploit code: everything is computed locally from the same
manifests :func:`mcpharden.core.scan` already parses. Synthetic-for-tests and
real values only — nothing is fabricated.
"""

from __future__ import annotations

import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .core import (
    Finding,
    Report,
    SEVERITY_ORDER,
    audit_path,
    load_manifest,
    _normalize_transport,
    _DANGEROUS_RE,
    _SECRET_RE,
    _iter_manifest_files,
)

# Rules that, when present on a *network-reachable* server, mean an attacker who
# reaches the port (or rebinds DNS into it) gets meaningful authority. Used to
# weight concentration + lateral-movement scoring.
_RCE_RULES = frozenset({"tool.shell_exec", "transport.unpinned_command"})
_EXPOSURE_RULES = frozenset({
    "transport.bind_all", "transport.no_auth", "transport.no_tls",
    "transport.cors_wildcard", "transport.wildcard_origin",
})
_NETWORK_TYPES = frozenset({"http", "sse", "streamable-http"})

# Tokens that look like a real secret but are obviously placeholders/examples
# (so a fleet of demo manifests using the SAME ``YOUR_TOKEN_HERE`` is not
# reported as a reused live credential). Lowercased substring match.
_PLACEHOLDER_HINTS = (
    "your", "example", "changeme", "change_me", "placeholder", "xxxx",
    "redacted", "dummy", "sample", "test_token", "<", "...", "todo",
)

# Extract concrete secret strings from raw manifest text (the matched span),
# so identical credentials can be correlated across servers.
_SECRET_VALUE_RE = re.compile(
    r"(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{8,}"
    r"|ghp_[A-Za-z0-9]{16,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|xox[baprs]-[A-Za-z0-9\-]{8,}"
    r"|AKIA[0-9A-Z]{12,}"
    r"|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}"
)


@dataclass
class ServerSummary:
    """Compact per-server view used by the correlators."""

    source: str
    name: str
    transport_type: str
    network: bool
    failed: bool
    score: int
    rules: frozenset
    tool_names: Tuple[str, ...]
    secrets: Tuple[str, ...]
    has_auth: bool
    has_tls: bool


@dataclass
class PostureReport:
    """Fleet-level posture: per-server scores + cross-server correlations."""

    target: str
    servers: List[ServerSummary] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    @property
    def server_count(self) -> int:
        return len(self.servers)

    @property
    def network_count(self) -> int:
        return sum(1 for s in self.servers if s.network)

    @property
    def fleet_score(self) -> int:
        """0-100 fleet posture: mean per-server score, then penalized by the
        cross-server (correlation) findings that per-server scoring can't see."""
        if not self.servers:
            return 100
        base = sum(s.score for s in self.servers) / len(self.servers)
        weights = {"critical": 15, "high": 8, "medium": 3, "low": 1, "info": 0}
        penalty = sum(weights.get(f.severity, 0) for f in self.findings)
        return max(0, int(round(base)) - penalty)

    @property
    def grade(self) -> str:
        s = self.fleet_score
        if s >= 90:
            return "A"
        if s >= 80:
            return "B"
        if s >= 70:
            return "C"
        if s >= 55:
            return "D"
        return "F"

    @property
    def counts(self) -> Dict[str, int]:
        c = {k: 0 for k in SEVERITY_ORDER}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c

    @property
    def failed(self) -> bool:
        c = self.counts
        return c["critical"] > 0 or c["high"] > 0

    @property
    def top_remediation(self) -> Optional[str]:
        """The single highest-leverage fix: the remediation of the most-severe,
        earliest correlation finding (stable, deterministic)."""
        if not self.findings:
            return None
        worst = min(self.findings,
                    key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.rule))
        return worst.remediation or worst.message

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "fleet_score": self.fleet_score,
            "grade": self.grade,
            "server_count": self.server_count,
            "network_count": self.network_count,
            "failed": self.failed,
            "counts": self.counts,
            "top_remediation": self.top_remediation,
            "servers": [
                {
                    "source": s.source,
                    "name": s.name,
                    "transport": s.transport_type,
                    "network": s.network,
                    "score": s.score,
                    "failed": s.failed,
                }
                for s in self.servers
            ],
            "correlations": [f.to_dict() for f in self.findings],
        }


# --------------------------------------------------------------------------
# Summarization
# --------------------------------------------------------------------------

def _is_placeholder(secret: str) -> bool:
    low = secret.lower()
    return any(h in low for h in _PLACEHOLDER_HINTS)


def _extract_secrets(raw_text: str) -> Tuple[str, ...]:
    """Concrete, non-placeholder secret strings present in a manifest."""
    if not raw_text:
        return ()
    out: List[str] = []
    for m in _SECRET_VALUE_RE.finditer(raw_text):
        val = m.group(0)
        if not _is_placeholder(val) and val not in out:
            out.append(val)
    return tuple(out)


def _tool_names(manifest: Dict[str, Any]) -> Tuple[str, ...]:
    tools = manifest.get("tools")
    if not isinstance(tools, list):
        return ()
    names: List[str] = []
    for t in tools:
        if isinstance(t, dict):
            n = str(t.get("name", "")).strip()
            if n:
                names.append(n)
    return tuple(names)


def summarize(report: Report, manifest: Dict[str, Any]) -> ServerSummary:
    """Reduce a per-server :class:`Report` + its manifest to a summary."""
    transport = _normalize_transport(manifest)
    ttype = str(transport.get("type", "")).lower()
    network = ttype in _NETWORK_TYPES
    return ServerSummary(
        source=report.source,
        name=report.server_name,
        transport_type=ttype or "(undeclared)",
        network=network,
        failed=report.failed,
        score=report.score,
        rules=frozenset(f.rule for f in report.findings),
        tool_names=_tool_names(manifest),
        secrets=_extract_secrets(manifest.get("_raw_text", "")),
        has_auth=bool(transport.get("auth")),
        has_tls=bool(transport.get("tls", False)),
    )


# --------------------------------------------------------------------------
# Cross-server correlators (each returns Findings invisible to a per-server audit)
# --------------------------------------------------------------------------

def _correlate_tool_collisions(servers: List[ServerSummary]) -> List[Finding]:
    out: List[Finding] = []
    owners: Dict[str, List[str]] = defaultdict(list)
    for s in servers:
        for name in set(s.tool_names):
            owners[name].append(s.name)
    for name in sorted(owners):
        names = owners[name]
        if len(names) > 1:
            who = ", ".join(sorted(set(names)))
            out.append(Finding(
                "fleet.tool_collision", "high",
                f"Tool name '{name}' is registered by {len(names)} servers "
                f"({who}); the agent cannot deterministically disambiguate which "
                "implementation runs — the precondition for cross-server tool "
                "shadowing / confused-deputy routing.",
                f"tool:{name}",
                "Namespace tools per server (server prefix), or remove the "
                "duplicate registration so each tool name resolves to one server.",
            ))
    return out


def _correlate_shared_secrets(servers: List[ServerSummary]) -> List[Finding]:
    out: List[Finding] = []
    owners: Dict[str, List[str]] = defaultdict(list)
    for s in servers:
        for secret in s.secrets:
            owners[secret].append(s.name)
    for secret in sorted(owners):
        names = owners[secret]
        if len(set(names)) > 1:
            who = ", ".join(sorted(set(names)))
            # Show only a fingerprint, never the full credential.
            fp = secret[:6] + "…" + secret[-2:]
            out.append(Finding(
                "fleet.shared_secret", "critical",
                f"The same embedded credential ({fp}) appears in "
                f"{len(set(names))} manifests ({who}); compromise of any one "
                "server exposes a credential whose blast radius is the whole "
                "fleet, and rotation now requires touching every server.",
                "<fleet>",
                "Move the credential to a per-server secret store with distinct, "
                "least-privilege, independently-rotatable tokens; never share one "
                "key across servers.",
            ))
    return out


def _correlate_concentration(servers: List[ServerSummary]) -> List[Finding]:
    out: List[Finding] = []
    rce = [s for s in servers if s.rules & _RCE_RULES]
    exposed_net = [s for s in servers if s.network and (s.rules & _EXPOSURE_RULES)]
    # Lateral-movement surface: an RCE-capable server co-resident with a
    # network-reachable, exposed peer is a pivot.
    if rce and exposed_net:
        rnames = ", ".join(sorted(s.name for s in rce))
        enames = ", ".join(sorted(s.name for s in exposed_net))
        out.append(Finding(
            "fleet.lateral_movement", "high",
            f"{len(rce)} server(s) expose RCE-prone tools ({rnames}) while "
            f"{len(exposed_net)} network-reachable peer(s) are under-protected "
            f"({enames}); an attacker who lands code execution on one host can "
            "pivot to the exposed peer — a lateral-movement surface no single "
            "manifest reveals.",
            "<fleet>",
            "Isolate RCE-capable servers (separate host / network namespace), "
            "require auth+TLS on every network transport, and bind to localhost.",
        ))
    # Raw concentration: what fraction of the fleet is failing?
    if servers:
        failing = sum(1 for s in servers if s.failed)
        frac = failing / len(servers)
        if frac >= 0.5 and failing >= 2:
            out.append(Finding(
                "fleet.failure_concentration", "medium",
                f"{failing}/{len(servers)} servers ({int(frac * 100)}%) fail "
                "their per-server hardening audit; the deployment's dangerous "
                "surface is broad, not a single outlier.",
                "<fleet>",
                "Treat hardening as a fleet program: apply a baseline policy to "
                "every server and gate new servers in CI before they join.",
            ))
    return out


def _correlate_trust_tiers(servers: List[ServerSummary]) -> List[Finding]:
    out: List[Finding] = []
    net = [s for s in servers if s.network]
    if len(net) < 2:
        return out
    authed = [s for s in net if s.has_auth]
    unauthed = [s for s in net if not s.has_auth]
    if authed and unauthed:
        a = ", ".join(sorted(s.name for s in authed))
        u = ", ".join(sorted(s.name for s in unauthed))
        out.append(Finding(
            "fleet.trust_tier_inconsistency", "high",
            f"On network transports, {len(authed)} server(s) require auth "
            f"({a}) but {len(unauthed)} peer(s) do not ({u}); the fleet is only "
            "as strong as its weakest reachable member, and the unauth'd peer is "
            "the entry point.",
            "<fleet>",
            "Apply a uniform auth (and TLS) policy to every network-reachable "
            "server; there is no benefit to hardening some peers and not others.",
        ))
    # TLS consistency, separately (cleartext peer leaks tokens for the fleet).
    tls = [s for s in net if s.has_tls]
    notls = [s for s in net if not s.has_tls]
    if tls and notls:
        out.append(Finding(
            "fleet.tls_inconsistency", "medium",
            f"{len(notls)} network server(s) run without TLS while {len(tls)} "
            "peer(s) use it; cleartext peers leak tokens/traffic that protect "
            "the rest of the fleet.",
            "<fleet>",
            "Terminate TLS for every network transport (or front the fleet with "
            "one authenticating, TLS-terminating proxy).",
        ))
    return out


_CORRELATORS = (
    _correlate_shared_secrets,
    _correlate_tool_collisions,
    _correlate_trust_tiers,
    _correlate_concentration,
)


def analyze(servers: List[ServerSummary], target: str = "<fleet>") -> PostureReport:
    """Run every cross-server correlator over already-summarized servers."""
    findings: List[Finding] = []
    for correlate in _CORRELATORS:
        findings.extend(correlate(servers))
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.rule))
    return PostureReport(target=target, servers=list(servers), findings=findings)


def assess(target: str) -> PostureReport:
    """High-level entry point: scan a directory/file and correlate the fleet."""
    summaries: List[ServerSummary] = []
    for path in _iter_manifest_files(target):
        try:
            manifest = load_manifest(path)
        except Exception:  # noqa: BLE001 — unreadable manifests skipped from posture
            continue
        report = audit_path(path)
        summaries.append(summarize(report, manifest))
    # Stable order: worst score first, then name.
    summaries.sort(key=lambda s: (s.score, s.name))
    return analyze(summaries, target=target)


# --------------------------------------------------------------------------
# Renderers
# --------------------------------------------------------------------------

_SEV_LABEL = {
    "critical": "CRIT", "high": "HIGH", "medium": "MED ",
    "low": "LOW ", "info": "INFO",
}


def render_table(pr: PostureReport) -> str:
    lines: List[str] = []
    lines.append(f"MCPHARDEN fleet posture — {pr.target}")
    lines.append("=" * 72)
    lines.append(
        f"{pr.server_count} server(s), {pr.network_count} network-reachable.  "
        f"Fleet score: {pr.fleet_score}/100  (grade {pr.grade})"
    )
    lines.append("-" * 72)
    for s in pr.servers:
        flag = "FAIL" if s.failed else "PASS"
        net = "net" if s.network else "local"
        lines.append(f"  [{flag}] {s.score:>3}/100  {net:<5} {s.transport_type:<14} {s.name}")
    lines.append("-" * 72)
    if not pr.findings:
        lines.append("No cross-server correlation findings.")
    else:
        lines.append(f"CROSS-SERVER CORRELATIONS ({len(pr.findings)}):")
        for f in pr.findings:
            lines.append(f"[{_SEV_LABEL.get(f.severity, f.severity.upper())}] {f.rule}")
            lines.append(f"        {f.message}")
            if f.location:
                lines.append(f"        at: {f.location}")
            if f.remediation:
                lines.append(f"        fix: {f.remediation}")
    lines.append("=" * 72)
    if pr.top_remediation:
        lines.append(f"TOP PRIORITY: {pr.top_remediation}")
    c = pr.counts
    lines.append(
        f"correlations: critical={c['critical']} high={c['high']} "
        f"medium={c['medium']} low={c['low']}"
    )
    lines.append("RESULT: " + ("FAIL" if pr.failed else "PASS"))
    return "\n".join(lines)


_SEV_COLOR = {"critical": "#c0392b", "high": "#e67e22", "medium": "#f1c40f",
              "low": "#3498db", "info": "#95a5a6"}


def _esc(s: str) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def render_html(pr: PostureReport) -> str:
    """Self-contained, shareable HTML fleet-posture report."""
    gcolor = {"A": "#27ae60", "B": "#2ecc71", "C": "#f1c40f",
              "D": "#e67e22", "F": "#c0392b"}.get(pr.grade, "#777")
    srv_rows = []
    for s in pr.servers:
        scolor = "#c0392b" if s.failed else "#27ae60"
        net = "network" if s.network else "local"
        srv_rows.append(
            f"<tr><td style='color:{scolor};font-weight:600'>"
            f"{'FAIL' if s.failed else 'PASS'}</td>"
            f"<td>{s.score}/100</td><td>{_esc(net)}</td>"
            f"<td><code>{_esc(s.transport_type)}</code></td>"
            f"<td>{_esc(s.name)}</td></tr>"
        )
    corr_rows = []
    for f in pr.findings:
        color = _SEV_COLOR.get(f.severity, "#777")
        corr_rows.append(
            f"<tr><td><span class='sev' style='background:{color}'>"
            f"{f.severity.upper()}</span></td>"
            f"<td><code>{_esc(f.rule)}</code></td>"
            f"<td>{_esc(f.message)}</td>"
            f"<td>{_esc(f.remediation)}</td></tr>"
        )
    corr_html = (
        "<table><thead><tr><th>Severity</th><th>Rule</th><th>Finding</th>"
        "<th>Remediation</th></tr></thead><tbody>" + "".join(corr_rows) + "</tbody></table>"
        if corr_rows else "<p class='clean'>No cross-server correlation findings.</p>"
    )
    top = (f"<p class='top'><b>Top priority:</b> {_esc(pr.top_remediation)}</p>"
           if pr.top_remediation else "")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>mcpharden fleet posture</title>
<style>
 body{{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;color:#222;background:#fafafa}}
 .grade{{font-size:40px;font-weight:800;color:{gcolor}}}
 table{{border-collapse:collapse;width:100%;background:#fff;margin:1rem 0;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
 th,td{{border:1px solid #e1e1e1;padding:.5rem .6rem;text-align:left;vertical-align:top}}
 th{{background:#f3f4f6}}
 code{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}}
 .sev{{color:#fff;padding:.1rem .4rem;border-radius:.25rem;font-size:11px;font-weight:600}}
 .clean{{color:#27ae60}} .top{{background:#fff3cd;padding:.6rem;border-left:4px solid #e67e22}}
</style></head><body>
<h1>mcpharden — MCP fleet posture</h1>
<p class="grade">{pr.grade} &nbsp;<span style="font-size:18px;color:#555">{pr.fleet_score}/100</span></p>
<p>{_esc(pr.target)} — {pr.server_count} server(s), {pr.network_count} network-reachable,
{sum(1 for s in pr.servers if s.failed)} failing.</p>
{top}
<h2>Servers</h2>
<table><thead><tr><th>Result</th><th>Score</th><th>Reach</th><th>Transport</th><th>Name</th></tr></thead>
<tbody>{''.join(srv_rows)}</tbody></table>
<h2>Cross-server correlations</h2>
{corr_html}
<hr><p style="color:#999;font-size:12px">Generated by mcpharden — Cognis Neural Suite.</p>
</body></html>
"""

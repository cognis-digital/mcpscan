"""Curated catalog of Model Context Protocol (MCP) vulnerability classes.

This is the reference taxonomy mcpharden hardens against — every well-documented
MCP attack class through 2026, each tied to real CVEs / public advisories and a
detection rule where the weakness is statically observable in a server manifest.

Sources (public, 2025–2026): Invariant Labs tool-poisoning research; OWASP MCP
Tool Poisoning + MCP Security Cheat Sheet; the MCP-38 threat taxonomy
(arXiv:2603.18063); the Vulnerable MCP Project; and the CVEs cited per entry.

Each entry is data only — no exploit code. ``detect_rule`` names the mcpharden
core rule that flags the class on a manifest (``None`` = runtime/operational,
not statically detectable from a descriptor).
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Optional


@dataclass(frozen=True)
class VulnClass:
    id: str                     # mcpharden taxonomy id
    name: str
    severity: str               # critical|high|medium|low|info
    summary: str
    cves: tuple[str, ...]       # real CVEs / advisory ids
    references: tuple[str, ...]
    detect_rule: Optional[str]  # mcpharden core rule id that flags it (or None)
    remediation: str

    def to_dict(self) -> dict:
        return asdict(self)


CATALOG: tuple[VulnClass, ...] = (
    VulnClass(
        "MCP-TP-01", "Tool poisoning (hidden instructions in tool metadata)", "critical",
        "Malicious directives embedded in a tool's description/schema enter the model "
        "context at tools/list and are treated as trusted instructions.",
        ("CVE-2025-54136", "CVE-2025-54135"),
        ("Invariant Labs (Apr 2025)", "OWASP MCP Tool Poisoning",
         "https://owasp.org/www-community/attacks/MCP_Tool_Poisoning"),
        "tool.injection_in_description",
        "Treat tool descriptions as untrusted; strip/escape instructions, pin & "
        "re-verify descriptions at runtime, surface them to the user.",
    ),
    VulnClass(
        "MCP-LJ-01", "Line jumping (ANSI/control-char hiding in descriptions or output)", "high",
        "ANSI escape / control characters hide malicious text on screen while the "
        "model still ingests it, defeating human review of tool metadata.",
        (),
        ("MCP-38 taxonomy", "https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html"),
        "tool.control_chars",
        "Reject control/ANSI sequences in tool descriptions and outputs before they "
        "reach the model or the terminal.",
    ),
    VulnClass(
        "MCP-TS-01", "Cross-server tool shadowing", "high",
        "A malicious server's tool description manipulates how the agent uses tools "
        "from other trusted servers (cross-origin escalation).",
        (),
        ("Invariant Labs", "Vulnerable MCP Project"),
        "tool.shadowing",
        "Namespace tools per server; never let one server's metadata reference or "
        "override another's; isolate server contexts.",
    ),
    VulnClass(
        "MCP-RP-01", "Rug pull (mutable tool definitions after approval)", "high",
        "A server changes a tool's behavior/description after the user approved it — "
        "the connect-time vs runtime trust gap; dynamic registration is the channel.",
        ("CVE-2025-54136",),
        ("Invariant Labs", "TrueFoundry MCPoison analysis"),
        "tool.mutable_registration",
        "Pin tool definitions with a hash; re-prompt on any change; disable or gate "
        "dynamic tool registration.",
    ),
    VulnClass(
        "MCP-CI-01", "Command injection in tool handlers", "critical",
        "Tool arguments flow into a shell/exec call, yielding RCE on the server host.",
        ("CVE-2025-53967", "CVE-2025-54073", "CVE-2025-53818", "CVE-2025-69256",
         "CVE-2025-59834", "CVE-2025-53107"),
        ("ox.security MCP supply-chain advisory", "GitHub Advisory Database"),
        "tool.shell_exec",
        "Never pass tool input to a shell; use argv arrays / parameterized APIs; "
        "validate and allow-list inputs.",
    ),
    VulnClass(
        "MCP-TPT-01", "Token passthrough / authority collapse", "high",
        "Upstream tokens are forwarded to tools or the model context without scoping, "
        "collapsing the auth boundary (everything in-context has equal authority).",
        (),
        ("MCP Authorization spec", "OWASP MCP Cheat Sheet"),
        "auth.token_passthrough",
        "Mint short-lived, audience-scoped tokens per tool; never forward the user's "
        "bearer token to downstream tools.",
    ),
    VulnClass(
        "MCP-OAUTH-01", "OAuth/session binding failure (session id in URL, no CSRF binding)", "high",
        "Authorization codes not bound to a session and session ids exposed in URLs "
        "enable CSRF-style takeover and session hijacking.",
        (),
        ("OWASP MCP Cheat Sheet", "MCP-38 taxonomy"),
        "auth.session_in_url",
        "Bind auth codes to the session (PKCE/state); keep session ids out of URLs; "
        "use rotating, unguessable session tokens.",
    ),
    VulnClass(
        "MCP-SSE-01", "SSE/HTTP DNS rebinding via permissive CORS / no Origin check", "critical",
        "SSE/HTTP transports with wildcard CORS and no Origin validation are open to "
        "DNS-rebinding, letting a browser reach internal MCP services.",
        (),
        ("MCP Toolbox SSE advisory (2026)", "https://cybersecuritynews.com/mcp-toolbox-vulnerability/"),
        "transport.cors_wildcard",
        "Validate the Origin header, disable wildcard CORS, bind to localhost, and "
        "require auth on every SSE/HTTP request.",
    ),
    VulnClass(
        "MCP-AA-01", "Auto-approved tool execution (no human in the loop)", "high",
        "Clients/servers that auto-approve tool calls remove the human review that "
        "would catch poisoned descriptions before execution.",
        (),
        ("Invariant Labs", "Descope MCP vulnerabilities"),
        "tool.auto_approve",
        "Require explicit per-tool consent for sensitive/dangerous tools; default to "
        "review, not auto-run.",
    ),
    VulnClass(
        "MCP-SC-01", "Supply chain — unpinned server command/package (STDIO RCE)", "high",
        "Launching a server via an unpinned package (npx/uvx latest) lets a poisoned "
        "release execute on the host.",
        (),
        ("ox.security supply-chain advisory",),
        "transport.unpinned_command",
        "Pin server packages to a hash/version; vet and lock dependencies; run "
        "servers with least privilege.",
    ),
    VulnClass(
        "MCP-SAMP-01", "Sampling / resource-credit abuse (DoS, billing drain)", "medium",
        "Exposed sampling or paid tools without rate limits let an attacker drain "
        "credits or cause denial of service.",
        (),
        ("Kluster Verify advisory", "MCP-38 taxonomy"),
        "capabilities.sampling_unbounded",
        "Rate-limit and quota sampling/paid tools; require auth; alert on spend "
        "anomalies.",
    ),
    VulnClass(
        "MCP-SECRET-01", "Hardcoded secrets in manifest/config", "high",
        "API keys/tokens embedded in the server descriptor leak to anyone who reads it.",
        (),
        ("OWASP MCP Cheat Sheet",),
        "manifest.embedded_secret",
        "Load secrets from the environment / a secret manager; never commit them to "
        "the manifest.",
    ),
    VulnClass(
        "MCP-PRIV-01", "Over-broad capabilities / excessive scope", "medium",
        "Declaring more capability than needed widens blast radius if the server is "
        "compromised.",
        (),
        ("OWASP MCP Cheat Sheet", "MCP-38 taxonomy"),
        "capabilities.overbroad",
        "Declare least-privilege capabilities; split high-risk tools into a separate, "
        "tightly-scoped server.",
    ),
    VulnClass(
        "MCP-BIND-01", "Transport bound to all interfaces", "critical",
        "Binding HTTP/SSE to 0.0.0.0 exposes the MCP server off-host.",
        (),
        ("OWASP MCP Cheat Sheet",),
        "transport.bind_all",
        "Bind to 127.0.0.1 unless remote access is required, and front with authn/z.",
    ),
)

BY_ID = {v.id: v for v in CATALOG}
# Reverse map: core rule id -> catalog entry, so findings link to the taxonomy.
BY_RULE = {v.detect_rule: v for v in CATALOG if v.detect_rule}


def by_cve(cve: str) -> list[VulnClass]:
    cve = cve.upper()
    return [v for v in CATALOG if any(cve == c.upper() for c in v.cves)]


def all_cves() -> list[str]:
    seen: list[str] = []
    for v in CATALOG:
        for c in v.cves:
            if c not in seen:
                seen.append(c)
    return seen

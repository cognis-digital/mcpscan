"""Audit real MCP *client* config files — where servers are actually registered.

The biggest practical MCP risk surface isn't a server manifest in the abstract,
it's the `mcpServers` block a user pastes into Claude Desktop / Cursor / Cline /
Windsurf / VS Code. This module parses those config formats, extracts each
registered server, and flags the dangerous patterns:

* unpinned `npx`/`uvx`/`bunx` launch commands (supply-chain rug-pull vector)
* secrets hard-coded in a server's ``env`` block
* `sh -c` / shell-exec style commands (command-injection / RCE)
* remote (`http`/`sse`) servers with no auth header
* blanket auto-approve / always-allow tool lists (no human in the loop)

It reuses the suite Finding/Report model and the :mod:`mcpharden.vulndb`
taxonomy, so config findings merge with manifest findings in one report.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from .core import Finding, Report, _SECRET_RE

# command launchers whose package arg must be version-pinned
_UNPINNED_LAUNCHERS = {"npx", "uvx", "bunx", "pipx", "pnpm", "dlx"}
_SHELL_EXE = re.compile(r"\b(sh|bash|zsh|cmd|powershell|pwsh)\b", re.IGNORECASE)
_PINNED = re.compile(r"@\d|@v\d|==|@[0-9a-f]{7,40}\b")
# env value worth flagging as a secret (token-ish, not a path/flag/url)
_ENV_SECRET = re.compile(
    r"(sk-[A-Za-z0-9]{16,}|sk_(live|test)_[A-Za-z0-9]{8,}|AKIA[0-9A-Z]{16}|"
    r"ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}|"
    r"cg-sk-[A-Za-z0-9]{6,})")
_SECRET_KEYNAME = re.compile(r"(token|secret|api[_-]?key|password|passwd|bearer|access[_-]?key)",
                             re.IGNORECASE)


def _iter_servers(doc: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
    """Yield (name, server_obj) across the known client config shapes."""
    servers: List[Tuple[str, Dict[str, Any]]] = []
    # Claude Desktop / Cursor / Cline / Windsurf: {"mcpServers": {name: {...}}}
    # VS Code: {"mcp": {"servers": {...}}} or {"servers": {...}}
    candidates = [doc.get("mcpServers"),
                  (doc.get("mcp") or {}).get("servers") if isinstance(doc.get("mcp"), dict) else None,
                  doc.get("servers")]
    for block in candidates:
        if isinstance(block, dict):
            for name, obj in block.items():
                if isinstance(obj, dict):
                    servers.append((name, obj))
        elif isinstance(block, list):  # some formats use a list with "name"
            for obj in block:
                if isinstance(obj, dict):
                    servers.append((obj.get("name", "?"), obj))
    return servers


def _server_findings(name: str, srv: Dict[str, Any]) -> List[Finding]:
    out: List[Finding] = []
    loc = f"mcpServers.{name}"
    command = str(srv.get("command", "")).strip()
    args = srv.get("args") if isinstance(srv.get("args"), list) else []
    argstr = " ".join(str(a) for a in args)
    base = os.path.basename(command).lower()

    # 1) unpinned launcher (supply-chain)
    if base in _UNPINNED_LAUNCHERS or any(os.path.basename(str(a)).lower() in _UNPINNED_LAUNCHERS for a in args[:1]):
        if not _PINNED.search(argstr):
            out.append(Finding(
                "config.unpinned_command", "high",
                f"Server '{name}' launches via '{base or argstr[:12]}' with no pinned "
                "version — a poisoned package release would execute on your machine.",
                loc, "Pin the package to an exact version/hash (e.g. pkg@1.2.3)."))

    # 2) shell-exec command (command injection / RCE)
    if _SHELL_EXE.search(base) and any(a in ("-c", "/c", "-Command") for a in args):
        out.append(Finding(
            "config.shell_exec", "critical",
            f"Server '{name}' runs a shell command line ('{base} -c …') — "
            "command-injection / arbitrary execution risk.",
            loc, "Launch the server binary directly with an argv array; never via a shell -c string."))

    # 3) secrets in env
    env = srv.get("env") if isinstance(srv.get("env"), dict) else {}
    for k, v in env.items():
        val = str(v)
        if _ENV_SECRET.search(val) or (_SECRET_KEYNAME.search(str(k)) and len(val) >= 12
                                       and not val.startswith(("$", "${", "%"))):
            redacted = (val[:4] + "…") if len(val) > 5 else "…"
            out.append(Finding(
                "config.secret_in_env", "high",
                f"Server '{name}' hard-codes a secret in env '{k}' ({redacted}); "
                "config files sync to disk/cloud and leak.",
                f"{loc}.env.{k}",
                "Reference an OS env var (e.g. \"${MY_TOKEN}\") or a secret manager, not a literal."))

    # 4) remote server with no auth
    url = str(srv.get("url", "")).strip()
    ttype = str(srv.get("type", srv.get("transport", ""))).lower()
    if url.startswith(("http://", "https://")) or ttype in ("sse", "http", "streamable-http"):
        headers = srv.get("headers") if isinstance(srv.get("headers"), dict) else {}
        has_auth = any(h.lower() == "authorization" for h in headers) or bool(srv.get("auth"))
        if url.startswith("http://"):
            out.append(Finding(
                "config.cleartext_endpoint", "high",
                f"Server '{name}' uses a cleartext http:// endpoint — traffic and tokens are exposed.",
                f"{loc}.url", "Use https:// (or a localhost stdio server)."))
        if not has_auth:
            out.append(Finding(
                "config.remote_no_auth", "medium",
                f"Remote server '{name}' has no Authorization header / auth — anyone who can reach "
                "it can drive your agent.",
                loc, "Require an auth header/token on the remote MCP endpoint."))

    # 5) blanket auto-approve
    aa = srv.get("autoApprove") or srv.get("alwaysAllow") or srv.get("auto_approve")
    if aa is True or (isinstance(aa, list) and ("*" in aa or len(aa) > 8)):
        out.append(Finding(
            "config.auto_approve", "high",
            f"Server '{name}' auto-approves tool calls — no human review before tools run "
            "(poisoned tool descriptions execute silently).",
            loc, "Approve sensitive tools explicitly; avoid blanket auto-approve / alwaysAllow."))
    return out


def audit_config(doc: Dict[str, Any], source: str = "<config>") -> Report:
    """Audit a parsed MCP client config document."""
    servers = _iter_servers(doc)
    findings: List[Finding] = []
    if not servers:
        findings.append(Finding(
            "config.no_servers", "info",
            "No MCP servers found (expected an 'mcpServers' / 'servers' block).",
            source, "Point mcpharden at a Claude Desktop / Cursor / Cline / VS Code MCP config."))
    for name, srv in servers:
        findings.extend(_server_findings(name, srv))
    from .core import SEVERITY_ORDER
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.rule))
    return Report(source=source, server_name=f"{len(servers)} server(s)", findings=findings)


def audit_config_path(path: str) -> Report:
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    return audit_config(doc, source=path)


def default_config_paths() -> List[str]:
    """Best-effort common MCP client config locations for the current OS."""
    home = os.path.expanduser("~")
    appdata = os.environ.get("APPDATA", os.path.join(home, "AppData", "Roaming"))
    return [p for p in [
        os.path.join(appdata, "Claude", "claude_desktop_config.json"),
        os.path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
        os.path.join(home, ".config", "Claude", "claude_desktop_config.json"),
        os.path.join(home, ".cursor", "mcp.json"),
        os.path.join(home, ".codeium", "windsurf", "mcp_config.json"),
        os.path.join(home, ".vscode", "mcp.json"),
    ]]

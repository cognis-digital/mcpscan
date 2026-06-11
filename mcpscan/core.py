"""Core scanning engine for mcpscan.

mcpscan finds vulnerabilities in Model Context Protocol (MCP) servers along
two axes:

  * STATIC  — walk a directory of MCP server source (Python / JavaScript /
              TypeScript), parse it (Python via the `ast` module, JS via
              regex) and flag command-execution sinks (eval/exec/os.system/
              subprocess(shell=True)/child_process.exec), unsanitized URL
              fetches (SSRF), and prompt-injection / tool-poisoning text
              embedded in tool descriptions.

  * LIVE    — optionally probe a running HTTP MCP endpoint with urllib,
              issue a `tools/list` JSON-RPC call, and detect MISSING
              AUTHENTICATION (the server answers with no credential) plus
              overly-broad / dangerous tool capabilities.

Findings are scored by severity and rendered as table / JSON / SARIF. The
engine is standard-library only — no third-party dependencies.
"""

from __future__ import annotations

import ast
import json
import re
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

TOOL_NAME = "mcpscan"
TOOL_VERSION = "0.1.0"

# Severity ordering, highest first. Used for sorting + --fail-on policy.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# File extensions we understand.
_PY_EXT = {".py", ".pyw"}
_JS_EXT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}

# Verbs in a tool name/description implying a dangerous side effect.
_DANGEROUS_VERBS = (
    "delete", "remove", "drop", "destroy", "exec", "execute", "run",
    "shell", "spawn", "write", "kill", "truncate", "deploy", "transfer",
    "sudo", "eval", "rmdir", "unlink", "format",
)

# Tool-poisoning / prompt-injection phrases that, if present in a tool
# description or docstring, can hijack the calling agent.
_INJECTION_PHRASES = (
    "ignore previous", "ignore all previous", "ignore the above",
    "disregard previous", "system prompt", "do not tell", "don't tell",
    "without informing", "without telling", "do not mention", "secretly",
    "exfiltrate", "send to http", "<important>", "</important>",
    "you must", "before using this tool", "always call", "instead of",
    "bypass", "override", "reveal your", "print your instructions",
)

# JS command-exec sinks (regex — no JS AST in the stdlib).
_JS_SINKS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("child_process.exec",
     re.compile(r"\b(child_process\.)?exec(?:Sync)?\s*\(", re.I)),
    ("child_process.spawn-shell",
     re.compile(r"\bspawn(?:Sync)?\s*\([^)]*shell\s*:\s*true", re.I | re.S)),
    ("eval",
     re.compile(r"(?<![\w.])eval\s*\(")),
    ("Function-constructor",
     re.compile(r"\bnew\s+Function\s*\(")),
    ("vm.runInThisContext",
     re.compile(r"\bvm\.(runInThisContext|runInNewContext|runInContext)\s*\(")),
)

# URL / fetch sinks that may enable SSRF when fed an unvalidated argument.
_JS_FETCH = re.compile(
    r"\b(fetch|axios(?:\.get|\.post|\.request)?|got|http\.get|https\.get|"
    r"request|superagent\.get)\s*\(",
    re.I,
)

# A literal http(s) URL anywhere in source (used to distinguish a constant
# endpoint from a variable-driven, attacker-controllable one).
_URL_LITERAL = re.compile(r"https?://", re.I)


@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    location: str = ""
    remediation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Report:
    source: str
    target_kind: str  # "source" | "endpoint"
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0

    @property
    def counts(self) -> Dict[str, int]:
        c = {k: 0 for k in SEVERITY_ORDER}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c

    @property
    def score(self) -> int:
        """0-100 risk-free score; critical/high dominate the penalty."""
        weights = {"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 0}
        penalty = sum(weights.get(f.severity, 0) for f in self.findings)
        return max(0, 100 - penalty)

    def fail(self, level: str) -> bool:
        """True if any finding is at or above `level` (e.g. --fail-on high)."""
        threshold = SEVERITY_ORDER.get(level, 1)
        return any(SEVERITY_ORDER.get(f.severity, 99) <= threshold
                   for f in self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "source": self.source,
            "target_kind": self.target_kind,
            "files_scanned": self.files_scanned,
            "score": self.score,
            "counts": self.counts,
            "findings": [f.to_dict() for f in self.findings],
        }


class ScanError(ValueError):
    """Raised when a target cannot be read or probed."""


# ==========================================================================
# Static analysis — Python (ast)
# ==========================================================================

def _name_chain(node: ast.AST) -> str:
    """Return a dotted name for a Call func node, e.g. os.system, subprocess.run."""
    parts: List[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _shell_true(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "shell":
            v = kw.value
            if isinstance(v, ast.Constant) and v.value is True:
                return True
    return False


def _is_string_literal(node: Optional[ast.AST]) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _call_arg(call: ast.Call, idx: int) -> Optional[ast.AST]:
    return call.args[idx] if len(call.args) > idx else None


class _PyVisitor(ast.NodeVisitor):
    """Walks a Python AST collecting command-exec, SSRF, and poisoning findings."""

    SUBPROCESS_FUNCS = {"run", "call", "check_call", "check_output", "Popen"}
    # http client callables whose URL arg can be attacker-controlled (SSRF).
    FETCH_CALLS = {
        "requests.get", "requests.post", "requests.put", "requests.delete",
        "requests.head", "requests.patch", "requests.request",
        "urllib.request.urlopen", "request.urlopen", "urlopen",
        "httpx.get", "httpx.post", "httpx.request", "httpx.Client.get",
        "aiohttp.ClientSession.get", "session.get",
    }
    EXEC_NAMES = {"eval", "exec", "compile"}
    OS_EXEC = {"os.system", "os.popen", "os.execv", "os.execve",
               "os.spawnl", "os.spawnv"}

    def __init__(self, path: str, source: str) -> None:
        self.path = path
        self.source = source
        self.findings: List[Finding] = []
        # Track function args so we can tell "url built from a parameter"
        # (tainted → SSRF) from "url is a constant".
        self._param_names: set[str] = set()

    # -- helpers ---------------------------------------------------------
    def _loc(self, node: ast.AST) -> str:
        return f"{self.path}:{getattr(node, 'lineno', '?')}"

    def _add(self, rule: str, sev: str, msg: str, node: ast.AST, fix: str) -> None:
        self.findings.append(Finding(rule, sev, msg, self._loc(node), fix))

    def _arg_is_dynamic(self, node: Optional[ast.AST]) -> bool:
        """A string literal / constant is safe; anything else is 'dynamic'
        (built from variables, f-strings, concatenation, params)."""
        if node is None:
            return False
        if _is_string_literal(node):
            return False
        # f-strings, BinOp concatenation, Name, Call, .format() → dynamic
        return True

    # -- function defs: remember parameter names for taint heuristics ----
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        prev = set(self._param_names)
        for a in list(node.args.args) + list(node.args.kwonlyargs):
            self._param_names.add(a.arg)
        if node.args.vararg:
            self._param_names.add(node.args.vararg.arg)
        if node.args.kwarg:
            self._param_names.add(node.args.kwarg.arg)
        self._scan_tool_docstring(node)
        self.generic_visit(node)
        self._param_names = prev

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def _scan_tool_docstring(self, node: ast.AST) -> None:
        """Flag prompt-injection / tool-poisoning text in a function docstring
        or in a description=... decorator kwarg (FastMCP / mcp.tool style)."""
        doc = ast.get_docstring(node) or ""
        text = doc.lower()
        if _has_injection(text):
            self._add(
                "static.tool_poisoning", "critical",
                "Tool docstring/description contains prompt-injection / "
                "tool-poisoning text that can hijack the calling agent.",
                node,
                "Remove imperative/meta instructions and hidden directives "
                "from tool descriptions.",
            )

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        chain = _name_chain(node.func)
        bare = chain.split(".")[-1]

        # --- command execution sinks ---
        if chain in self.OS_EXEC:
            sev = "critical" if self._arg_is_dynamic(_call_arg(node, 0)) else "high"
            self._add(
                "static.command_exec", sev,
                f"Call to {chain}() executes a shell/OS command"
                + (" built from a dynamic value (RCE)." if sev == "critical"
                   else " (review the command source)."),
                node,
                "Avoid os.system/popen; use subprocess with a list argv and "
                "shell=False, and never interpolate untrusted input.",
            )
        elif bare in self.EXEC_NAMES and isinstance(node.func, ast.Name):
            sev = "critical" if self._arg_is_dynamic(_call_arg(node, 0)) else "high"
            self._add(
                "static.dynamic_eval", sev,
                f"Use of {bare}() evaluates code at runtime"
                + (" from a dynamic value (RCE)." if sev == "critical" else "."),
                node,
                "Never eval/exec untrusted input; parse with ast.literal_eval "
                "or a real parser instead.",
            )
        elif bare in self.SUBPROCESS_FUNCS and (
                "subprocess" in chain or bare == "Popen"):
            if _shell_true(node):
                dyn = self._arg_is_dynamic(_call_arg(node, 0))
                self._add(
                    "static.subprocess_shell", "critical" if dyn else "high",
                    "subprocess call with shell=True"
                    + (" and a dynamic command string enables command "
                       "injection / RCE." if dyn
                       else " — shell parsing is risky."),
                    node,
                    "Pass an argv list and use shell=False; if a shell is "
                    "truly required, hard-code the command and quote args.",
                )

        # --- SSRF: outbound fetch with a non-literal URL ---
        if chain in self.FETCH_CALLS or (
                bare in {"get", "post", "urlopen", "request"} and
                ("requests" in chain or "urllib" in chain or "httpx" in chain)):
            url_arg = _call_arg(node, 0)
            if self._arg_is_dynamic(url_arg):
                self._add(
                    "static.ssrf", "high",
                    f"Outbound HTTP via {chain}() uses a dynamically-built "
                    "URL; an attacker-controlled host can pivot to internal "
                    "services (SSRF).",
                    node,
                    "Validate the URL against an allowlist of schemes/hosts "
                    "and block private/link-local/metadata IP ranges before "
                    "fetching.",
                )

        # --- tool description kwarg poisoning (decorator/registration) ---
        for kw in node.keywords:
            if kw.arg in ("description", "desc") and _is_string_literal(kw.value):
                if _has_injection(str(kw.value.value).lower()):
                    self._add(
                        "static.tool_poisoning", "critical",
                        "Tool registration description= contains "
                        "prompt-injection / tool-poisoning text.",
                        node,
                        "Strip hidden instructions from tool descriptions.",
                    )

        self.generic_visit(node)


def _has_injection(text: str) -> bool:
    return any(p in text for p in _INJECTION_PHRASES)


def scan_python_source(path: str, source: str) -> List[Finding]:
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        return [Finding(
            "static.parse_error", "info",
            f"Could not parse Python file: {exc}", f"{path}:{exc.lineno or '?'}",
            "Ensure the file is valid Python; mcpscan fell back to regex.",
        )] + _scan_text_fallback(path, source)
    v = _PyVisitor(path, source)
    v.visit(tree)
    return v.findings


def _scan_text_fallback(path: str, source: str) -> List[Finding]:
    """Regex sweep used for JS/TS and unparseable Python."""
    out: List[Finding] = []
    lines = source.splitlines()

    for lineno, line in enumerate(lines, start=1):
        loc = f"{path}:{lineno}"
        for rule, pat in _JS_SINKS:
            if pat.search(line):
                # exec/eval on a literal-only line is lower risk.
                dynamic = not _line_is_literal_only(line)
                sev = "critical" if dynamic else "high"
                out.append(Finding(
                    "static.command_exec", sev,
                    f"Command-execution sink ({rule}) detected"
                    + (" with dynamic input (RCE)." if dynamic else "."),
                    loc,
                    "Avoid exec/eval/Function; if spawning a process use an "
                    "argv array with shell disabled and validated arguments.",
                ))
        if _JS_FETCH.search(line) and not _URL_LITERAL.search(line):
            # fetch(varUrl) with no literal URL on the line → likely tainted.
            out.append(Finding(
                "static.ssrf", "high",
                "Outbound HTTP fetch with a non-literal URL argument may "
                "allow SSRF to internal services.",
                loc,
                "Validate/allowlist the target host and block private and "
                "cloud-metadata IP ranges before fetching.",
            ))

    # Tool-poisoning text in JS string descriptions (whole-file sweep).
    for m in re.finditer(r"description\s*[:=]\s*([\"'`])(.*?)\1",
                         source, re.S | re.I):
        desc = m.group(2).lower()
        if _has_injection(desc):
            lineno = source[:m.start()].count("\n") + 1
            out.append(Finding(
                "static.tool_poisoning", "critical",
                "Tool description string contains prompt-injection / "
                "tool-poisoning text that can hijack the calling agent.",
                f"{path}:{lineno}",
                "Remove hidden/meta instructions from tool descriptions.",
            ))
    return out


def _line_is_literal_only(line: str) -> bool:
    """Heuristic: the only argument is a quoted literal (lower RCE risk)."""
    # e.g. eval("2 + 2")  → literal-only ; eval(userInput) → dynamic
    m = re.search(r"\(\s*([\"'`]).*?\1\s*\)\s*;?\s*$", line)
    return bool(m)


def scan_js_source(path: str, source: str) -> List[Finding]:
    return _scan_text_fallback(path, source)


# ==========================================================================
# Static analysis — directory walk
# ==========================================================================

def scan_path(target: str) -> Report:
    """Statically scan a file or directory of MCP server source."""
    p = Path(target)
    if not p.exists():
        raise ScanError(f"no such path: {target}")

    files: List[Path]
    if p.is_file():
        files = [p]
    else:
        files = sorted(
            f for f in p.rglob("*")
            if f.is_file() and (f.suffix in _PY_EXT or f.suffix in _JS_EXT)
            and "node_modules" not in f.parts and ".git" not in f.parts
        )

    report = Report(source=str(target), target_kind="source")
    for f in files:
        try:
            src = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        report.files_scanned += 1
        rel = str(f)
        if f.suffix in _PY_EXT:
            report.findings.extend(scan_python_source(rel, src))
        else:
            report.findings.extend(scan_js_source(rel, src))

    if report.files_scanned == 0:
        report.findings.append(Finding(
            "static.no_source", "info",
            "No Python/JavaScript source files found at the target.",
            str(target),
            "Point mcpscan at the MCP server's source directory.",
        ))
    _finalize(report)
    return report


# ==========================================================================
# Live probe — HTTP MCP endpoint (urllib)
# ==========================================================================

def _jsonrpc(url: str, method: str, headers: Optional[Dict[str, str]] = None,
             timeout: float = 6.0) -> Tuple[int, Any]:
    """POST a JSON-RPC request and return (status, parsed-body-or-text)."""
    payload = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": method, "params": {},
    }).encode("utf-8")
    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json, text/event-stream")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            status = resp.getcode()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
        status = exc.code
    try:
        return status, json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return status, body


def probe_endpoint(url: str, token: Optional[str] = None,
                   timeout: float = 6.0) -> Report:
    """Probe a live HTTP MCP endpoint for missing auth + broad capabilities."""
    report = Report(source=url, target_kind="endpoint")

    if not re.match(r"^https?://", url, re.I):
        raise ScanError("endpoint must be an http(s):// URL")

    # 1) Unauthenticated tools/list — the key MISSING-AUTH test. We always
    #    probe WITHOUT a credential first; a 2xx here means missing auth even
    #    if the operator supplied a token.
    try:
        # `anon_status` reflects the credential-free probe and is what the
        # missing-auth verdict is based on, regardless of any token re-probe.
        anon_status, body = _jsonrpc(url, "tools/list", headers=None,
                                     timeout=timeout)
        status = anon_status
        if anon_status in (401, 403) and token:
            # Re-probe authenticated so we can still enumerate the surface,
            # but keep `anon_status` for the auth verdict.
            status, body = _jsonrpc(
                url, "tools/list",
                headers={"Authorization": f"Bearer {token}"}, timeout=timeout)
    except (urllib.error.URLError, socket.timeout, OSError) as exc:
        raise ScanError(f"could not reach endpoint: {exc}") from exc

    tools = _extract_tools(body)
    auth_required = anon_status in (401, 403)
    exposed_no_auth = (not auth_required and anon_status < 400
                       and tools is not None)

    if exposed_no_auth:
        report.findings.append(Finding(
            "live.no_auth", "critical",
            "Endpoint answered tools/list with NO authentication "
            f"(HTTP {anon_status}); any client that reaches the port can "
            "enumerate and invoke tools.",
            url,
            "Require a bearer token / OAuth and reject unauthenticated "
            "tools/list and tools/call requests.",
        ))
    elif auth_required:
        report.findings.append(Finding(
            "live.auth_enforced", "info",
            f"Endpoint requires authentication (HTTP {anon_status}) for "
            "tools/list — good.",
            url, "",
        ))
    elif anon_status >= 500:
        report.findings.append(Finding(
            "live.server_error", "low",
            f"Endpoint returned HTTP {anon_status} on tools/list.",
            url, "Check server logs; mcpscan could not enumerate tools.",
        ))

    # 2) Cleartext transport.
    if url.lower().startswith("http://"):
        report.findings.append(Finding(
            "live.no_tls", "high",
            "MCP endpoint served over plain HTTP; tokens and tool traffic "
            "travel in cleartext.",
            url,
            "Serve over HTTPS / terminate TLS at an authenticating proxy.",
        ))

    # 3) Capability surface (if we got a tools list).
    if tools:
        report.findings.append(Finding(
            "live.tools_enumerated", "info",
            f"Enumerated {len(tools)} tool(s) from the live endpoint.",
            url, "",
        ))
        for t in tools:
            report.findings.extend(
                _assess_live_tool(t, url, exposed=exposed_no_auth))

    _finalize(report)
    return report


def _extract_tools(body: Any) -> Optional[List[Dict[str, Any]]]:
    if not isinstance(body, dict):
        return None
    result = body.get("result")
    if isinstance(result, dict) and isinstance(result.get("tools"), list):
        return result["tools"]
    if isinstance(body.get("tools"), list):
        return body["tools"]
    return None


def _assess_live_tool(tool: Dict[str, Any], url: str,
                      exposed: bool) -> List[Finding]:
    out: List[Finding] = []
    if not isinstance(tool, dict):
        return out
    name = str(tool.get("name", "")).strip() or "<unnamed>"
    desc = str(tool.get("description", "")).strip()
    haystack = (name + " " + desc).lower()
    loc = f"{url} :: {name}"

    if _has_injection(desc.lower()):
        out.append(Finding(
            "live.tool_poisoning", "critical",
            f"Tool '{name}' description contains prompt-injection / "
            "tool-poisoning text.",
            loc, "Audit and sanitize tool descriptions on the server.",
        ))

    dangerous = any(v in haystack for v in _DANGEROUS_VERBS)
    if dangerous:
        sev = "critical" if exposed else "high"
        out.append(Finding(
            "live.dangerous_capability", sev,
            f"Tool '{name}' exposes a destructive/side-effecting capability"
            + (" and is reachable WITHOUT auth." if exposed
               else " — confirm it is access-controlled."),
            loc,
            "Gate side-effecting tools behind auth + per-tool authorization "
            "and require explicit confirmation.",
        ))

    schema = tool.get("inputSchema") or tool.get("input_schema")
    if dangerous and not schema:
        out.append(Finding(
            "live.unconstrained_tool", "high",
            f"Side-effecting tool '{name}' advertises no inputSchema; its "
            "arguments are unvalidated.",
            loc, "Publish a strict JSON Schema (types, enums, required).",
        ))
    elif isinstance(schema, dict) and schema.get("additionalProperties") is True:
        out.append(Finding(
            "live.open_schema", "medium",
            f"Tool '{name}' inputSchema sets additionalProperties=true.",
            loc, "Set additionalProperties=false to reject unknown args.",
        ))
    return out


# ==========================================================================
# Unified entry point + finalization
# ==========================================================================

def _finalize(report: Report) -> None:
    report.findings.sort(
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.rule, f.location))


def scan(target: str, endpoint: Optional[str] = None,
         token: Optional[str] = None, **_: Any) -> Report:
    """Public API used by the CLI and the MCP server.

    If `target` looks like an http(s) URL (or `endpoint` is given), probe the
    live endpoint; otherwise statically scan the path.
    """
    live = endpoint or (target if re.match(r"^https?://", target or "", re.I)
                        else None)
    if live:
        return probe_endpoint(live, token=token)
    return scan_path(target)


# ==========================================================================
# Exporters
# ==========================================================================

def to_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2)


def to_sarif(report: Report) -> str:
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    sarif_level = {"critical": "error", "high": "error", "medium": "warning",
                   "low": "note", "info": "note"}
    for f in report.findings:
        rules.setdefault(f.rule, {
            "id": f.rule,
            "name": f.rule,
            "shortDescription": {"text": f.rule},
            "properties": {"security-severity": _sec_sev(f.severity)},
        })
        loc_path, line = _split_loc(f.location)
        results.append({
            "ruleId": f.rule,
            "level": sarif_level.get(f.severity, "note"),
            "message": {"text": f.message + (
                f" Remediation: {f.remediation}" if f.remediation else "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": loc_path or report.source},
                    "region": {"startLine": line} if line else {},
                }
            }],
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "informationUri": "https://github.com/cognis-digital/mcpscan",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)


def _sec_sev(severity: str) -> str:
    return {"critical": "9.5", "high": "8.0", "medium": "5.0",
            "low": "3.0", "info": "0.0"}.get(severity, "0.0")


def _split_loc(loc: str) -> Tuple[str, Optional[int]]:
    if not loc:
        return "", None
    m = re.match(r"^(.*):(\d+)$", loc)
    if m:
        return m.group(1), int(m.group(2))
    return loc, None

"""Core scanning engine for mcpscan.

mcpscan finds vulnerabilities in Model Context Protocol (MCP) servers and the
agents that drive them along several axes:

  * STATIC  — walk a directory of MCP server source (Python / JavaScript /
              TypeScript), parse it (Python via the `ast` module, JS via
              regex) and flag a deep rule pack covering the OWASP LLM Top-10
              and the full MCP/agent threat surface: command-execution sinks
              (RCE), SSRF, path traversal, insecure deserialization, SSTI,
              hard-coded secrets, tool poisoning, confused-deputy / token
              passthrough, rug-pull / version drift, excessive agency, and
              insecure output handling. Python additionally gets real
              source->sink TAINT analysis (dataflow), not just signatures.

  * LIVE    — optionally probe a running HTTP MCP endpoint with urllib,
              issue a `tools/list` JSON-RPC call, and detect MISSING
              AUTHENTICATION plus overly-broad / dangerous tool capabilities.

  * REMOTE  — fetch a public GitHub / raw URL of an MCP server file over
              urllib and scan its contents (`scan-url`).

  * AI      — OPT-IN, OFF BY DEFAULT. When `--ai` is given and a Cognis fleet
              backend is configured + reachable, an LLM reviews the same source
              for NOVEL logic flaws; findings are merged in tagged source="ai".
              With `--ai` absent the tool is byte-for-byte deterministic.

Every native rule is mapped to a CWE id and to the Microsoft AI agent threat
taxonomy. Findings are scored by severity and rendered as table / JSON / SARIF
/ HTML / badge. The engine is standard-library only — no third-party deps.
"""

from __future__ import annotations

import ast
import json
import re
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from html import escape as _html_escape
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

TOOL_NAME = "mcpscan"
TOOL_VERSION = "0.3.0"

# Severity ordering, highest first. Used for sorting + --fail-on policy.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# File extensions we understand.
_PY_EXT = {".py", ".pyw"}
_JS_EXT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}

# ==========================================================================
# Rule metadata — CWE + OWASP-LLM Top-10 + Microsoft agent-threat taxonomy.
#
# OWASP LLM Top-10 (2025): LLM01 Prompt Injection, LLM02 Sensitive Info
# Disclosure, LLM05 Improper Output Handling, LLM06 Excessive Agency,
# LLM08 Vector/Embedding Weaknesses, LLM10 Unbounded Consumption, etc.
#
# Microsoft "Taxonomy of Failure Modes in Agentic AI Systems" buckets used
# below: agent-tool-poisoning, agent-confused-deputy, agent-excessive-agency,
# agent-knowledge-poisoning, agent-impersonation, memory-poisoning.
# ==========================================================================

RULE_META: Dict[str, Dict[str, str]] = {
    "static.command_exec": {
        "cwe": "CWE-78", "owasp_llm": "LLM06",
        "ms_taxonomy": "agent-excessive-agency",
        "title": "OS command execution"},
    "static.dynamic_eval": {
        "cwe": "CWE-95", "owasp_llm": "LLM06",
        "ms_taxonomy": "agent-excessive-agency",
        "title": "Dynamic code evaluation (eval/exec)"},
    "static.subprocess_shell": {
        "cwe": "CWE-78", "owasp_llm": "LLM06",
        "ms_taxonomy": "agent-excessive-agency",
        "title": "Subprocess with shell=True"},
    "static.ssrf": {
        "cwe": "CWE-918", "owasp_llm": "LLM06",
        "ms_taxonomy": "agent-confused-deputy",
        "title": "Server-side request forgery"},
    "static.path_traversal": {
        "cwe": "CWE-22", "owasp_llm": "LLM06",
        "ms_taxonomy": "agent-excessive-agency",
        "title": "Path traversal / arbitrary file access"},
    "static.deserialization": {
        "cwe": "CWE-502", "owasp_llm": "LLM05",
        "ms_taxonomy": "agent-excessive-agency",
        "title": "Insecure deserialization"},
    "static.ssti": {
        "cwe": "CWE-1336", "owasp_llm": "LLM05",
        "ms_taxonomy": "agent-excessive-agency",
        "title": "Server-side template injection"},
    "static.secret_exposure": {
        "cwe": "CWE-798", "owasp_llm": "LLM02",
        "ms_taxonomy": "agent-knowledge-poisoning",
        "title": "Hard-coded secret / credential"},
    "static.tool_poisoning": {
        "cwe": "CWE-94", "owasp_llm": "LLM01",
        "ms_taxonomy": "agent-tool-poisoning",
        "title": "Tool-description poisoning / prompt injection"},
    "static.confused_deputy": {
        "cwe": "CWE-441", "owasp_llm": "LLM06",
        "ms_taxonomy": "agent-confused-deputy",
        "title": "Confused-deputy: ambient credential forwarded outbound"},
    "static.token_passthrough": {
        "cwe": "CWE-522", "owasp_llm": "LLM02",
        "ms_taxonomy": "agent-impersonation",
        "title": "Token passthrough (upstream token relayed downstream)"},
    "static.excessive_agency": {
        "cwe": "CWE-250", "owasp_llm": "LLM06",
        "ms_taxonomy": "agent-excessive-agency",
        "title": "Excessive agency: unconfirmed destructive tool"},
    "static.insecure_output": {
        "cwe": "CWE-79", "owasp_llm": "LLM05",
        "ms_taxonomy": "agent-knowledge-poisoning",
        "title": "Insecure handling of LLM/tool output"},
    # --- v0.3 deep rules: MCP config hygiene + shell-tool taint ---
    "config.hardcoded_secret": {
        "cwe": "CWE-798", "owasp_llm": "LLM02",
        "ms_taxonomy": "agent-knowledge-poisoning",
        "title": "Hard-coded bearer/secret in MCP config"},
    "config.open_bind_no_auth": {
        "cwe": "CWE-306", "owasp_llm": "LLM06",
        "ms_taxonomy": "agent-impersonation",
        "title": "Server bound to 0.0.0.0 with no authentication"},
    "config.no_tls_remote": {
        "cwe": "CWE-319", "owasp_llm": "LLM02",
        "ms_taxonomy": "agent-impersonation",
        "title": "Remote MCP transport without TLS (cleartext http://)"},
    "static.shell_tool_input": {
        "cwe": "CWE-78", "owasp_llm": "LLM06",
        "ms_taxonomy": "agent-excessive-agency",
        "title": "Shell tool passes user input to a subprocess"},
    "static.parse_error": {
        "cwe": "", "owasp_llm": "", "ms_taxonomy": "",
        "title": "Parser error (fell back to regex)"},
    "static.no_source": {
        "cwe": "", "owasp_llm": "", "ms_taxonomy": "",
        "title": "No source found"},
    # taint dataflow specializations (inherit the sink CWE)
    "taint.command_injection": {
        "cwe": "CWE-78", "owasp_llm": "LLM06",
        "ms_taxonomy": "agent-excessive-agency",
        "title": "Tainted dataflow → command injection"},
    "taint.code_injection": {
        "cwe": "CWE-95", "owasp_llm": "LLM06",
        "ms_taxonomy": "agent-excessive-agency",
        "title": "Tainted dataflow → code injection"},
    "taint.ssrf": {
        "cwe": "CWE-918", "owasp_llm": "LLM06",
        "ms_taxonomy": "agent-confused-deputy",
        "title": "Tainted dataflow → SSRF"},
    "taint.path_traversal": {
        "cwe": "CWE-22", "owasp_llm": "LLM06",
        "ms_taxonomy": "agent-excessive-agency",
        "title": "Tainted dataflow → path traversal"},
    "taint.deserialization": {
        "cwe": "CWE-502", "owasp_llm": "LLM05",
        "ms_taxonomy": "agent-excessive-agency",
        "title": "Tainted dataflow → insecure deserialization"},
    # live rules
    "live.no_auth": {
        "cwe": "CWE-306", "owasp_llm": "LLM06",
        "ms_taxonomy": "agent-impersonation",
        "title": "Missing authentication on MCP endpoint"},
    "live.no_tls": {
        "cwe": "CWE-319", "owasp_llm": "LLM02",
        "ms_taxonomy": "agent-impersonation",
        "title": "Cleartext transport"},
    "live.dangerous_capability": {
        "cwe": "CWE-250", "owasp_llm": "LLM06",
        "ms_taxonomy": "agent-excessive-agency",
        "title": "Destructive capability exposed"},
    "live.unconstrained_tool": {
        "cwe": "CWE-20", "owasp_llm": "LLM06",
        "ms_taxonomy": "agent-excessive-agency",
        "title": "Tool with no input schema"},
    "live.open_schema": {
        "cwe": "CWE-20", "owasp_llm": "LLM06",
        "ms_taxonomy": "agent-excessive-agency",
        "title": "Open input schema (additionalProperties=true)"},
    "live.tool_poisoning": {
        "cwe": "CWE-94", "owasp_llm": "LLM01",
        "ms_taxonomy": "agent-tool-poisoning",
        "title": "Tool-description poisoning (live)"},
    "live.auth_enforced": {"cwe": "", "owasp_llm": "", "ms_taxonomy": "",
                           "title": "Auth enforced"},
    "live.tools_enumerated": {"cwe": "", "owasp_llm": "", "ms_taxonomy": "",
                              "title": "Tools enumerated"},
    "live.server_error": {"cwe": "", "owasp_llm": "", "ms_taxonomy": "",
                          "title": "Server error"},
    # AI (LLM-discovered)
    "ai.finding": {
        "cwe": "", "owasp_llm": "LLM01",
        "ms_taxonomy": "agent-novel-logic-flaw",
        "title": "AI-discovered finding"},
}


def _meta(rule: str) -> Dict[str, str]:
    return RULE_META.get(rule, {"cwe": "", "owasp_llm": "", "ms_taxonomy": "",
                                "title": rule})


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

# Hard-coded secrets — high-signal patterns, language-agnostic regex.
_SECRET_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("OpenAI/Anthropic key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Generic assigned secret",
     re.compile(r"(?i)\b(api[_-]?key|secret|passwd|password|token|access[_-]?key)\b"
                r"\s*[:=]\s*[\"'][A-Za-z0-9/+_=-]{12,}[\"']")),
)

# JS template-render sinks that enable SSTI on a non-literal template.
_JS_SSTI = re.compile(
    r"\b(handlebars\.compile|ejs\.render|pug\.(?:render|compile)|"
    r"_\.template|nunjucks\.renderString|Vue\.compile)\s*\(",
    re.I,
)

# JS path/file sinks (path traversal).
_JS_FS = re.compile(
    r"\bfs\.(?:read|write|append|unlink|create)[A-Za-z]*\s*\(",
    re.I,
)


@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    location: str = ""
    remediation: str = ""
    source: str = "rule"          # "rule" | "ai"
    cwe: str = ""
    owasp_llm: str = ""
    ms_taxonomy: str = ""
    novel: bool = False
    confidence: float = 1.0

    def __post_init__(self) -> None:
        # Auto-populate CWE / OWASP / MS-taxonomy from the rule registry when
        # the caller did not set them explicitly.
        m = _meta(self.rule)
        if not self.cwe:
            self.cwe = m.get("cwe", "")
        if not self.owasp_llm:
            self.owasp_llm = m.get("owasp_llm", "")
        if not self.ms_taxonomy:
            self.ms_taxonomy = m.get("ms_taxonomy", "")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Report:
    source: str
    target_kind: str  # "source" | "endpoint" | "url"
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    ai_used: bool = False
    ai_note: str = ""

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
        d = {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "source": self.source,
            "target_kind": self.target_kind,
            "files_scanned": self.files_scanned,
            "score": self.score,
            "counts": self.counts,
            "ai_used": self.ai_used,
            "findings": [f.to_dict() for f in self.findings],
        }
        if self.ai_note:
            d["ai_note"] = self.ai_note
        return d


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
    """Walks a Python AST collecting signature-based findings across the deep
    rule pack (command exec, SSRF, path traversal, deserialization, SSTI,
    secrets, tool poisoning, confused-deputy / token passthrough)."""

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
    # insecure deserialization sinks.
    DESER_CALLS = {"pickle.load", "pickle.loads", "cPickle.load",
                   "cPickle.loads", "yaml.load", "yaml.unsafe_load",
                   "marshal.loads", "marshal.load", "dill.load", "dill.loads",
                   "shelve.open", "jsonpickle.decode"}
    # path / file sinks for traversal.
    FILE_CALLS = {"open", "os.remove", "os.unlink", "os.rmdir", "os.mkdir",
                  "os.makedirs", "shutil.rmtree", "shutil.copy", "shutil.move",
                  "pathlib.Path", "Path", "send_file", "send_from_directory"}
    # template-render sinks for SSTI.
    SSTI_CALLS = {"Template", "jinja2.Template", "render_template_string",
                  "Environment.from_string", "from_string"}

    def __init__(self, path: str, source: str) -> None:
        self.path = path
        self.source = source
        self.findings: List[Finding] = []
        self._param_names: set[str] = set()

    # -- helpers ---------------------------------------------------------
    def _loc(self, node: ast.AST) -> str:
        return f"{self.path}:{getattr(node, 'lineno', '?')}"

    def _add(self, rule: str, sev: str, msg: str, node: ast.AST,
             fix: str) -> None:
        self.findings.append(
            Finding(rule, sev, msg, self._loc(node), fix))

    def _arg_is_dynamic(self, node: Optional[ast.AST]) -> bool:
        if node is None:
            return False
        if _is_string_literal(node):
            return False
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
        is_fetch = chain in self.FETCH_CALLS or (
            bare in {"get", "post", "urlopen", "request"} and
            ("requests" in chain or "urllib" in chain or "httpx" in chain))
        if is_fetch:
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
            # --- confused deputy / token passthrough: forwarding an ambient
            #     Authorization header / token to an outbound request. ---
            self._check_confused_deputy(node, chain)

        # --- insecure deserialization ---
        if chain in self.DESER_CALLS or bare in {
                "load", "loads"} and ("pickle" in chain or "marshal" in chain
                                      or "dill" in chain):
            # yaml.load is unsafe only without SafeLoader.
            if "yaml" in chain and self._has_safe_loader(node):
                pass
            else:
                self._add(
                    "static.deserialization", "high",
                    f"Insecure deserialization via {chain}() can execute "
                    "arbitrary code when fed attacker-controlled bytes.",
                    node,
                    "Use json / ast.literal_eval, or yaml.safe_load; never "
                    "unpickle untrusted data.",
                )

        # --- server-side template injection ---
        if bare in self.SSTI_CALLS or chain in {"render_template_string"}:
            arg = _call_arg(node, 0)
            if self._arg_is_dynamic(arg):
                self._add(
                    "static.ssti", "high",
                    f"Template built from a dynamic value via {chain}() "
                    "enables server-side template injection (SSTI → RCE).",
                    node,
                    "Render fixed templates with data passed as context; "
                    "never compile a template from user input.",
                )

        # --- path traversal: file sink fed a dynamic path ---
        if chain in self.FILE_CALLS or (
                bare == "open" and isinstance(node.func, ast.Name)):
            path_arg = _call_arg(node, 0)
            if self._arg_is_dynamic(path_arg) and not is_fetch:
                self._add(
                    "static.path_traversal", "medium",
                    f"File operation {chain}() uses a dynamically-built path; "
                    "unvalidated '..' segments allow arbitrary file access.",
                    node,
                    "Resolve the path and confirm it stays within an allowed "
                    "base directory (os.path.realpath + commonpath check).",
                )

        # --- tool description kwarg poisoning + excessive agency hints ---
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

    def _has_safe_loader(self, call: ast.Call) -> bool:
        """True if a yaml.load call passes a *Safe* Loader (then it's safe)."""
        for kw in call.keywords:
            if kw.arg == "Loader":
                return "Safe" in _name_chain(kw.value)
        for a in call.args[1:]:
            if "Safe" in _name_chain(a):
                return True
        return False

    def _check_confused_deputy(self, node: ast.Call, chain: str) -> None:
        """Flag outbound requests that forward an ambient Authorization
        header / inbound token to a different (downstream) service — the
        classic MCP confused-deputy / token-passthrough anti-pattern."""
        for kw in node.keywords:
            if kw.arg == "headers":
                txt = ast.dump(kw.value)
                if "Authorization" in txt or "authorization" in txt:
                    self._add(
                        "static.confused_deputy", "high",
                        f"Outbound {chain}() forwards an Authorization header; "
                        "relaying an inbound credential to a downstream service "
                        "is a confused-deputy / token-passthrough risk.",
                        node,
                        "Mint a fresh, audience-scoped token for the downstream "
                        "call; never pass the caller's token through.",
                    )
            if kw.arg in ("token", "auth", "access_token", "bearer"):
                if isinstance(kw.value, ast.Name) and kw.value.id in self._param_names:
                    self._add(
                        "static.token_passthrough", "high",
                        f"Inbound parameter '{kw.value.id}' is passed as the "
                        f"credential to outbound {chain}() — token passthrough.",
                        node,
                        "Exchange the inbound token for a scoped downstream "
                        "credential instead of relaying it.",
                    )


def _has_injection(text: str) -> bool:
    return any(p in text for p in _INJECTION_PHRASES)


# ==========================================================================
# Real AST taint analysis (Python): source -> sink dataflow
# ==========================================================================

# Functions / attributes that introduce attacker-controlled (tainted) data.
_TAINT_SOURCE_CALLS = {
    "input", "request.args.get", "request.form.get", "request.json",
    "request.get_json", "request.values.get", "request.data",
    "os.environ.get", "sys.argv", "flask.request",
}
_TAINT_SOURCE_ATTRS = {
    "args", "form", "json", "values", "data", "params", "query",
}

# sink callable -> (rule, severity)
_TAINT_SINKS: Dict[str, Tuple[str, str]] = {
    "os.system": ("taint.command_injection", "critical"),
    "os.popen": ("taint.command_injection", "critical"),
    "subprocess.run": ("taint.command_injection", "critical"),
    "subprocess.call": ("taint.command_injection", "critical"),
    "subprocess.Popen": ("taint.command_injection", "critical"),
    "subprocess.check_output": ("taint.command_injection", "critical"),
    "eval": ("taint.code_injection", "critical"),
    "exec": ("taint.code_injection", "critical"),
    "pickle.loads": ("taint.deserialization", "critical"),
    "pickle.load": ("taint.deserialization", "critical"),
    "yaml.load": ("taint.deserialization", "high"),
    "open": ("taint.path_traversal", "high"),
    "requests.get": ("taint.ssrf", "high"),
    "requests.post": ("taint.ssrf", "high"),
    "urllib.request.urlopen": ("taint.ssrf", "high"),
    "urlopen": ("taint.ssrf", "high"),
}


class _TaintVisitor(ast.NodeVisitor):
    """Per-function intraprocedural taint tracking.

    A variable becomes tainted when assigned from:
      * a function parameter (MCP tool args are attacker-controlled),
      * a known taint source call (input(), request.*.get(), os.environ...),
      * an expression that *uses* an already-tainted variable (propagation
        through f-strings, concatenation, .format(), str(), slicing, etc.).

    A finding is raised when a tainted value reaches a dangerous sink. This is
    real dataflow (not a line regex): `x = request.args.get('c'); cmd = 'ls '
    + x; os.system(cmd)` is caught even though no sink and source share a line.
    """

    def __init__(self, path: str, source: str) -> None:
        self.path = path
        self.source = source
        self.findings: List[Finding] = []

    def _loc(self, node: ast.AST) -> str:
        return f"{self.path}:{getattr(node, 'lineno', '?')}"

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        tainted: set[str] = set()
        for a in list(node.args.args) + list(node.args.kwonlyargs):
            if a.arg not in ("self", "cls"):
                tainted.add(a.arg)
        if node.args.vararg:
            tainted.add(node.args.vararg.arg)
        if node.args.kwarg:
            tainted.add(node.args.kwarg.arg)
        self._walk_body(node.body, tainted)
        # do NOT generic_visit into nested funcs here; handle them recursively
        for child in node.body:
            for n in ast.walk(child):
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n is not node:
                    pass  # nested defs are visited by the outer NodeVisitor walk

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    # ---- taint propagation ------------------------------------------------
    def _expr_is_tainted(self, node: Optional[ast.AST], tainted: set[str]) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Name):
            return node.id in tainted
        if isinstance(node, ast.Constant):
            return False
        if isinstance(node, ast.Call):
            chain = _name_chain(node.func)
            bare = chain.split(".")[-1]
            if chain in _TAINT_SOURCE_CALLS or bare == "input":
                return True
            # request.args.get(...) etc.
            if any(s in chain for s in ("request.", ".args", ".form",
                                        ".json", ".values")):
                return True
            # str(taint), bytes(taint), .format(taint) → propagate from args
            return any(self._expr_is_tainted(a, tainted) for a in node.args) \
                or any(self._expr_is_tainted(kw.value, tainted)
                       for kw in node.keywords)
        if isinstance(node, ast.Attribute):
            # request.args / obj.data style sources
            if node.attr in _TAINT_SOURCE_ATTRS:
                base = _name_chain(node)
                if "request" in base or "argv" in base:
                    return True
            return self._expr_is_tainted(node.value, tainted)
        if isinstance(node, ast.Subscript):
            return self._expr_is_tainted(node.value, tainted)
        if isinstance(node, (ast.BinOp,)):
            return self._expr_is_tainted(node.left, tainted) or \
                self._expr_is_tainted(node.right, tainted)
        if isinstance(node, ast.JoinedStr):  # f-string
            return any(self._expr_is_tainted(v.value, tainted)
                       for v in node.values
                       if isinstance(v, ast.FormattedValue))
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self._expr_is_tainted(e, tainted) for e in node.elts)
        if isinstance(node, ast.BoolOp):
            return any(self._expr_is_tainted(v, tainted) for v in node.values)
        if isinstance(node, ast.IfExp):
            return self._expr_is_tainted(node.body, tainted) or \
                self._expr_is_tainted(node.orelse, tainted)
        return False

    def _assign_targets(self, target: ast.AST) -> List[str]:
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, (ast.Tuple, ast.List)):
            out: List[str] = []
            for e in target.elts:
                out.extend(self._assign_targets(e))
            return out
        return []

    def _walk_body(self, body: List[ast.stmt], tainted: set[str]) -> None:
        for stmt in body:
            self._exec_stmt(stmt, tainted)

    def _exec_stmt(self, stmt: ast.stmt, tainted: set[str]) -> None:
        # 1) propagate taint through assignments
        if isinstance(stmt, ast.Assign):
            t = self._expr_is_tainted(stmt.value, tainted)
            for tgt in stmt.targets:
                for name in self._assign_targets(tgt):
                    if t:
                        tainted.add(name)
                    else:
                        tainted.discard(name)
        elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
            tgt = stmt.target
            val = stmt.value
            if isinstance(tgt, ast.Name) and val is not None:
                if self._expr_is_tainted(val, tainted) or (
                        isinstance(stmt, ast.AugAssign) and tgt.id in tainted):
                    tainted.add(tgt.id)

        # 2) check every call inside this statement for a tainted->sink hit
        for call in [n for n in ast.walk(stmt) if isinstance(n, ast.Call)]:
            self._check_sink(call, tainted)

        # 3) recurse into compound bodies (taint flows forward, fixpoint-ish)
        for field_name in ("body", "orelse", "finalbody"):
            sub = getattr(stmt, field_name, None)
            if isinstance(sub, list):
                self._walk_body(sub, tainted)
        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            # loop var inherits taint from the iterable
            if self._expr_is_tainted(stmt.iter, tainted):
                for name in self._assign_targets(stmt.target):
                    tainted.add(name)
        for handler in getattr(stmt, "handlers", []) or []:
            self._walk_body(handler.body, tainted)

    def _check_sink(self, call: ast.Call, tainted: set[str]) -> None:
        chain = _name_chain(call.func)
        bare = chain.split(".")[-1]
        rule_sev = _TAINT_SINKS.get(chain)
        if rule_sev is None:
            # match bare subprocess.* / Popen forms
            if bare in {"system", "popen"} and "os" in chain:
                rule_sev = ("taint.command_injection", "critical")
            elif bare in {"run", "call", "Popen", "check_output"} and (
                    "subprocess" in chain or bare == "Popen"):
                rule_sev = ("taint.command_injection", "critical")
            elif bare in {"eval", "exec"} and isinstance(call.func, ast.Name):
                rule_sev = ("taint.code_injection", "critical")
        if rule_sev is None:
            return
        rule, sev = rule_sev
        # is any positional/keyword arg tainted?
        hit = any(self._expr_is_tainted(a, tainted) for a in call.args) or \
            any(self._expr_is_tainted(kw.value, tainted) for kw in call.keywords)
        if not hit:
            return
        self.findings.append(Finding(
            rule, sev,
            f"TAINT: attacker-controlled data reaches {chain}() "
            f"({_meta(rule)['title']}). Tracked source->sink dataflow.",
            self._loc(call),
            "Break the dataflow: validate/whitelist the value, or pass it as "
            "structured data (argv list, parameterized query) — never let "
            "untrusted input reach this sink.",
        ))


def _taint_findings(path: str, tree: ast.AST, source: str) -> List[Finding]:
    v = _TaintVisitor(path, source)
    v.visit(tree)
    # de-dupe identical (rule, location) pairs the walk can produce when a
    # statement appears in multiple recursion paths.
    seen: set[Tuple[str, str]] = set()
    out: List[Finding] = []
    for f in v.findings:
        key = (f.rule, f.location)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


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
    findings = list(v.findings)
    findings.extend(_taint_findings(path, tree, source))
    findings.extend(_scan_shell_tool_input(path, tree))
    findings.extend(_scan_secrets(path, source))
    findings.extend(scan_open_bind(path, source))
    findings.extend(scan_no_tls_remote(path, source))
    return findings


def _scan_secrets(path: str, source: str) -> List[Finding]:
    out: List[Finding] = []
    for lineno, line in enumerate(source.splitlines(), start=1):
        for label, pat in _SECRET_PATTERNS:
            if pat.search(line):
                out.append(Finding(
                    "static.secret_exposure", "high",
                    f"Hard-coded secret detected ({label}); credentials in "
                    "source leak to anyone who can read the repo.",
                    f"{path}:{lineno}",
                    "Move secrets to environment variables / a secrets "
                    "manager and rotate the exposed credential.",
                ))
                break  # one finding per line is enough
    return out


def _scan_text_fallback(path: str, source: str) -> List[Finding]:
    """Regex sweep used for JS/TS and unparseable Python."""
    out: List[Finding] = []
    lines = source.splitlines()

    for lineno, line in enumerate(lines, start=1):
        loc = f"{path}:{lineno}"
        for rule, pat in _JS_SINKS:
            if pat.search(line):
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
            out.append(Finding(
                "static.ssrf", "high",
                "Outbound HTTP fetch with a non-literal URL argument may "
                "allow SSRF to internal services.",
                loc,
                "Validate/allowlist the target host and block private and "
                "cloud-metadata IP ranges before fetching.",
            ))
        if _JS_SSTI.search(line) and not _line_is_literal_only(line):
            out.append(Finding(
                "static.ssti", "high",
                "Template compiled/rendered from a non-literal value "
                "(server-side template injection).",
                loc,
                "Precompile fixed templates and pass user data as context "
                "variables, never as the template body.",
            ))
        if _JS_FS.search(line) and not _line_is_literal_only(line):
            out.append(Finding(
                "static.path_traversal", "medium",
                "Filesystem call with a non-literal path may allow path "
                "traversal to arbitrary files.",
                loc,
                "Resolve and confine the path to an allowed base directory.",
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
    out.extend(_scan_secrets(path, source))
    return out


def _line_is_literal_only(line: str) -> bool:
    m = re.search(r"\(\s*([\"'`]).*?\1\s*\)\s*;?\s*$", line)
    return bool(m)


def scan_js_source(path: str, source: str) -> List[Finding]:
    return _scan_text_fallback(path, source)


# ==========================================================================
# Manifest / package drift — rug-pull / version-drift detection
# ==========================================================================

def _scan_manifest(path: str, source: str) -> List[Finding]:
    """Detect rug-pull / version-drift risk in dependency manifests:
    floating / unpinned versions let a malicious maintainer ship new code
    silently into the agent's tool supply chain."""
    out: List[Finding] = []
    name = Path(path).name.lower()
    if name in ("requirements.txt", "requirements.in"):
        for lineno, raw in enumerate(source.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            if not re.search(r"==\s*\d", line) and "@" not in line:
                out.append(Finding(
                    "static.tool_poisoning", "low",
                    f"Unpinned dependency '{line}' (rug-pull / version-drift "
                    "risk): a future malicious release enters the MCP supply "
                    "chain automatically.",
                    f"{path}:{lineno}",
                    "Pin exact versions (== x.y.z) and use a hash-locked "
                    "lockfile so updates are reviewed.",
                ))
    elif name == "package.json":
        try:
            data = json.loads(source)
        except (json.JSONDecodeError, ValueError):
            return out
        for sect in ("dependencies", "devDependencies"):
            deps = data.get(sect) or {}
            if not isinstance(deps, dict):
                continue
            for dep, ver in deps.items():
                v = str(ver)
                if v.startswith("^") or v.startswith("~") or v in ("*", "latest") \
                        or v.startswith(">"):
                    out.append(Finding(
                        "static.tool_poisoning", "low",
                        f"Floating dependency '{dep}': \"{v}\" (rug-pull / "
                        "version-drift risk) auto-pulls future releases into "
                        "the MCP supply chain.",
                        path,
                        "Pin exact versions and commit package-lock.json / "
                        "an npm shrinkwrap.",
                    ))
    return out


# ==========================================================================
# v0.3 — MCP config hygiene rules (JSON client/server config files)
# ==========================================================================

# Config file basenames that hold MCP client/server wiring (env, headers,
# args, transport URLs). These are NOT package manifests.
_CONFIG_NAMES = {
    ".mcp.json", "mcp.json", "mcp_config.json", "mcpservers.json",
    "claude_desktop_config.json", "claude_config.json",
}

# Key names whose value is expected to be a credential.
_SECRET_KEY_RE = re.compile(
    r"(?i)(authorization|bearer|api[_-]?key|apikey|secret|token|password|"
    r"passwd|access[_-]?key|client[_-]?secret|private[_-]?key)")

# Value that is merely an env-var placeholder ( ${VAR}, $VAR, %VAR% ) — not a
# baked-in literal, so it must NOT be flagged.
_ENV_PLACEHOLDER_RE = re.compile(r"^\s*(\$\{[^}]+\}|\$[A-Za-z_][\w]*|%[^%]+%)\s*$")

# A literal that actually looks like a credential value (>=12 chars of token
# alphabet, or a "Bearer <token>" string). Avoids flagging short flags/words.
_LITERAL_SECRET_RE = re.compile(r"^[A-Za-z0-9/+_.\-]{12,}={0,2}$")


def _is_placeholder(val: str) -> bool:
    return bool(_ENV_PLACEHOLDER_RE.match(val))


def _looks_like_secret_value(val: str) -> bool:
    """True if a *string value* looks like a baked-in credential (not a
    placeholder, not a short token, or an explicit ``Bearer <token>``)."""
    if not isinstance(val, str):
        return False
    v = val.strip()
    if not v or _is_placeholder(v):
        return False
    bearer = re.match(r"(?i)^(bearer|token)\s+(\S+)", v)
    if bearer:
        return not _is_placeholder(bearer.group(2))
    if _LITERAL_SECRET_RE.match(v) and any(ch.isdigit() for ch in v):
        return True
    # any known high-signal secret format counts too
    return any(pat.search(v) for _, pat in _SECRET_PATTERNS)


def _walk_config_servers(data: Any):
    """Yield (server_label, server_dict) for each MCP server entry, tolerating
    the common shapes: {"mcpServers": {name: {...}}} and {"servers": {...}}."""
    if not isinstance(data, dict):
        return
    for container_key in ("mcpServers", "servers", "mcp"):
        block = data.get(container_key)
        if isinstance(block, dict):
            for name, srv in block.items():
                if isinstance(srv, dict):
                    yield str(name), srv
    # also allow a top-level single server object
    if any(k in data for k in ("command", "env", "headers", "url")):
        yield "<root>", data


def scan_config_secret(path: str, source: str) -> List[Finding]:
    """Flag hard-coded bearer tokens / API keys / secrets baked into an MCP
    config's ``env`` / ``headers`` / ``args``. Env-var placeholders are clean.

    Drafted by the local fleet; rewritten to skip placeholders robustly, only
    flag credential-shaped values, and avoid crashing on non-string values."""
    out: List[Finding] = []
    try:
        data = json.loads(source)
    except (json.JSONDecodeError, ValueError):
        return out
    seen: set = set()

    def _flag(where: str, key: str, val: str) -> None:
        sig = (where, key, val)
        if sig in seen:
            return
        seen.add(sig)
        out.append(Finding(
            "config.hardcoded_secret", "high",
            f"Hard-coded credential in MCP config {where} ('{key}'); a baked-in "
            "secret leaks to anyone who can read the config and cannot be "
            "rotated without an edit.",
            path,
            "Reference the secret via an environment variable placeholder "
            "(e.g. \"${MY_TOKEN}\") and inject it at runtime; rotate the "
            "exposed value.",
        ))

    for label, srv in _walk_config_servers(data):
        env = srv.get("env")
        if isinstance(env, dict):
            for k, v in env.items():
                if isinstance(v, str) and (_SECRET_KEY_RE.search(str(k))
                                           or _looks_like_secret_value(v)):
                    if _looks_like_secret_value(v):
                        _flag(f"env of server '{label}'", str(k), v)
        headers = srv.get("headers")
        if isinstance(headers, dict):
            for k, v in headers.items():
                if not isinstance(v, str):
                    continue
                if str(k).lower() == "authorization" or _SECRET_KEY_RE.search(str(k)):
                    if _looks_like_secret_value(v):
                        _flag(f"headers of server '{label}'", str(k), v)
                elif v.lower().startswith("bearer ") and _looks_like_secret_value(v):
                    _flag(f"headers of server '{label}'", str(k), v)
        args = srv.get("args")
        if isinstance(args, list):
            prev = ""
            for a in args:
                if not isinstance(a, str):
                    prev = ""
                    continue
                # `--token SECRET` (prev flag) or `--token=SECRET` (inline)
                inline = re.match(r"^--?[\w-]*"
                                  r"(authorization|bearer|api[_-]?key|secret|"
                                  r"token|password)[\w-]*=(.+)$", a, re.I)
                if inline and _looks_like_secret_value(inline.group(2)):
                    _flag(f"args of server '{label}'", a.split("=")[0], a)
                elif _SECRET_KEY_RE.search(prev) and _looks_like_secret_value(a):
                    _flag(f"args of server '{label}'", prev, a)
                prev = a
    return out


# Bind to all interfaces — host="0.0.0.0", run("0.0.0.0", ...), --host 0.0.0.0.
_BIND_ALL_RE = re.compile(
    r"""(?ix)
    (?:
        \b(?:host|bind|address|hostname)\s*[:=]\s*['"]0\.0\.0\.0['"]   |
        ['"]0\.0\.0\.0['"]\s*,\s*\d{2,5}                                |  # ("0.0.0.0", 8080)
        \.run\s*\(\s*['"]0\.0\.0\.0['"]                                 |
        --(?:host|bind)\s+0\.0\.0\.0                                    |
        \b0\.0\.0\.0:\d{2,5}\b
    )
    """)

# Any sign that auth is being enforced in the same file.
_AUTH_PRESENT_RE = re.compile(
    r"(?i)\b(authorization|bearer|verify_token|require_auth|auth_required|"
    r"api[_-]?key|access[_-]?token|oauth|jwt|HTTPBasic|HTTPBearer|"
    r"check_token|authenticate|login_required)\b")


def scan_open_bind(path: str, source: str) -> List[Finding]:
    """Flag a listener bound to 0.0.0.0 (all interfaces) when the same file
    shows no authentication — the server is reachable network-wide with no
    gate. Drafted by the fleet; widened the bind matcher to cover positional
    .run("0.0.0.0", ...) / "host:port" / CLI forms and line-precise location."""
    out: List[Finding] = []
    if _AUTH_PRESENT_RE.search(source):
        return out
    for lineno, line in enumerate(source.splitlines(), start=1):
        if _BIND_ALL_RE.search(line):
            out.append(Finding(
                "config.open_bind_no_auth", "high",
                "Server binds to 0.0.0.0 (all network interfaces) and no "
                "authentication is configured in this file; any host that can "
                "reach the port can drive the MCP server.",
                f"{path}:{lineno}",
                "Bind to 127.0.0.1 for local use, or require a bearer "
                "token / OAuth before serving tools/list and tools/call.",
            ))
            break  # one finding per file is enough
    return out


# http:// URL whose host is NOT loopback/all-interfaces (i.e. a real remote).
_REMOTE_HTTP_RE = re.compile(
    r"""(?ix)\bhttp://
        (?P<host>[A-Za-z0-9.\-]+(?::\d+)?)
        (?P<rest>[^\s'"`)]*)""")
_LOCAL_HOST_RE = re.compile(
    r"(?i)^(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|::1)(:\d+)?$")
# context keys that mark a value as an MCP transport / remote endpoint.
_TRANSPORT_HINT_RE = re.compile(
    r"(?i)\b(url|uri|endpoint|base[_-]?url|server[_-]?url|transport|sse|"
    r"baseUrl|serverUrl|host|remote|mcp)\b")


def scan_no_tls_remote(path: str, source: str) -> List[Finding]:
    """Flag a remote (non-loopback) MCP transport configured over plaintext
    http://. Drafted by the fleet; rewritten to extract the real host, ignore
    loopback, de-dupe per host, and require transport context so arbitrary
    doc/comment links don't false-positive."""
    out: List[Finding] = []
    has_transport_ctx = bool(_TRANSPORT_HINT_RE.search(source))
    seen: set = set()
    for lineno, line in enumerate(source.splitlines(), start=1):
        for m in _REMOTE_HTTP_RE.finditer(line):
            host = m.group("host")
            if _LOCAL_HOST_RE.match(host):
                continue
            # require either a transport key on this line, or the file is a
            # config/transport file overall (avoids flagging prose URLs).
            line_ctx = _TRANSPORT_HINT_RE.search(line)
            if not (line_ctx or has_transport_ctx):
                continue
            if host in seen:
                continue
            seen.add(host)
            out.append(Finding(
                "config.no_tls_remote", "medium",
                f"Remote MCP transport uses cleartext http:// (host '{host}'); "
                "tokens and tool traffic to a remote server travel unencrypted "
                "and can be intercepted or tampered with.",
                f"{path}:{lineno}",
                "Use https:// for any non-loopback MCP endpoint (or an "
                "authenticating TLS-terminating proxy).",
            ))
    return out


def _scan_config(path: str, source: str) -> List[Finding]:
    """Run all MCP-config-file rules over a JSON config (.mcp.json,
    claude_desktop_config.json, ...): hard-coded secrets + cleartext remote
    transport."""
    out: List[Finding] = []
    out.extend(scan_config_secret(path, source))
    out.extend(scan_no_tls_remote(path, source))
    return out


# ==========================================================================
# v0.3 — shell-tool input flow (AST): an MCP tool param reaches a subprocess
# ==========================================================================

_SHELL_SINKS = {
    "os.system", "os.popen", "subprocess.run", "subprocess.call",
    "subprocess.check_call", "subprocess.check_output", "subprocess.Popen",
}


def _node_uses_param(node: Optional[ast.AST], params: set) -> bool:
    """True if expression `node` references any of the given parameter names
    (directly, or through concat / f-string / .format() / str() wrapping)."""
    if node is None:
        return False
    found = False
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and sub.id in params:
            found = True
            break
    return found


def _scan_shell_tool_input(path: str, tree: ast.AST) -> List[Finding]:
    """Flag a tool/function that feeds one of its own parameters into a shell
    subprocess sink (shell=True, or the param concatenated into the command
    argument). This is the canonical 'shell tool runs user input' MCP RCE.

    Drafted by the fleet as a regex (broken); reimplemented as a real AST pass
    that confines the flow to a single function's parameters and the command
    argument of the sink."""
    out: List[Finding] = []
    seen: set = set()

    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        params: set = set()
        for a in list(fn.args.args) + list(fn.args.kwonlyargs):
            if a.arg not in ("self", "cls"):
                params.add(a.arg)
        if fn.args.vararg:
            params.add(fn.args.vararg.arg)
        if fn.args.kwarg:
            params.add(fn.args.kwarg.arg)
        if not params:
            continue
        for call in [n for n in ast.walk(fn) if isinstance(n, ast.Call)]:
            chain = _name_chain(call.func)
            bare = chain.split(".")[-1]
            is_sink = chain in _SHELL_SINKS or (
                bare == "Popen") or (
                bare in {"system", "popen"} and "os" in chain) or (
                bare in {"run", "call", "check_call", "check_output"}
                and "subprocess" in chain)
            if not is_sink:
                continue
            cmd_arg = _call_arg(call, 0)
            shelly = _shell_true(call) or bare in {"system", "popen"}
            param_in_cmd = _node_uses_param(cmd_arg, params)
            # also catch the param appearing in any positional arg of a
            # shell=True subprocess call (the command may be arg 0 list/str).
            if not param_in_cmd and shelly:
                param_in_cmd = any(_node_uses_param(a, params)
                                   for a in call.args)
            if param_in_cmd and (shelly or "os" in chain or
                                 "subprocess" in chain):
                loc = f"{path}:{getattr(call, 'lineno', '?')}"
                if loc in seen:
                    continue
                seen.add(loc)
                out.append(Finding(
                    "static.shell_tool_input", "critical",
                    f"Tool '{fn.name}' passes its parameter into {chain}() "
                    + ("with shell=True " if _shell_true(call) else "")
                    + "— attacker-controlled MCP tool input reaches a shell "
                    "(command injection / RCE).",
                    loc,
                    "Never build a shell command from tool input: use an argv "
                    "list with shell=False and validate/allowlist arguments.",
                ))
    return out


# ==========================================================================
# Static analysis — directory walk
# ==========================================================================

_MANIFEST_NAMES = {"requirements.txt", "requirements.in", "package.json"}


def scan_path(target: str, *, use_ai: bool = False,
              ai_focus: Optional[str] = None) -> Report:
    """Statically scan a file or directory of MCP server source.

    With ``use_ai=True`` the configured Cognis fleet backend (env COGNIS_AI_*)
    reviews the same files; AI findings are merged tagged source="ai" and
    de-duped against rule findings. AI is OFF unless explicitly requested and
    a backend is reachable; failure never crashes the scan.
    """
    p = Path(target)
    if not p.exists():
        raise ScanError(f"no such path: {target}")

    files: List[Path]
    if p.is_file():
        files = [p]
    else:
        try:
            files = sorted(
                f for f in p.rglob("*")
                if f.is_file() and (
                    f.suffix in _PY_EXT or f.suffix in _JS_EXT
                    or f.name in _MANIFEST_NAMES
                    or f.name.lower() in _CONFIG_NAMES)
                and "node_modules" not in f.parts and ".git" not in f.parts
            )
        except PermissionError as exc:
            raise ScanError(f"cannot read directory {target!r}: {exc}") from exc

    report = Report(source=str(target), target_kind="source")
    ai_inputs: List[Tuple[str, str]] = []
    for f in files:
        try:
            src = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(f)
        if f.name.lower() in _CONFIG_NAMES:
            report.findings.extend(_scan_config(rel, src))
            continue
        if f.name in _MANIFEST_NAMES and f.suffix not in _JS_EXT:
            report.findings.extend(_scan_manifest(rel, src))
            continue
        report.files_scanned += 1
        if f.suffix in _PY_EXT:
            report.findings.extend(scan_python_source(rel, src))
        else:
            report.findings.extend(scan_js_source(rel, src))
        ai_inputs.append((rel, src))

    if report.files_scanned == 0:
        report.findings.append(Finding(
            "static.no_source", "info",
            "No Python/JavaScript source files found at the target.",
            str(target),
            "Point mcpscan at the MCP server's source directory.",
        ))

    if use_ai:
        _merge_ai_findings(report, ai_inputs, ai_focus)

    _finalize(report)
    return report


# ==========================================================================
# Remote fetch — scan a public GitHub / raw URL file
# ==========================================================================

def _normalize_raw_url(url: str) -> str:
    """Turn a github.com/.../blob/... URL into its raw.githubusercontent form."""
    m = re.match(
        r"^https?://github\.com/([^/]+)/([^/]+)/blob/(.+)$", url, re.I)
    if m:
        owner, repo, rest = m.group(1), m.group(2), m.group(3)
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{rest}"
    return url


def scan_url(url: str, *, timeout: float = 10.0, use_ai: bool = False,
             ai_focus: Optional[str] = None) -> Report:
    """Fetch a remote public MCP server / repo file and scan its source."""
    if not re.match(r"^https?://", url, re.I):
        raise ScanError("scan-url requires an http(s):// URL")
    if timeout <= 0:
        raise ScanError(f"timeout must be a positive number, got {timeout!r}")
    fetch = _normalize_raw_url(url)
    req = urllib.request.Request(fetch, method="GET")
    req.add_header("User-Agent", f"{TOOL_NAME}/{TOOL_VERSION}")
    req.add_header("Accept", "text/plain, */*")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        raise ScanError(f"could not fetch {fetch}: HTTP {exc.code}") from exc
    except (urllib.error.URLError, socket.timeout, OSError, ValueError) as exc:
        raise ScanError(f"could not fetch {fetch}: {exc}") from exc

    src = raw.decode("utf-8", errors="replace")
    report = Report(source=url, target_kind="url")
    report.files_scanned = 1
    name = fetch.rsplit("/", 1)[-1].split("?")[0]
    suffix = ("." + name.rsplit(".", 1)[-1]) if "." in name else ""
    if name.lower() in _CONFIG_NAMES:
        report.findings.extend(_scan_config(name, src))
    elif name in _MANIFEST_NAMES:
        report.findings.extend(_scan_manifest(name, src))
    elif suffix in _JS_EXT:
        report.findings.extend(scan_js_source(name, src))
    else:
        # default to Python (covers .py and unknown — ast parse will fall back)
        report.findings.extend(scan_python_source(name, src))

    if use_ai:
        _merge_ai_findings(report, [(name, src)], ai_focus)

    _finalize(report)
    return report


# ==========================================================================
# AI merge layer — opt-in, fail-open
# ==========================================================================

def _ai_focus_default() -> str:
    return ("This is a Model Context Protocol (MCP) server / AI-agent tool. "
            "Pay special attention to tool-description poisoning, "
            "confused-deputy / token passthrough, excessive agency, insecure "
            "handling of tool/LLM output, and novel logic flaws a signature "
            "scanner would miss.")


def _rule_dedupe_keys(report: Report) -> set:
    """Keys for de-duping AI findings against existing rule findings:
    (cwe, line) and (normalized title token, line)."""
    keys = set()
    for f in report.findings:
        path, line = _split_loc(f.location)
        if f.cwe and line:
            keys.add(("cwe", f.cwe, line))
    return keys


def _merge_ai_findings(report: Report, inputs: List[Tuple[str, str]],
                       focus: Optional[str]) -> None:
    """Run the AI backend over the same inputs and merge results. Fail-open:
    any error/disabled/unreachable backend leaves the rule findings intact and
    records a human-readable note instead of raising."""
    try:
        from . import ai_backend as ai
    except Exception:  # pragma: no cover
        report.ai_note = "AI backend module unavailable; rule findings only."
        return

    backend = ai.CognisAIBackend()
    if not backend.is_enabled():
        report.ai_note = (
            "--ai given but no backend configured (set COGNIS_AI_BACKEND or "
            "COGNIS_AI_ENDPOINT); continuing with rule findings only.")
        return
    if not backend.health():
        report.ai_note = (
            f"--ai given but backend at {backend.base_url} is unreachable; "
            "continuing with rule findings only.")
        return

    report.ai_used = True
    dedupe = _rule_dedupe_keys(report)
    focus_text = focus or _ai_focus_default()
    added = 0
    for path, src in inputs:
        try:
            ai_findings = backend.analyze_code(
                src, context=f"file: {path}", focus=focus_text)
        except Exception:
            continue
        for item in ai_findings or []:
            line = item.get("line", 0) or 0
            cwe = item.get("cwe", "") or ""
            loc = f"{path}:{line}" if line else path
            # de-dupe against rule findings sharing the same CWE+line
            if cwe and line and ("cwe", cwe, line) in dedupe:
                continue
            sev = item.get("severity", "info")
            title = item.get("title") or "AI finding"
            why = item.get("why") or ""
            evidence = item.get("evidence") or ""
            msg = title + ((" — " + why) if why else "")
            if evidence:
                msg += f"  [evidence: {evidence[:160]}]"
            report.findings.append(Finding(
                rule="ai.finding",
                severity=sev,
                message=msg,
                location=loc,
                remediation="Review this AI-discovered issue and confirm "
                            "before acting; it is advisory, not deterministic.",
                source="ai",
                cwe=cwe,
                novel=bool(item.get("novel", False)),
                confidence=float(item.get("confidence", 0.0) or 0.0),
            ))
            added += 1
    report.ai_note = (
        f"AI backend ({backend.backend or backend.base_url}) added "
        f"{added} finding(s).")


# ==========================================================================
# Live probe — HTTP MCP endpoint (urllib)
# ==========================================================================

def _jsonrpc(url: str, method: str, headers: Optional[Dict[str, str]] = None,
             timeout: float = 6.0) -> Tuple[int, Any]:
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
    report = Report(source=url, target_kind="endpoint")

    if not re.match(r"^https?://", url, re.I):
        raise ScanError("endpoint must be an http(s):// URL")
    if timeout <= 0:
        raise ScanError(f"timeout must be a positive number, got {timeout!r}")

    try:
        anon_status, body = _jsonrpc(url, "tools/list", headers=None,
                                     timeout=timeout)
        status = anon_status
        if anon_status in (401, 403) and token:
            status, body = _jsonrpc(
                url, "tools/list",
                headers={"Authorization": f"Bearer {token}"}, timeout=timeout)
    except (urllib.error.URLError, socket.timeout, OSError, ValueError) as exc:
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

    if url.lower().startswith("http://"):
        report.findings.append(Finding(
            "live.no_tls", "high",
            "MCP endpoint served over plain HTTP; tokens and tool traffic "
            "travel in cleartext.",
            url,
            "Serve over HTTPS / terminate TLS at an authenticating proxy.",
        ))

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
         token: Optional[str] = None, use_ai: bool = False, **_: Any) -> Report:
    """Public API used by the CLI and the MCP server.

    If `target` looks like an http(s) URL (or `endpoint` is given), probe the
    live endpoint; otherwise statically scan the path.
    """
    live = endpoint or (target if re.match(r"^https?://", target or "", re.I)
                        else None)
    if live:
        return probe_endpoint(live, token=token)
    return scan_path(target, use_ai=use_ai)


# ==========================================================================
# Exporters
# ==========================================================================

def to_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2)


def to_badge(report: Report) -> str:
    """shields.io endpoint JSON: {schemaVersion,label,message,color}.

    Point a shields.io endpoint badge at a hosted copy of this JSON:
    https://img.shields.io/endpoint?url=<raw-url-of-this-file>
    """
    c = report.counts
    crit, high = c["critical"], c["high"]
    if crit:
        message, color = f"{crit} critical", "red"
    elif high:
        message, color = f"{high} high", "orange"
    elif c["medium"]:
        message, color = f"{c['medium']} medium", "yellow"
    elif c["low"]:
        message, color = f"{c['low']} low", "yellowgreen"
    else:
        message, color = "no findings", "brightgreen"
    return json.dumps({
        "schemaVersion": 1,
        "label": "mcpscan",
        "message": message,
        "color": color,
    })


def to_html(report: Report) -> str:
    """A clean, self-contained (no external assets) HTML report."""
    c = report.counts
    e = _html_escape
    sev_color = {"critical": "#c0392b", "high": "#e67e22", "medium": "#d4ac0d",
                 "low": "#7f8c8d", "info": "#3498db"}
    kind = {"endpoint": "live endpoint", "url": "remote URL"}.get(
        report.target_kind, "source")
    rows = []
    for f in report.findings:
        tags = []
        if f.cwe:
            tags.append(e(f.cwe))
        if f.owasp_llm:
            tags.append("OWASP " + e(f.owasp_llm))
        if f.ms_taxonomy:
            tags.append("MS:" + e(f.ms_taxonomy))
        if f.source == "ai":
            tags.append("AI")
        if f.novel:
            tags.append("NOVEL")
        badge = ('<span class="src ai">AI</span>' if f.source == "ai"
                 else '<span class="src rule">rule</span>')
        rows.append(
            f'<tr class="sev-{e(f.severity)}">'
            f'<td><span class="pill" style="background:{sev_color.get(f.severity, "#555")}">'
            f'{e(f.severity.upper())}</span></td>'
            f'<td><code>{e(f.rule)}</code>{badge}<div class="tags">'
            f'{" · ".join(tags)}</div></td>'
            f'<td>{e(f.message)}'
            + (f'<div class="loc">{e(f.location)}</div>' if f.location else "")
            + (f'<div class="fix">fix: {e(f.remediation)}</div>'
               if f.remediation else "")
            + '</td></tr>'
        )
    body = "\n".join(rows) or '<tr><td colspan="3">No findings.</td></tr>'
    ai_line = (f'<p class="ai-note">AI: {e(report.ai_note)}</p>'
               if report.ai_note else "")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>mcpscan report — {e(report.source)}</title>
<style>
 :root {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; }}
 body {{ margin: 0; background:#0f1117; color:#e6e6e6; }}
 header {{ background:#161a22; padding:24px 32px; border-bottom:2px solid #6b46c1; }}
 h1 {{ margin:0 0 4px; font-size:20px; }}
 .meta {{ color:#9aa4b2; font-size:13px; }}
 .score {{ font-size:42px; font-weight:700; }}
 .summary {{ display:flex; gap:14px; padding:18px 32px; flex-wrap:wrap; }}
 .card {{ background:#161a22; border-radius:8px; padding:12px 18px; min-width:80px; }}
 .card b {{ display:block; font-size:24px; }}
 table {{ width:calc(100% - 64px); margin:0 32px 40px; border-collapse:collapse; }}
 th,td {{ text-align:left; padding:10px 12px; border-bottom:1px solid #262b36;
          vertical-align:top; font-size:14px; }}
 th {{ color:#9aa4b2; font-weight:600; }}
 .pill {{ color:#fff; padding:2px 8px; border-radius:10px; font-size:11px;
          font-weight:700; }}
 code {{ background:#11141b; padding:1px 5px; border-radius:4px; color:#c6a0ff; }}
 .src {{ font-size:10px; margin-left:6px; padding:1px 5px; border-radius:4px; }}
 .src.ai {{ background:#6b46c1; color:#fff; }}
 .src.rule {{ background:#2c3340; color:#9aa4b2; }}
 .tags {{ color:#7f8c8d; font-size:11px; margin-top:3px; }}
 .loc {{ color:#9aa4b2; font-size:12px; margin-top:4px; font-family:monospace; }}
 .fix {{ color:#7fcaa0; font-size:12px; margin-top:4px; }}
 .ai-note {{ color:#c6a0ff; padding:0 32px; font-size:13px; }}
 footer {{ color:#6b7280; padding:16px 32px; font-size:12px; }}
</style></head><body>
<header>
 <h1>mcpscan — {e(kind)} report</h1>
 <div class="meta">target: {e(report.source)} · files scanned: {report.files_scanned}
  · mcpscan {e(TOOL_VERSION)}</div>
</header>
<div class="summary">
 <div class="card"><span class="meta">score</span><b class="score">{report.score}</b></div>
 <div class="card"><span class="meta">critical</span><b>{c['critical']}</b></div>
 <div class="card"><span class="meta">high</span><b>{c['high']}</b></div>
 <div class="card"><span class="meta">medium</span><b>{c['medium']}</b></div>
 <div class="card"><span class="meta">low</span><b>{c['low']}</b></div>
 <div class="card"><span class="meta">info</span><b>{c['info']}</b></div>
</div>
{ai_line}
<table>
 <thead><tr><th>severity</th><th>rule</th><th>detail</th></tr></thead>
 <tbody>
{body}
 </tbody>
</table>
<footer>Generated by mcpscan {e(TOOL_VERSION)} — Cognis Neural Suite ·
 rules mapped to CWE + OWASP LLM Top-10 + Microsoft agent-threat taxonomy.</footer>
</body></html>"""


def to_sarif(report: Report) -> str:
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    sarif_level = {"critical": "error", "high": "error", "medium": "warning",
                   "low": "note", "info": "note"}
    for f in report.findings:
        props: Dict[str, Any] = {"security-severity": _sec_sev(f.severity)}
        if f.cwe:
            props["cwe"] = f.cwe
        if f.owasp_llm:
            props["owasp-llm"] = f.owasp_llm
        if f.ms_taxonomy:
            props["ms-agent-taxonomy"] = f.ms_taxonomy
        if f.source == "ai":
            props["source"] = "ai"
        rules.setdefault(f.rule, {
            "id": f.rule,
            "name": f.rule,
            "shortDescription": {"text": _meta(f.rule).get("title", f.rule)},
            "properties": props,
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

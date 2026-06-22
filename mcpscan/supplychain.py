"""Supply-chain / dependency audit for mcpscan (OWASP Agentic ASI04).

The MCP supply chain is the soft underbelly of agentic systems: an agent's
tools are only as trustworthy as the packages that implement them. A single
poisoned, unpinned, or known-vulnerable dependency hands an attacker code
execution *inside* the tool the model is told it can trust. The OWASP Top 10
for Agentic Applications (2026) calls this ASI04 "Agent Supply Chain"; CWE
labels the building blocks (CWE-1357 reliance on unmaintained/uncontrolled
components, CWE-1395 vulnerable dependency, CWE-829 inclusion from an untrusted
control sphere).

This module parses the dependency manifests an MCP server ships and reports
real, defensible supply-chain risk:

  * known_vuln          — a pinned version that falls inside a published OSV /
                          GHSA / CVE advisory range (matched against a shipped
                          offline advisory DB, or OSV.dev live when --online).
  * unpinned            — a floating / range / unbounded spec that auto-pulls a
                          future (possibly malicious) release — the rug-pull
                          window.
  * no_lockfile         — a manifest with declared deps but no committed
                          lockfile, so installs are not reproducible/reviewable.
  * install_hook        — package.json pre/post-install scripts, or a setup.py
                          that runs arbitrary code at install time (CWE-829).
  * typosquat           — a dependency whose name is one edit away from a
                          widely-used package but is not that package
                          (dependency-confusion / typosquat candidate).
  * nonregistry_source  — a dependency pulled from a VCS URL, tarball URL, git+,
                          or local path rather than the public registry.

Standard-library only. Advisory matching is OFFLINE by default and fully
deterministic; the optional OSV.dev live lookup is opt-in (`online=True`).

Defensive / authorized-use only.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_DATA = Path(__file__).resolve().parent / "data"

# Manifests we know how to parse. Lockfiles are recorded so a manifest can tell
# whether a sibling lockfile exists.
PY_MANIFESTS = {"requirements.txt", "requirements.in", "pyproject.toml", "setup.py", "setup.cfg"}
JS_MANIFESTS = {"package.json"}
PY_LOCKS = {"requirements.lock", "poetry.lock", "pdm.lock", "uv.lock", "pip.lock", "constraints.txt"}
JS_LOCKS = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}

MANIFEST_NAMES = PY_MANIFESTS | JS_MANIFESTS
LOCK_NAMES = PY_LOCKS | JS_LOCKS

# npm version-spec characters that mean "not exactly pinned".
_NPM_FLOATING = ("^", "~", "*", ">", "<", "x", "X", "||", " - ", "latest")
# A non-registry npm source.
_NPM_NONREG = re.compile(r"^(git\+|git:|github:|https?:|file:|link:|workspace:|[./])", re.I)


@dataclass
class Dependency:
    name: str
    raw_spec: str
    pinned_version: Optional[str]   # exact version if pinned, else None
    ecosystem: str                  # "PyPI" | "npm"
    section: str                    # "dependencies" | "dev" | "optional" | ...
    location: str                   # file:line or file
    nonregistry: bool = False       # VCS/url/local source


# ---------------------------------------------------------------------------
# Advisory database (offline)
# ---------------------------------------------------------------------------

def load_advisories(path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Load the shipped offline advisory DB (or a custom path)."""
    p = Path(path) if path else (_DATA / "advisories.json")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return []
    return data.get("advisories", []) if isinstance(data, dict) else []


def load_popular(path: Optional[str] = None) -> Dict[str, set]:
    p = Path(path) if path else (_DATA / "popular_packages.json")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return {"PyPI": set(), "npm": set()}
    return {
        "PyPI": {str(n).lower() for n in data.get("PyPI", [])},
        "npm": {str(n).lower() for n in data.get("npm", [])},
    }


# ---------------------------------------------------------------------------
# Version comparison (PEP 440 / semver subset, no third-party deps)
# ---------------------------------------------------------------------------

def parse_version(v: str) -> Tuple[int, ...]:
    """Best-effort numeric version tuple for ordering. Non-numeric pre-release
    tags are stripped; a release is treated as >= its pre-releases for the
    purpose of "is this version affected" (conservative — we'd rather surface
    than hide a known-vuln dependency)."""
    v = str(v).strip().lstrip("vV=")
    # Cut at the first pre/post/dev/local separator.
    v = re.split(r"[-+~^ ]", v, maxsplit=1)[0]
    parts: List[int] = []
    for chunk in v.split("."):
        m = re.match(r"(\d+)", chunk)
        if not m:
            break
        parts.append(int(m.group(1)))
    return tuple(parts) if parts else (0,)


def _cmp(a: Tuple[int, ...], b: Tuple[int, ...]) -> int:
    la, lb = list(a), list(b)
    n = max(len(la), len(lb))
    la += [0] * (n - len(la))
    lb += [0] * (n - len(lb))
    return (la > lb) - (la < lb)


def version_in_range(version: str, rng: Dict[str, str]) -> bool:
    """OSV range semantics: affected if introduced <= v < fixed (when fixed
    is present), else introduced <= v."""
    v = parse_version(version)
    intro = parse_version(rng.get("introduced", "0"))
    if _cmp(v, intro) < 0:
        return False
    fixed = rng.get("fixed")
    if fixed:
        return _cmp(v, parse_version(fixed)) < 0
    last = rng.get("last_affected")
    if last:
        return _cmp(v, parse_version(last)) <= 0
    return True


def match_advisories(dep: Dependency,
                     advisories: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return advisories that affect this dependency's pinned version. An
    unpinned dependency is not matched here (it has no concrete version) — it
    is reported separately as `unpinned`."""
    if not dep.pinned_version:
        return []
    hits: List[Dict[str, Any]] = []
    name = dep.name.lower()
    for adv in advisories:
        if adv.get("ecosystem") != dep.ecosystem:
            continue
        if str(adv.get("package", "")).lower() != name:
            continue
        ranges = adv.get("ranges") or [{"introduced": "0"}]
        if any(version_in_range(dep.pinned_version, r) for r in ranges):
            hits.append(adv)
    return hits


# ---------------------------------------------------------------------------
# Typosquat / dependency-confusion heuristic
# ---------------------------------------------------------------------------

def _edit_distance_le1(a: str, b: str) -> bool:
    """True if a and b differ by at most one insert/delete/substitution.
    Cheap O(n) check — no full DP needed for the threshold-1 case."""
    if a == b:
        return False  # identical is not a near-miss
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    if la == lb:  # at most one substitution
        diffs = sum(1 for x, y in zip(a, b) if x != y)
        return diffs == 1
    # length differs by 1 — check single insertion/deletion
    if la > lb:
        a, b = b, a  # ensure a is the shorter
    i = j = 0
    skipped = False
    while i < len(a) and j < len(b):
        if a[i] == b[j]:
            i += 1
            j += 1
        elif skipped:
            return False
        else:
            skipped = True
            j += 1
    return True


def typosquat_candidates(name: str, ecosystem: str,
                         popular: Dict[str, set]) -> List[str]:
    """Popular package names that `name` is a near-miss of (and is not)."""
    n = name.lower()
    pool = popular.get(ecosystem, set())
    if n in pool:
        return []
    return sorted(p for p in pool if _edit_distance_le1(n, p))


# ---------------------------------------------------------------------------
# Manifest parsers -> List[Dependency]
# ---------------------------------------------------------------------------

_REQ_LINE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*"
    r"(\[[^\]]*\])?\s*"
    r"(.*)$"
)


def parse_requirements(path: str, source: str) -> List[Dependency]:
    deps: List[Dependency] = []
    for lineno, raw in enumerate(source.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        # VCS / URL / local installs: "pkg @ git+https://...", "git+https://..."
        nonreg = bool(re.match(r"^(git\+|https?:|file:|\.{1,2}/)", line, re.I)) \
            or " @ " in line
        m = _REQ_LINE.match(line)
        if not m:
            continue
        name = m.group(1)
        spec = m.group(3).strip()
        pinned = None
        pm = re.match(r"==\s*([0-9][^,;\s]*)", spec)
        if pm and not re.search(r"[,*]", pm.group(1)):
            pinned = pm.group(1)
        deps.append(Dependency(
            name=name, raw_spec=spec or "(any)", pinned_version=pinned,
            ecosystem="PyPI", section="dependencies",
            location=f"{path}:{lineno}", nonregistry=nonreg))
    return deps


def parse_package_json(path: str, source: str) -> Tuple[List[Dependency], Dict[str, Any]]:
    """Returns (dependencies, meta) where meta carries install-script info."""
    try:
        data = json.loads(source)
    except (json.JSONDecodeError, ValueError):
        return [], {}
    deps: List[Dependency] = []
    sections = {
        "dependencies": "dependencies",
        "devDependencies": "dev",
        "optionalDependencies": "optional",
        "peerDependencies": "peer",
    }
    for key, sect in sections.items():
        block = data.get(key) or {}
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            v = str(spec)
            nonreg = bool(_NPM_NONREG.match(v))
            pinned = v if re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][\w.]+)?", v) else None
            deps.append(Dependency(
                name=name, raw_spec=v, pinned_version=pinned,
                ecosystem="npm", section=sect, location=path,
                nonregistry=nonreg))
    scripts = data.get("scripts") or {}
    install_hooks = {k: v for k, v in scripts.items()
                     if isinstance(scripts, dict)
                     and k in ("preinstall", "install", "postinstall",
                               "preuninstall", "postuninstall", "prepare")}
    meta = {"install_hooks": install_hooks}
    return deps, meta


def parse_setup_py(path: str, source: str) -> Tuple[List[Dependency], Dict[str, Any]]:
    """Extract install_requires entries from setup.py via AST when possible,
    and flag any top-level side-effecting code (arbitrary install-time exec)."""
    import ast as _ast
    deps: List[Dependency] = []
    risky_exec = False
    try:
        tree = _ast.parse(source)
    except SyntaxError:
        return deps, {"risky_exec": False}

    # install_requires=[...]
    for node in _ast.walk(tree):
        if isinstance(node, _ast.keyword) and node.arg == "install_requires":
            if isinstance(node.value, (_ast.List, _ast.Tuple)):
                for elt in node.value.elts:
                    if isinstance(elt, _ast.Constant) and isinstance(elt.value, str):
                        for d in parse_requirements(path, elt.value):
                            deps.append(d)

    # Top-level (module body) statements that execute code beyond imports /
    # the setup() call / simple assignments / function+class defs are an
    # install-time arbitrary-code-execution surface.
    _SAFE = (_ast.Import, _ast.ImportFrom, _ast.Assign, _ast.AnnAssign,
             _ast.FunctionDef, _ast.AsyncFunctionDef, _ast.ClassDef,
             _ast.Expr, _ast.If, _ast.Pass)
    for stmt in tree.body:
        if isinstance(stmt, _ast.Expr):
            call = stmt.value
            if isinstance(call, _ast.Call):
                fn = getattr(call.func, "id", None) or getattr(call.func, "attr", None)
                if fn in ("system", "check_call", "check_output", "run",
                          "Popen", "call", "exec", "eval", "urlopen",
                          "urlretrieve", "get", "post"):
                    risky_exec = True
        elif not isinstance(stmt, _SAFE):
            # e.g. a top-level For / While / With doing real work at import
            risky_exec = True
    return deps, {"risky_exec": risky_exec}


# ---------------------------------------------------------------------------
# Optional live OSV.dev lookup (opt-in; offline by default)
# ---------------------------------------------------------------------------

_OSV_URL = "https://api.osv.dev/v1/query"
_UA = "Mozilla/5.0 (cognis-mcpscan; +https://github.com/cognis-digital)"


def osv_query_live(name: str, version: str, ecosystem: str,
                   timeout: float = 8.0) -> List[Dict[str, Any]]:
    """Query OSV.dev for advisories affecting (name, version). Returns a list
    in the same shape as the offline DB rows. Network failures return []
    (the offline DB still applies). Only called when online=True."""
    body = json.dumps({
        "version": version,
        "package": {"name": name, "ecosystem": ecosystem},
    }).encode()
    req = urllib.request.Request(
        _OSV_URL, data=body,
        headers={"User-Agent": _UA, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, json.JSONDecodeError, ValueError, OSError):
        return []
    out: List[Dict[str, Any]] = []
    for v in payload.get("vulns", []) or []:
        out.append({
            "id": v.get("id", ""),
            "aliases": v.get("aliases", []),
            "ecosystem": ecosystem,
            "package": name,
            "summary": v.get("summary") or (v.get("details", "")[:140]),
            "severity": _osv_severity(v),
            "ranges": [],   # already matched by OSV server
        })
    return out


def _osv_severity(vuln: Dict[str, Any]) -> str:
    for s in vuln.get("severity", []) or []:
        score = str(s.get("score", ""))
        if "/C:H" in score or "VC:H" in score:
            return "high"
    return "medium"


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

def _adv_severity(adv: Dict[str, Any]) -> str:
    sev = str(adv.get("severity", "")).lower()
    return sev if sev in ("critical", "high", "medium", "low") else "high"


def _adv_id(adv: Dict[str, Any]) -> str:
    aliases = adv.get("aliases") or []
    cve = next((a for a in aliases if str(a).startswith("CVE-")), "")
    primary = adv.get("id", "")
    return f"{primary} ({cve})" if cve else primary


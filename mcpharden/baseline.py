"""Tool-definition baselining — detect MCP "rug pulls".

A rug pull (CVE-2025-54136 / MCP-RP-01) is when an approved server silently
changes a tool's behavior or description *after* you trusted it. mcpharden can
pin a baseline of each tool's definition (a hash of name + description +
inputSchema), then diff a later manifest against it and flag anything that was
added, removed, or mutated — the rug-pull signature.

    mcpharden baseline server.json -o server.baseline.json   # pin (once, when trusted)
    mcpharden diff server.json --baseline server.baseline.json   # later: detect drift
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List

from .core import Finding, Report, SEVERITY_ORDER


def _tool_hash(tool: Dict[str, Any]) -> str:
    basis = {
        "name": tool.get("name", ""),
        "description": tool.get("description", ""),
        "inputSchema": tool.get("inputSchema") or tool.get("input_schema") or {},
    }
    blob = json.dumps(basis, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def build_baseline(manifest: Dict[str, Any]) -> Dict[str, Any]:
    tools = manifest.get("tools") if isinstance(manifest.get("tools"), list) else []
    return {
        "server": str(manifest.get("name") or manifest.get("server_name") or "unknown"),
        "tools": {str(t.get("name", f"tool{i}")): _tool_hash(t)
                  for i, t in enumerate(tools) if isinstance(t, dict)},
    }


def diff_baseline(baseline: Dict[str, Any], manifest: Dict[str, Any],
                  source: str = "<manifest>") -> Report:
    base_tools: Dict[str, str] = dict(baseline.get("tools", {}))
    current = build_baseline(manifest)["tools"]
    findings: List[Finding] = []

    for name, h in current.items():
        if name not in base_tools:
            findings.append(Finding(
                "rugpull.tool_added", "high",
                f"Tool '{name}' was added since the baseline — it was never reviewed/approved.",
                f"tools:{name}",
                "Re-review the new tool's description and schema before trusting the server."))
        elif base_tools[name] != h:
            findings.append(Finding(
                "rugpull.tool_changed", "critical",
                f"Tool '{name}' changed since the baseline (description/schema mutated) — "
                "classic rug-pull / tool-poisoning vector.",
                f"tools:{name}",
                "Inspect the diff; do not auto-trust. Re-pin only after review."))
    for name in base_tools:
        if name not in current:
            findings.append(Finding(
                "rugpull.tool_removed", "medium",
                f"Tool '{name}' present in the baseline is gone — server surface changed.",
                f"tools:{name}", "Confirm the removal is expected."))

    if not findings:
        findings.append(Finding(
            "rugpull.unchanged", "info",
            f"All {len(base_tools)} baselined tool definition(s) match — no drift.",
            source, ""))
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.rule))
    return Report(source=source, server_name=baseline.get("server", "unknown"), findings=findings)

"""OWASP Top 10 for Agentic Applications (2026) — taxonomy + mapping.

Released Dec 2025 by the OWASP GenAI Security Project, this is the current
benchmark for autonomous-agent security (systems that plan, decide, and act
across tools and steps). mcpscan maps every finding to one of the ten ASI
categories so a scan report speaks the 2026 standard — alongside the existing
CWE / OWASP-LLM-Top-10 / Microsoft agent-threat mappings.

Reference: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/

The ASI<->finding mapping below is mcpscan's best-fit classification; titles
track the published themes (planning, tool use, identity, supply chain, code
execution, memory, inter-agent comms, cascading failures, human-agent trust,
rogue agents).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class ASIClass:
    id: str
    title: str
    summary: str


CATALOG: tuple[ASIClass, ...] = (
    ASIClass("ASI01", "Agent Planning & Goal Manipulation",
             "Untrusted input bends the agent's plan/goals (prompt & indirect injection driving multi-step actions)."),
    ASIClass("ASI02", "Tool Use & Tool Misuse",
             "Unsafe, over-broad, or poisoned tools — the agent invokes capabilities it shouldn't, or attacker-controlled tool metadata steers it."),
    ASIClass("ASI03", "Identity, Privilege & Delegated Trust",
             "Impersonation, confused-deputy, token passthrough, and over-privileged agent/tool identities."),
    ASIClass("ASI04", "Agent Supply Chain",
             "Compromised servers/packages/skills the agent depends on (rug-pulls, unpinned/poisoned dependencies)."),
    ASIClass("ASI05", "Unsafe Code Execution",
             "Agent-reachable code/command execution — eval/exec, shell, SSRF, path traversal from tool inputs."),
    ASIClass("ASI06", "Memory & Knowledge Poisoning",
             "Persistent memory / RAG / knowledge stores poisoned to corrupt future decisions."),
    ASIClass("ASI07", "Inter-Agent Communication",
             "Trust/abuse across agent-to-agent messaging, tool shadowing, and cross-server influence."),
    ASIClass("ASI08", "Cascading Failures & Unbounded Consumption",
             "One failure/loop amplifies across steps/agents; resource/credit exhaustion and runaway actions."),
    ASIClass("ASI09", "Human-Agent Trust & Oversight",
             "Auto-approval, missing human-in-the-loop, deceptive output, and sensitive-data exposure to/through the user."),
    ASIClass("ASI10", "Rogue & Misaligned Agents",
             "Agents that act outside intended scope — emergent/misaligned behavior, backdoors, untrusted autonomy."),
)

BY_ID = {c.id: c for c in CATALOG}

# Microsoft agent-threat taxonomy -> ASI (primary signal: most precise).
_MS_TO_ASI = {
    "agent-excessive-agency": "ASI02",
    "agent-tool-poisoning": "ASI02",
    "agent-impersonation": "ASI03",
    "agent-confused-deputy": "ASI03",
    "agent-knowledge-poisoning": "ASI06",
    "agent-supply-chain": "ASI04",
    "agent-novel-logic-flaw": "ASI10",
}
# OWASP-LLM-Top-10 -> ASI (fallback when no MS taxonomy).
_LLM_TO_ASI = {
    "LLM01": "ASI01",   # prompt injection -> planning/goal manipulation
    "LLM02": "ASI09",   # sensitive info disclosure -> human-agent trust/exposure
    "LLM03": "ASI04",   # supply chain
    "LLM04": "ASI06",   # data/model poisoning -> memory
    "LLM05": "ASI05",   # improper output handling -> unsafe code execution
    "LLM06": "ASI02",   # excessive agency -> tool misuse
    "LLM07": "ASI03",   # system prompt leakage -> identity/secrets
    "LLM08": "ASI06",   # vector/embedding weaknesses -> memory/knowledge
    "LLM09": "ASI09",   # misinformation -> human-agent trust
    "LLM10": "ASI08",   # unbounded consumption -> cascading/consumption
}
# CWE hints for code-execution-flavored rules with no taxonomy.
_CWE_EXEC = {"CWE-78", "CWE-94", "CWE-95", "CWE-96", "CWE-502", "CWE-918", "CWE-22"}


def asi_for(*, cwe: str = "", owasp_llm: str = "",
            ms_taxonomy: str = "") -> Optional[ASIClass]:
    """Best-fit OWASP Agentic Top-10 (2026) class for a finding's metadata."""
    if ms_taxonomy and ms_taxonomy in _MS_TO_ASI:
        return BY_ID[_MS_TO_ASI[ms_taxonomy]]
    if owasp_llm and owasp_llm in _LLM_TO_ASI:
        return BY_ID[_LLM_TO_ASI[owasp_llm]]
    if cwe in _CWE_EXEC:
        return BY_ID["ASI05"]
    if cwe:                      # any other concrete weakness -> tool misuse bucket
        return BY_ID["ASI02"]
    return None


def asi_label(finding) -> str:
    """Return 'ASI0x' for a Finding-like object, or '' if unmappable."""
    c = asi_for(cwe=getattr(finding, "cwe", "") or "",
                owasp_llm=getattr(finding, "owasp_llm", "") or "",
                ms_taxonomy=getattr(finding, "ms_taxonomy", "") or "")
    return c.id if c else ""

"""PROMPTMIRROR — prompt-injection / LLM-abuse signature scanner.

Scans untrusted text destined for an LLM (user prompts, RAG-retrieved
documents, tool outputs, fetched web pages) for prompt-injection and
LLM-abuse patterns — jailbreaks, role/system hijacks, markdown data
exfiltration, encoding smuggling, and tool-call injection — and maps every
detection to the OWASP Top 10 for LLM Applications (2025).

In the spirit of `leondz/garak` (probe/detector zoo) and `protectai/rebuff`
(layered prompt-injection firewall). Standard library only, zero install.
"""

from .core import (
    Rule,
    Match,
    ScanResult,
    RULES,
    RULES_BY_ID,
    CATEGORIES,
    OWASP_LLM,
    SEVERITY_ORDER,
    scan,
    decode_layers,
    normalize,
)

TOOL_NAME = "promptmirror"
TOOL_VERSION = "2.0.0"

__all__ = [
    "Rule",
    "Match",
    "ScanResult",
    "RULES",
    "RULES_BY_ID",
    "CATEGORIES",
    "OWASP_LLM",
    "SEVERITY_ORDER",
    "scan",
    "decode_layers",
    "normalize",
    "TOOL_NAME",
    "TOOL_VERSION",
]

"""PROMPTMIRROR core — prompt-injection / LLM-abuse signature engine.

Scans untrusted text (user prompts, RAG-retrieved documents, tool outputs,
web pages fed to an agent) for prompt-injection and LLM-abuse patterns, and
maps every detection to the OWASP Top 10 for LLM Applications (2025).

Inspired by the detector philosophy of `leondz/garak` (a probe/detector zoo)
and `protectai/rebuff` (a layered prompt-injection firewall): this module
ships a real, substantial signature library covering jailbreaks, role/system
hijacks, markdown data-exfiltration, encoding smuggling, and tool-call
injection — not toy samples.

Standard library only, zero install. Detection is heuristic and local; it is
meant as a defense-in-depth pre-filter, not a guarantee.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re
import unicodedata
from dataclasses import dataclass, field, asdict
from typing import Iterable

TOOL_NAME = "promptmirror"
TOOL_VERSION = "2.0.0"

# --------------------------------------------------------------------------- #
# Severity model
# --------------------------------------------------------------------------- #
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
_SEV_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# Numeric weights used to combine multiple hits into one 0-100 risk score.
_SEV_WEIGHT = {"info": 2, "low": 8, "medium": 20, "high": 40, "critical": 60}

# OWASP Top 10 for LLM Applications (2025) reference titles.
OWASP_LLM = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM10": "Unbounded Consumption",
}


# --------------------------------------------------------------------------- #
# Rule + finding data model
# --------------------------------------------------------------------------- #
@dataclass
class Rule:
    """A single compiled detection signature."""
    id: str
    name: str
    category: str          # jailbreak | role_hijack | exfil_markdown | encoding | tool_inject | meta
    owasp: str             # e.g. "LLM01"
    severity: str          # info|low|medium|high|critical
    pattern: str           # raw regex source
    description: str
    flags: int = re.IGNORECASE | re.DOTALL
    _rx: re.Pattern | None = field(default=None, repr=False, compare=False)

    def compiled(self) -> re.Pattern:
        if self._rx is None:
            self._rx = re.compile(self.pattern, self.flags)
        return self._rx


@dataclass
class Match:
    rule_id: str
    name: str
    category: str
    owasp: str
    owasp_title: str
    severity: str
    evidence: str          # the matched snippet (trimmed)
    span: tuple[int, int]  # (start, end) in the *decoded* text scanned
    layer: str             # "raw" | "decoded:base64" | "decoded:hex" | ...
    description: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["span"] = list(self.span)
        return d


@dataclass
class ScanResult:
    text_len: int
    matches: list[Match] = field(default_factory=list)
    decoded_layers: list[str] = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        """0-100 aggregated risk. Saturates; multiple hits compound."""
        if not self.matches:
            return 0
        total = 0.0
        # Highest-severity hit gets full weight; subsequent hits add with decay
        for i, m in enumerate(sorted(self.matches,
                                     key=lambda x: -_SEV_RANK[x.severity])):
            total += _SEV_WEIGHT[m.severity] * (0.6 ** i if i else 1.0)
        return min(100, int(round(total)))

    @property
    def verdict(self) -> str:
        s = self.risk_score
        if s >= 70:
            return "block"
        if s >= 35:
            return "flag"
        if s > 0:
            return "review"
        return "clean"

    @property
    def max_severity(self) -> str:
        if not self.matches:
            return "info"
        return max((m.severity for m in self.matches), key=lambda s: _SEV_RANK[s])

    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in SEVERITY_ORDER}
        for m in self.matches:
            c[m.severity] += 1
        return c

    def owasp_breakdown(self) -> dict[str, int]:
        c: dict[str, int] = {}
        for m in self.matches:
            c[m.owasp] = c.get(m.owasp, 0) + 1
        return c

    def to_dict(self) -> dict:
        return {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "text_len": self.text_len,
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "max_severity": self.max_severity,
            "decoded_layers": self.decoded_layers,
            "counts": self.counts(),
            "owasp": self.owasp_breakdown(),
            "matches": [m.to_dict() for m in self.matches],
        }


# --------------------------------------------------------------------------- #
# Bundled signature library
# --------------------------------------------------------------------------- #
def _rules() -> list[Rule]:
    R: list[Rule] = []
    add = lambda *a, **k: R.append(Rule(*a, **k))  # noqa: E731

    # --- Jailbreaks (LLM01) ------------------------------------------------- #
    add("JB-IGNORE", "Ignore previous instructions", "jailbreak", "LLM01", "critical",
        r"\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}?"
        r"\b(?:all\s+)?(?:previous|prior|above|earlier|the\s+system|your)\b"
        r"[^.\n]{0,30}?\b(?:instruction|prompt|rule|direction|guideline|context)s?\b",
        "Classic instruction-override; tries to nullify the system prompt.")
    add("JB-DAN", "DAN / 'Do Anything Now' persona", "jailbreak", "LLM01", "high",
        r"\b(?:you are|act as|pretend to be|from now on)\b[^.\n]{0,40}\bDAN\b"
        r"|\bdo\s+anything\s+now\b|\bDAN\s+mode\b",
        "DAN-style unrestricted-persona jailbreak.")
    add("JB-DEVMODE", "Developer / unrestricted mode", "jailbreak", "LLM01", "high",
        r"\b(?:developer|dev|debug|god|sudo|admin|jailbreak|unrestricted|uncensored)\s+mode\b"
        r"|\benable\s+(?:developer|debug|unrestricted)\b",
        "Requests a fictitious unrestricted/developer mode to bypass guardrails.")
    add("JB-NORULES", "No-rules / no-restrictions framing", "jailbreak", "LLM01", "high",
        r"\b(?:no|without|free\s+(?:of|from)|bypass(?:ing)?|ignore(?:s|d)?)\b"
        r"[^.\n]{0,30}?\b(?:restriction|limitation|filter|guardrail|safety|policy|policies|"
        r"content\s+polic|moderation|ethical)\w*",
        "Asserts the model has no safety restrictions or policies.")
    add("JB-HYPO", "Hypothetical / fiction wrapper", "jailbreak", "LLM01", "medium",
        r"\b(?:hypothetical(?:ly)?|imagine|in\s+a\s+fictional|for\s+a\s+(?:story|novel|movie)|"
        r"roleplay|let'?s\s+pretend)\b[^.\n]{0,60}?"
        r"\b(?:no\s+(?:rules|limits)|anything|illegal|harmful|bypass|unfiltered)\b",
        "Fiction/hypothetical framing used to elicit otherwise-refused content.")
    add("JB-GRANDMA", "Affective social-engineering ('grandma' exploit)", "jailbreak",
        "LLM01", "medium",
        r"\bmy\s+(?:dead\s+|late\s+)?(?:grandm[ao]|grandmother|grandpa)\b"
        r"[^.\n]{0,80}?\b(?:used\s+to|would)\b"
        r"|\bplease\b[^.\n]{0,30}\bi'?ll\s+(?:die|lose\s+my\s+job|tip\s+you)\b",
        "Emotional manipulation to coax restricted output.")
    add("JB-PAYLOAD-SPLIT", "Payload splitting / concatenation evasion", "jailbreak",
        "LLM01", "medium",
        r"\b(?:concatenate|combine|join|append)\b[^.\n]{0,40}\b(?:these|the following|each)\b"
        r"[^.\n]{0,40}\b(?:letters|words|parts|strings|fragments)\b"
        r"|\bstep\s*\d\s*[:=]\s*['\"][a-z ]{1,12}['\"]",
        "Splits a banned phrase across fragments for the model to reassemble.")
    add("JB-REFUSAL-SUPPRESS", "Refusal suppression", "jailbreak", "LLM01", "high",
        r"\b(?:do\s+not|don'?t|never)\b[^.\n]{0,30}\b(?:refuse|say\s+(?:no|you\s+can'?t)|"
        r"apolog|warn|caveat|mention\s+(?:that\s+)?you('?re| are))\b"
        r"|\bnever\s+break\s+character\b|\bstart\s+your\s+(?:reply|answer)\s+with\b",
        "Pre-emptively forbids the model from refusing or warning.")

    # --- Role / system hijack (LLM01 / LLM07) ------------------------------- #
    add("RH-SYSTEM-TAG", "Injected system/role chat tag", "role_hijack", "LLM01", "high",
        r"(?:<\|?(?:im_start|im_end|system|assistant|user)\|?>|\[/?INST\]|"
        r"<<\s*SYS\s*>>|###\s*(?:System|Instruction)\s*:)",
        "Smuggled chat-template / role delimiter to forge a system turn.")
    add("RH-NEWSYS", "You are now / new system prompt", "role_hijack", "LLM01", "high",
        r"\b(?:you\s+are\s+now|your\s+new\s+(?:role|task|instructions?\s+are)|"
        r"new\s+system\s+prompt|system\s*[:=]\s*you\s+are|reprogram(?:med)?)\b",
        "Attempts to replace the assistant's role or system instructions.")
    add("RH-LEAK-SYS", "Request to reveal system prompt", "role_hijack", "LLM07", "high",
        r"\b(?:repeat|print|show|reveal|output|echo|tell\s+me|what\s+(?:are|were)|"
        r"display|dump|spell\s+out)\b[^.\n]{0,40}?"
        r"\b(?:your\s+)?(?:system\s+prompt|initial\s+instruction|"
        r"original\s+(?:prompt|instruction)|prompt\s+above|hidden\s+(?:prompt|instruction)|"
        r"configuration|rules?\s+you\s+(?:were|are)\s+given)s?\b",
        "Tries to exfiltrate the confidential system prompt (LLM07).")
    add("RH-VERBATIM", "Repeat everything above verbatim", "role_hijack", "LLM07", "medium",
        r"\b(?:repeat|print|output|reproduce)\b[^.\n]{0,30}\b(?:everything|all\s+(?:text|the)|"
        r"the\s+(?:above|prior|preceding))\b[^.\n]{0,30}\bverbatim\b"
        r"|\bverbatim\b[^.\n]{0,30}\b(?:above|previous|prior)\b",
        "Asks to echo all prior context verbatim — common prompt-leak primitive.")

    # --- Markdown / link data exfiltration (LLM02 / LLM05) ------------------ #
    add("EX-MD-IMG", "Markdown image exfiltration", "exfil_markdown", "LLM02", "high",
        r"!\[[^\]]*\]\(\s*(?:https?:)?//[^)\s]+[?&/][^)\s]*"
        r"(?:\$\{|\{\{|%7B|<|conversation|history|secret|token|key|prompt|data)[^)]*\)",
        "Auto-rendered markdown image whose URL smuggles data to an attacker host.")
    add("EX-MD-LINK", "Markdown link with templated data", "exfil_markdown", "LLM02", "high",
        r"\[[^\]]*\]\(\s*(?:https?:)?//[^)\s]+\?[^)\s]*"
        r"(?:\$\{|\{\{|%7B|=\s*(?:conversation|history|secret|token|api[_-]?key|prompt))[^)]*\)",
        "Markdown link query-string templated with conversation/secret data.")
    add("EX-IMG-TAG", "HTML img/fetch beacon", "exfil_markdown", "LLM05", "high",
        r"<img\b[^>]*\bsrc\s*=\s*['\"]?\s*(?:https?:)?//[^'\">\s]+\?[^'\">]*"
        r"|\b(?:fetch|XMLHttpRequest|navigator\.sendBeacon)\s*\(\s*['\"]https?://",
        "HTML/JS beacon that exfiltrates rendered context if output is trusted (LLM05).")
    add("EX-URL-TEMPLATE", "URL templated with conversation data", "exfil_markdown",
        "LLM02", "medium",
        r"https?://[^\s)]+[?&][^\s)]*=\s*(?:\$\{?|\{\{)\s*(?:conversation|messages?|history|"
        r"chat|user[_-]?(?:input|data)|secret|token|api[_-]?key)\b",
        "Plain URL whose parameters are templated with sensitive context.")

    # --- Encoding / obfuscation smuggling (LLM01) --------------------------- #
    add("EN-BASE64-INSTR", "Base64-encoded instruction smuggling", "encoding", "LLM01",
        "medium",
        r"\b(?:decode|base64|b64decode|from\s*base\s*64|atob)\b[^.\n]{0,40}"
        r"(?:then|and)?\s*(?:execute|run|follow|do|obey)\b"
        r"|[A-Za-z0-9+/]{40,}={0,2}",
        "References base64 decoding of hidden instructions, or a long base64 blob.")
    add("EN-HEX", "Hex / \\x escaped instruction", "encoding", "LLM01", "low",
        r"(?:\\x[0-9a-f]{2}){8,}|\b0x[0-9a-f]{2}(?:\s+0x[0-9a-f]{2}){7,}",
        "Long run of hex escapes — possible obfuscated instruction payload.")
    add("EN-ROT13", "ROT13 / cipher instruction", "encoding", "LLM01", "low",
        r"\brot[\s-]?13\b|\b(?:caesar|cipher|decipher|decrypt)\b[^.\n]{0,30}"
        r"\b(?:then|and)\b[^.\n]{0,20}\b(?:execute|follow|obey|do)\b",
        "Asks the model to apply a cipher then act on the decoded text.")
    add("EN-LEET", "Leetspeak / spaced obfuscation", "encoding", "LLM01", "low",
        r"\bi\s+g\s*n\s*o\s*r\s*e\b|\b1gn0r3\b|\bd1sr3g4rd\b|\bs\s+y\s+s\s+t\s+e\s+m\b"
        r"|\b3x3cut3\b|\b5y5t3m\b|\bpr0mpt\b",
        "Letter-spaced / leetspeak rendering of a trigger word to dodge filters.")

    # --- Tool-call / function-call injection (LLM06 / LLM05) ---------------- #
    add("TI-CALL", "Direct tool/function call injection", "tool_inject", "LLM06", "high",
        r"\b(?:call|invoke|execute|use|trigger|run)\b[^.\n]{0,30}\b(?:tool|function|api|"
        r"endpoint|plugin|action|skill)\b[^.\n]{0,40}"
        r"(?:\bwith\b|\(|\{|\bargs?\b|\bparam)",
        "Instructs the agent to invoke a tool/function with attacker-chosen args (LLM06).")
    add("TI-JSON", "Forged tool-call JSON block", "tool_inject", "LLM05", "high",
        r'\{\s*["\']?(?:tool_call|function_call|tool|name|recipient_name|action)["\']?\s*:'
        r'[^{}]*["\']?(?:arguments|parameters|input|args)["\']?\s*:',
        "Embeds a structured tool_call/function_call object to hijack agent actions.")
    add("TI-DANGEROUS", "Dangerous action verbs", "tool_inject", "LLM06", "high",
        r"\b(?:send|forward|exfiltrate|email|post|upload|transfer|wire|delete|drop|"
        r"rm\s+-rf|shutdown|disable|grant|escalate)\b[^.\n]{0,40}"
        r"\b(?:all|every|the\s+(?:funds|data|files|secrets|credentials|emails)|"
        r"to\s+(?:attacker|external|https?://))\b",
        "High-impact action verbs targeting funds/data/credentials (excessive agency).")
    add("TI-SHELL", "Shell / code execution request", "tool_inject", "LLM06", "medium",
        r"\b(?:os\.system|subprocess\.|eval\s*\(|exec\s*\(|child_process|"
        r"system\s*\(|`[^`]*\b(?:curl|wget|bash|sh)\b[^`]*`)",
        "Requests host code/shell execution via a code-interpreter tool.")

    # --- Meta / structural anomalies (LLM01 / LLM08) ------------------------ #
    add("MT-INVISIBLE", "Invisible / zero-width Unicode", "meta", "LLM01", "medium",
        r"[​-‏‪-‮⁠-⁤﻿­]",
        "Zero-width or bidi-control characters hiding text from human reviewers.")
    add("MT-TAG-SECTION", "Spoofed instruction section tag", "meta", "LLM08", "low",
        r"(?:</?(?:document|context|data|untrusted|tool_output|retrieved)\s*>|"
        r"\b(?:end\s+of\s+(?:document|context|data)|begin\s+(?:new\s+)?instructions?)\b)",
        "Fake context/document delimiters to break out of a retrieved chunk (LLM08).")
    return R


RULES: list[Rule] = _rules()
RULES_BY_ID = {r.id: r for r in RULES}
CATEGORIES = sorted({r.category for r in RULES})


# --------------------------------------------------------------------------- #
# Decoding layer — surface obfuscated payloads for re-scanning
# --------------------------------------------------------------------------- #
_B64_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}\s*){16,}")


def _try_base64(text: str) -> list[str]:
    out: list[str] = []
    for m in _B64_RE.finditer(text):
        blob = m.group(0)
        if len(blob) % 4:
            blob = blob + "=" * (-len(blob) % 4)
        try:
            dec = base64.b64decode(blob, validate=False)
        except (binascii.Error, ValueError):
            continue
        try:
            s = dec.decode("utf-8")
        except UnicodeDecodeError:
            continue
        # Keep only mostly-printable, word-bearing results
        printable = sum(c.isprintable() or c.isspace() for c in s)
        if len(s) >= 8 and printable / max(1, len(s)) > 0.85 and re.search(r"[a-z]{3}", s, re.I):
            out.append(s)
    return out


def _try_hex(text: str) -> list[str]:
    out: list[str] = []
    for m in _HEX_RE.finditer(text):
        chunk = re.sub(r"\s+", "", m.group(0))
        if len(chunk) % 2:
            chunk = chunk[:-1]
        try:
            dec = bytes.fromhex(chunk).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if re.search(r"[a-z]{3}", dec, re.I):
            out.append(dec)
    return out


def _try_rot13(text: str) -> list[str]:
    dec = codecs.decode(text, "rot_13")
    # Only worth re-scanning if rot13 surfaces a trigger word it didn't before.
    if re.search(r"\b(ignore|system|instruction|execute|prompt)\b", dec, re.I) and \
       not re.search(r"\b(ignore|system|instruction|execute|prompt)\b", text, re.I):
        return [dec]
    return []


def decode_layers(text: str) -> list[tuple[str, str]]:
    """Return [(layer_label, decoded_text), ...] for obfuscation layers found."""
    layers: list[tuple[str, str]] = []
    for s in _try_base64(text):
        layers.append(("decoded:base64", s))
    for s in _try_hex(text):
        layers.append(("decoded:hex", s))
    for s in _try_rot13(text):
        layers.append(("decoded:rot13", s))
    return layers


def normalize(text: str) -> str:
    """NFKC-normalize and strip zero-width chars so confusables can't evade regex.

    (Detection of the raw zero-width chars themselves is handled by MT-INVISIBLE
    on the *original* text; this normalized copy is what content rules scan.)
    """
    norm = unicodedata.normalize("NFKC", text)
    return re.sub(r"[​-‏‪-‮⁠-⁤﻿­]", "", norm)


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #
def _trim(s: str, n: int = 120) -> str:
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def _scan_text(text: str, layer: str, rules: Iterable[Rule]) -> list[Match]:
    found: list[Match] = []
    for rule in rules:
        for m in rule.compiled().finditer(text):
            ev = m.group(0)
            if not ev.strip():
                continue
            found.append(Match(
                rule_id=rule.id, name=rule.name, category=rule.category,
                owasp=rule.owasp, owasp_title=OWASP_LLM.get(rule.owasp, rule.owasp),
                severity=rule.severity, evidence=_trim(ev),
                span=(m.start(), m.end()), layer=layer,
                description=rule.description,
            ))
    return found


def scan(text: str,
         categories: Iterable[str] | None = None,
         min_severity: str = "info",
         decode: bool = True) -> ScanResult:
    """Scan `text` for prompt-injection / LLM-abuse signatures.

    categories   : restrict to these rule categories (default: all)
    min_severity : drop matches below this severity
    decode       : also re-scan base64/hex/rot13-decoded layers
    """
    if text is None:
        text = ""
    cat_set = set(categories) if categories else None
    active = [r for r in RULES
              if (cat_set is None or r.category in cat_set)
              and _SEV_RANK[r.severity] >= _SEV_RANK[min_severity]]

    result = ScanResult(text_len=len(text))

    # 1) Raw text — catches invisible chars / bidi before normalization.
    result.matches.extend(_scan_text(text, "raw", active))

    # 2) Normalized copy — defeats confusable / zero-width evasion.
    norm = normalize(text)
    if norm != text:
        for m in _scan_text(norm, "normalized", active):
            # avoid duplicating identical evidence already seen at raw layer
            if not any(x.rule_id == m.rule_id and x.evidence == m.evidence
                       for x in result.matches):
                result.matches.append(m)

    # 3) Decoded obfuscation layers.
    if decode:
        for label, decoded in decode_layers(norm):
            hits = _scan_text(decoded, label, active)
            if hits:
                result.decoded_layers.append(label)
                result.matches.extend(hits)

    # De-duplicate exact (rule_id, layer, span) collisions, keep stable order.
    seen: set[tuple] = set()
    deduped: list[Match] = []
    for m in result.matches:
        key = (m.rule_id, m.layer, m.span, m.evidence)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(m)
    # Sort: severity desc, then position.
    deduped.sort(key=lambda m: (-_SEV_RANK[m.severity], m.layer, m.span[0]))
    result.matches = deduped
    return result

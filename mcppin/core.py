"""Trust-On-First-Use pinning and drift detection for MCP tool definitions.

An MCP client trusts the tool list a server advertises at connect time: each
tool's ``name``, ``description`` (which the model reads as instructions) and
``inputSchema``. A malicious or compromised server can silently change a tool's
description -- a prompt-injection vector -- or widen its schema *after* the user
has approved it. This is the "tool poisoning" / "rug pull" attack, and a client
that re-reads the tool list on every connection has no way to notice.

``mcppin`` fingerprints a server's tool manifest the first time it is approved
(trust on first use) and verifies every later connection against that pin,
reporting exactly which tools were added, removed, or changed -- and for changed
tools, whether the ``description`` or the ``inputSchema`` drifted.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from typing import Any

# The fields that define a tool's behavioural contract. A change in any of them
# is a change the user agreed to something different than what is now offered.
_FINGERPRINT_FIELDS = ("name", "description", "inputSchema")


def canonical_json(obj: Any) -> str:
    """Serialize ``obj`` deterministically so equal values hash identically."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def tool_fingerprint(tool: dict[str, Any]) -> str:
    """Stable hash over a single tool's name, description, and input schema."""
    subset = {key: tool.get(key) for key in _FINGERPRINT_FIELDS}
    return _sha256(canonical_json(subset))


def schema_fingerprint(tool: dict[str, Any]) -> str:
    """Stable hash over just a tool's ``inputSchema`` (None if absent)."""
    return _sha256(canonical_json(tool.get("inputSchema")))


def manifest_fingerprint(tools: list[dict[str, Any]]) -> str:
    """Order-independent hash over a whole tool manifest.

    Sorting the per-tool fingerprints first means reordering the tool list does
    not register as drift -- only real content changes do.
    """
    return _sha256(canonical_json(sorted(tool_fingerprint(t) for t in tools)))


@dataclass
class DriftReport:
    """Result of verifying a live tool manifest against its pin."""

    server_id: str
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    changed: list[dict[str, Any]] = field(default_factory=list)
    """Each entry is ``{"name": str, "fields": list[str]}`` naming the changed fields."""

    @property
    def is_drift(self) -> bool:
        """True if the live manifest differs from the pin in any way."""
        return bool(self.added or self.removed or self.changed)


def _index_by_name(tools: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {tool.get("name", ""): tool for tool in tools}


class PinStore:
    """A JSON-file-backed set of tool-manifest pins, keyed by server id."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._pins: dict[str, Any] = self._load()

    def _load(self) -> dict[str, Any]:
        if not os.path.exists(self.path):
            return {}
        with open(self.path, encoding="utf-8") as handle:
            return json.load(handle)

    def _save(self) -> None:
        """Write the store atomically so a crash cannot corrupt existing pins."""
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(self._pins, handle, indent=2, sort_keys=True)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    def is_pinned(self, server_id: str) -> bool:
        """Whether ``server_id`` has a stored pin."""
        return server_id in self._pins

    def get(self, server_id: str) -> dict[str, Any]:
        """Return the stored pin record. Raises ``KeyError`` if not pinned."""
        return self._pins[server_id]

    def servers(self) -> list[str]:
        """All pinned server ids."""
        return sorted(self._pins)

    def pin(self, server_id: str, tools: list[dict[str, Any]]) -> dict[str, Any]:
        """Record (or overwrite) the pin for ``server_id`` from ``tools``."""
        record = {
            "manifest": manifest_fingerprint(tools),
            "tools": {
                tool.get("name", ""): {
                    "fingerprint": tool_fingerprint(tool),
                    "schema_fingerprint": schema_fingerprint(tool),
                    "description": tool.get("description"),
                }
                for tool in tools
            },
        }
        self._pins[server_id] = record
        self._save()
        return record

    def verify(self, server_id: str, tools: list[dict[str, Any]]) -> DriftReport:
        """Compare a live manifest against the pin. Raises ``KeyError`` if unpinned."""
        if not self.is_pinned(server_id):
            raise KeyError(server_id)
        pinned_tools: dict[str, Any] = self._pins[server_id]["tools"]
        live = _index_by_name(tools)

        added = sorted(name for name in live if name not in pinned_tools)
        removed = sorted(name for name in pinned_tools if name not in live)

        changed: list[dict[str, Any]] = []
        for name in sorted(set(pinned_tools) & set(live)):
            tool = live[name]
            if tool_fingerprint(tool) == pinned_tools[name]["fingerprint"]:
                continue
            fields: list[str] = []
            if tool.get("description") != pinned_tools[name].get("description"):
                fields.append("description")
            if schema_fingerprint(tool) != pinned_tools[name]["schema_fingerprint"]:
                fields.append("inputSchema")
            changed.append({"name": name, "fields": fields})

        return DriftReport(server_id, added, removed, changed)

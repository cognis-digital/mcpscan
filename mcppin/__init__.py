"""mcppin -- Trust-On-First-Use pinning and drift detection for MCP tool definitions."""

from mcppin.core import (
    DriftReport,
    PinStore,
    canonical_json,
    manifest_fingerprint,
    schema_fingerprint,
    tool_fingerprint,
)

__version__ = "0.1.0"

__all__ = [
    "DriftReport",
    "PinStore",
    "canonical_json",
    "manifest_fingerprint",
    "schema_fingerprint",
    "tool_fingerprint",
    "__version__",
]

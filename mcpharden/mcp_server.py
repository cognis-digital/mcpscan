"""MCPHARDEN MCP server.

Exposes the hardening scanner as an MCP capability over stdio using
newline-delimited JSON-RPC 2.0. Standard library only — no SDK required — so it
runs anywhere Python does and can be wired into Cognis.Studio, Claude Desktop,
or Cursor as a local MCP server:

    {"command": "python", "args": ["-m", "mcpharden", "mcp"]}

Implemented methods:
  * initialize            — handshake, advertises the tools capability
  * tools/list            — describes the `scan` and `audit_manifest` tools
  * tools/call            — runs a tool and returns findings as JSON text

The protocol surface is intentionally small but real: each line on stdin is one
JSON-RPC request; each response is one JSON line on stdout.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    ManifestError,
    audit_manifest,
    scan_to_dict,
)
from . import posture as _posture

PROTOCOL_VERSION = "2024-11-05"

_TOOLS = [
    {
        "name": "scan",
        "description": "Audit an MCP server manifest file or a directory of "
                       "manifests for transport, capability, tooling, and "
                       "secret-exposure weaknesses. Returns prioritized findings.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Path to a manifest JSON file or a directory.",
                }
            },
            "required": ["target"],
            "additionalProperties": False,
        },
    },
    {
        "name": "audit_manifest",
        "description": "Audit an in-memory MCP server manifest object and return "
                       "prioritized hardening findings.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "manifest": {
                    "type": "object",
                    "description": "The MCP server manifest as a JSON object.",
                }
            },
            "required": ["manifest"],
            "additionalProperties": False,
        },
    },
    {
        "name": "posture",
        "description": "Correlate a fleet of MCP servers (a directory of "
                       "manifests) and return cross-server risks a per-server "
                       "audit cannot see: tool-name collisions, shared/reused "
                       "credentials, lateral-movement surface, trust-tier "
                       "inconsistency, and a fleet hardening grade.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Directory (or file) of MCP server manifests.",
                }
            },
            "required": ["target"],
            "additionalProperties": False,
        },
    },
]


def _result(req_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _call_tool(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    if name == "scan":
        target = arguments.get("target")
        if not isinstance(target, str) or not target:
            raise ValueError("`target` (string path) is required")
        payload = scan_to_dict(target)
    elif name == "audit_manifest":
        manifest = arguments.get("manifest")
        if not isinstance(manifest, dict):
            raise ValueError("`manifest` (object) is required")
        payload = audit_manifest(manifest, source="<mcp:inline>").to_dict()
    elif name == "posture":
        target = arguments.get("target")
        if not isinstance(target, str) or not target:
            raise ValueError("`target` (string path) is required")
        payload = _posture.assess(target).to_dict()
    else:
        raise ValueError(f"unknown tool: {name}")

    return {
        "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
        "isError": bool(payload.get("failed")),
    }


def handle_request(req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Dispatch a single JSON-RPC request. Returns None for notifications."""
    method = req.get("method")
    req_id = req.get("id")
    params = req.get("params") or {}

    # Notifications (no id) get no response.
    is_notification = "id" not in req

    if method == "initialize":
        res = _result(req_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": TOOL_NAME, "version": TOOL_VERSION},
        })
        return None if is_notification else res

    if method in ("notifications/initialized", "initialized"):
        return None

    if method == "ping":
        return None if is_notification else _result(req_id, {})

    if method == "tools/list":
        return _result(req_id, {"tools": _TOOLS})

    if method == "tools/call":
        name = params.get("name", "")
        arguments = params.get("arguments") or {}
        try:
            return _result(req_id, _call_tool(name, arguments))
        except (ValueError, OSError, ManifestError) as exc:
            return _error(req_id, -32602, str(exc))
        except Exception as exc:  # pragma: no cover - defensive
            return _error(req_id, -32603, f"internal error: {exc}")

    if is_notification:
        return None
    return _error(req_id, -32601, f"method not found: {method}")


def run_mcp_server(stdin=None, stdout=None) -> None:
    """Read newline-delimited JSON-RPC from stdin, write responses to stdout."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            stdout.write(json.dumps(_error(None, -32700, "parse error")) + "\n")
            stdout.flush()
            continue
        response = handle_request(req)
        if response is not None:
            stdout.write(json.dumps(response) + "\n")
            stdout.flush()


if __name__ == "__main__":
    run_mcp_server()

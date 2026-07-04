"""mcpauth MCP server — exposes token verification + demo as MCP tools.

Standard library only. If the optional ``mcp`` package is installed it builds a
real stdio MCP server; otherwise it still imports cleanly and exposes the same
callable handlers so the tool can be embedded without the dependency.
"""

from __future__ import annotations

import json
from typing import Any, Dict

from mcpauth.core import (
    TOOL_NAME,
    TOOL_VERSION,
    TokenStore,
    decide,
    run_demo,
)


def verify_capability(token: str, tokens_path: str = "tokens.json") -> Dict[str, Any]:
    """Verify a presented Bearer token against a token store on disk."""
    store = TokenStore.load(tokens_path)
    header = f"Bearer {token}" if token else None
    d = decide(header, store)
    return d.to_dict()


def demo_capability() -> Dict[str, Any]:
    """Run the built-in 401-without / 200-with-token demonstration."""
    return run_demo()


def build_mcp_server():
    """Build a stdio MCP server exposing mcpauth capabilities.

    Raises ImportError (with install hint) if the optional `mcp` package is
    not available — mirroring the suite's shared scaffolding behavior.
    """
    try:
        from mcp.server import Server
        from mcp.server.stdio import stdio_server
        from mcp.types import Tool, TextContent
    except ImportError as exc:  # pragma: no cover - optional dep
        raise ImportError("Install with: pip install mcp") from exc

    server = Server(f"cognis-{TOOL_NAME}")

    @server.list_tools()
    async def list_tools():  # pragma: no cover - requires mcp runtime
        return [
            Tool(
                name="mcpauth_verify",
                description=("Verify a Bearer token against a mcpauth token "
                             "store. Part of the Cognis Neural Suite."),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "token": {"type": "string"},
                        "tokens_path": {"type": "string", "default": "tokens.json"},
                    },
                    "required": ["token"],
                    "additionalProperties": False,
                },
            ),
            Tool(
                name="mcpauth_demo",
                description=("Run the built-in 401-without / 200-with-token "
                             "auth-gateway demonstration."),
                inputSchema={"type": "object", "properties": {},
                             "additionalProperties": False},
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: Dict[str, Any]):  # pragma: no cover
        if name == "mcpauth_verify":
            result = verify_capability(
                arguments.get("token", ""),
                arguments.get("tokens_path", "tokens.json"),
            )
        elif name == "mcpauth_demo":
            result = demo_capability()
        else:
            result = {"error": f"unknown tool: {name}"}
        return [TextContent(type="text", text=json.dumps(result, indent=2))]

    def run_mcp_server(transport: str = "stdio") -> None:  # pragma: no cover
        import asyncio

        async def _run():
            async with stdio_server() as (rs, ws):
                await server.run(rs, ws, server.create_initialization_options())

        asyncio.run(_run())

    return run_mcp_server


if __name__ == "__main__":  # pragma: no cover
    build_mcp_server()()

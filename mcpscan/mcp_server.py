"""mcpscan MCP server — exposes scan as an MCP capability for Cognis.Studio."""
from mcpscan.core import scan, TOOL_NAME

try:
    from cognis_core.mcp import build_mcp_server

    run_mcp_server = build_mcp_server(
        tool_name=TOOL_NAME,
        description="Scan MCP servers for RCE/SSRF/no-auth/tool-poisoning "
                    "vulnerabilities (static source + live endpoint probe)",
        scan_fn=scan,
        extra_params={
            "endpoint": {"type": "string",
                         "description": "Live HTTP MCP endpoint URL to probe"},
            "token": {"type": "string",
                      "description": "Optional bearer token for the endpoint"},
        },
    )
except Exception:  # pragma: no cover - cognis_core/mcp optional at runtime
    def run_mcp_server(transport: str = "stdio") -> None:
        raise ImportError(
            "MCP server scaffolding unavailable. Install the suite's "
            "cognis_core package and the `mcp` extra: pip install mcp")

if __name__ == "__main__":  # pragma: no cover
    run_mcp_server()

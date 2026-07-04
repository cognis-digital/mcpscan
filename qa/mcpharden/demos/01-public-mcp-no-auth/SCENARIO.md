# Scenario: Public MCP server with zero hardening

Worst-case MCP deployment: HTTP, no auth, no capability scoping, vague tool descriptions.

## Expected findings

- MH-CAP-001 (no scopes)
- MH-NET-001 (HTTP transport)
- MH-AUTH-001 (no auth)
- MH-DESC-001 × 2 (vague descriptions)

## Why this matters

Direct attack path: any LLM that connects executes anything. Real-world MCP servers have been deployed like this in 2025.

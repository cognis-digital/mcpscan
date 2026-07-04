# Scenario: Multi-server fleet scan

Scan a directory of MCP server definitions. Surfaces only the misconfigured ones.

## Expected findings

- github-mcp has MH-NET-001 + MH-AUTH-001
- slack-mcp clean

## Why this matters

Use in CI: scan a /mcp directory at every commit.

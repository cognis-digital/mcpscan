# Scenario: RAG corpus poisoned with structured tool-call directives

An attacker inserts fake MCP/function-call markers into an exported wiki page. When a code-completion agent retrieves this for context, naive markdown rendering or aggressive tool dispatchers could execute them.

## Expected findings

- PM-TOOL-001 × 2 (tool_use and function_call directives)

## Why this matters

Anthropic, OpenAI, and Google have all warned about indirect tool-call smuggling in 2024-2025. Discovery from a corp wiki export is realistic and dangerous.

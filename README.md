<div align="center">

# mcpscan

**The security suite for your MCP servers.** Scan, harden, gate, and pin every Model Context Protocol server your agents talk to — from one command, fully offline.

[![PyPI](https://img.shields.io/pypi/v/cognis-mcpscan.svg)](https://pypi.org/project/cognis-mcpscan/)
[![CI](https://github.com/cognis-digital/mcpscan/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/mcpscan/actions)
[![License: COCL 1.0](https://img.shields.io/badge/license-COCL%201.0-blue.svg)](LICENSE)
![Modules](https://img.shields.io/badge/modules-7-informational)
![Deps](https://img.shields.io/badge/runtime%20deps-none%20(stdlib)-success)

</div>

MCP is a brand-new attack surface: unauthenticated servers, tools that shell out, URL fetchers that can be turned into SSRF, tool descriptions that carry prompt injection, and *config trust settings that auto-approve remote code*. `mcpscan` finds those problems across a whole fleet of servers — and tells you exactly how to fix each one.

```bash
pip install cognis-mcpscan
mcpscan scan .              # audit the MCP servers configured on this machine
```

No cloud, no telemetry, no runtime dependencies — it runs on the stdlib and everything stays on your box.

## See it work

`mcpscan harden posture` over a fleet of four servers surfaces problems **no single-server scan can see** — shared credentials, lateral-movement paths, tool-name collisions, and inconsistent trust tiers across the fleet:

```console
$ mcpscan harden posture ./fleet --format table
MCPHARDEN fleet posture — ./fleet
========================================================================
4 server(s), 3 network-reachable.  Fleet score: 0/100  (grade F)
------------------------------------------------------------------------
  [FAIL]   0/100  net   http    files-mcp
  [FAIL]  20/100  net   sse     weather-mcp
  [FAIL]  60/100  net   http    github-mcp
  [PASS] 100/100  local stdio   jira-mcp
------------------------------------------------------------------------
CROSS-SERVER CORRELATIONS (6):
[CRIT] fleet.shared_secret
    The same embedded credential (sk_live_…) appears in 2 manifests
    (files-mcp, github-mcp); compromise of any one server exposes a
    credential whose blast radius is the whole fleet.
    fix: Move it to a per-server secret store with distinct,
         least-privilege, independently-rotatable tokens.
[HIGH] fleet.lateral_movement
    files-mcp exposes RCE-prone tools while 2 reachable peers are
    under-protected; code-exec on one host pivots to the peers — a
    lateral-movement surface no single manifest reveals.
[HIGH] fleet.tool_collision
    Tool 'read_file' is registered by 2 servers; the agent cannot
    disambiguate which runs — the precondition for tool shadowing.
```

Every finding ships with a severity, the exact location, and a concrete remediation. Findings emit as human-readable, JSON, HTML, or SARIF (straight into GitHub's Security tab).

## Why mcpscan

| | manual review | single-purpose scripts | **mcpscan** |
|---|:---:|:---:|:---:|
| RCE / tool-poisoning detection | ⚠️ error-prone | partial | ✅ |
| SSRF probing (consent-gated) | ✗ | ✗ | ✅ |
| Prompt-injection in tool descriptions | ✗ | ✗ | ✅ |
| Drop-in auth for unauth'd servers | ✗ | ✗ | ✅ |
| Definition pinning / drift detection | ✗ | ✗ | ✅ |
| **Cross-server fleet correlations** | ✗ | ✗ | ✅ |
| Runs offline, zero deps | — | varies | ✅ |
| CI / SARIF / SIEM output | ✗ | rare | ✅ |

## The seven modules

One install, one command, seven focused tools — run `mcpscan <module> --help` for each:

| Module | Command | What it does |
|---|---|---|
| **scan** | `mcpscan scan` | Static audit for RCE, SSRF sinks, no-auth, and tool-poisoning |
| **harden** | `mcpscan harden` | Posture linter + fleet scoring (capability, transport, tool safety) |
| **auth** | `mcpscan auth` | Drop-in token-auth gateway in front of unauthenticated servers |
| **pin** | `mcpscan pin` | Trust-On-First-Use pinning + drift detection for tool definitions |
| **ssrf** | `mcpscan ssrf` | Consent-gated SSRF probe for servers that fetch URLs |
| **prompt** | `mcpscan prompt` | Prompt-injection & indirect-injection scanner for any LLM context |
| **trust** | `mcpscan trust` | Detect symlink-hijack / one-click-RCE / unsafe auto-approve settings |

Each module is also installed as its own command (`mcpharden`, `mcpauth`, `ssrfmcp`, …) so existing scripts keep working.

## Integrations

- **CI/CD** — non-zero exit on findings + SARIF upload; a ready-to-use GitHub Action is in `action.yml`.
- **SIEM / SOAR** — `mcpscan-emit` streams findings in the [cognis-connect](https://github.com/cognis-digital/cognis-connect) Finding contract (Splunk, Elastic, Slack, STIX/MISP).
- **MCP-native** — install the `[mcp]` extra to expose the scanners as MCP tools your own agent can call.

## What it detects

Tool-poisoning and description injection · unauthenticated network transports · RCE-capable tools on reachable hosts · SSRF-prone URL fetchers · shared/embedded credentials · tool-name collisions (confused-deputy routing) · unsafe client trust settings (auto-approve, symlink-hijack, one-click-RCE) · definition drift / rug-pulls after first use.

## Install

```bash
pip install cognis-mcpscan            # core, stdlib only
pip install "cognis-mcpscan[mcp]"     # + expose scanners as MCP tools
pip install "cognis-mcpscan[connect]" # + SIEM/Slack/STIX emitters
```

Requires Python 3.10+. Runs on Windows, macOS, and Linux.

## Defensive use

`mcpscan` is a defensive tool for MCP servers **you operate or are authorized to assess**. The `ssrf` probe is consent-gated and refuses to run without an explicit authorization flag. Use it on your own infrastructure or under a written engagement.

## License

[COCL 1.0](LICENSE) — Cognis Open Collaboration License. See [DISCLAIMER.md](DISCLAIMER.md).

<div align="center"><sub>Part of the <a href="https://github.com/cognis-digital">Cognis</a> security tooling.</sub></div>

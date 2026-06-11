# mcpscan — Scan MCP servers for RCE/SSRF/no-auth/tool-poisoning vulnerabilities

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> Cognis Open Collaboration License (COCL) v1.0 · domain: `ai-security`

[![PyPI](https://img.shields.io/pypi/v/cognis-mcpscan.svg)](https://pypi.org/project/cognis-mcpscan/)
[![CI](https://github.com/cognis-digital/mcpscan/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/mcpscan/actions)
[![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE)
[![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

**A vulnerability scanner for Model Context Protocol (MCP) servers.** It finds
remote-code-execution sinks, SSRF, missing authentication, and tool-poisoning
prompt-injection — statically from source *and* by probing a live endpoint.

*AI Security & Governance — securing LLMs, agents, and the MCP supply chain.*

## What it detects

**Static** (point it at a directory/file of MCP server source):

- **RCE / command exec** — `eval`, `exec`, `os.system`, `os.popen`,
  `subprocess(..., shell=True)`, and JS `child_process.exec`, `eval`,
  `new Function`, `spawn({shell:true})`. Python is parsed with the `ast`
  module (taint-aware: a dynamic argument is *critical*, a string literal is
  *high*); JS/TS is swept with regex.
- **SSRF** — outbound HTTP (`requests`, `urllib`, `httpx`, `fetch`, `axios`,
  `got`, …) whose URL argument is built from a variable rather than a literal.
- **Tool poisoning** — prompt-injection / instruction-smuggling text inside
  tool docstrings, `description=` kwargs, and JS description strings.

**Live** (probe a running HTTP MCP endpoint over `urllib`):

- **Missing authentication** — issues an unauthenticated `tools/list`; a `2xx`
  answer is flagged critical (`live.no_auth`).
- **Cleartext transport** — plain `http://` endpoints (`live.no_tls`).
- **Overly-broad capabilities** — destructive tools reachable without auth,
  tools with no input schema, and `additionalProperties: true` schemas.

## Install

```bash
pip install cognis-mcpscan
# or, from this repo:
pip install -e ".[dev]"
```

Standard-library only — no runtime dependencies.

## Quick start

```bash
mcpscan --version
mcpscan scan demos/01-basic/                                  # static scan a dir
mcpscan scan path/to/server.py --format sarif --out r.sarif   # SARIF for code-scanning
mcpscan scan path/to/server/ --fail-on high                   # CI gate (exits 1)
mcpscan probe http://127.0.0.1:8080/mcp --fail-on high        # live no-auth probe
mcpscan probe https://mcp.example.com/mcp --token "$TOKEN"    # authenticated probe
```

## Output formats

- **Table** (default) — human-readable terminal summary with a 0-100 score.
- **JSON** — machine-readable findings for pipelines (`--format json`).
- **SARIF 2.1.0** — drops into GitHub code-scanning / IDE problem panes
  (`--format sarif`).

`--fail-on {critical,high,medium,low,info}` makes the process exit `1` when any
finding is at or above the given severity — wire it straight into CI.

## Demo

See [`demos/01-basic/SCENARIO.md`](demos/01-basic/SCENARIO.md). It ships a
deliberately-vulnerable FastMCP server and shows the five vulnerability classes
mcpscan flags (and one clean tool it correctly leaves alone).

## Use as an MCP server

Every Cognis Neural Suite tool ships an MCP server so agents can call it as a
scoped capability:

```bash
python -m mcpscan.mcp_server     # requires the `mcp` extra + cognis_core
```

## How it fits the Cognis Neural Suite

`mcpscan` is one tool in the [Cognis Neural Suite](https://github.com/cognis-digital).
It pairs naturally with [`mcpharden`](https://github.com/cognis-digital/mcpharden)
(manifest hardening linter): `mcpharden` audits the declared manifest, `mcpscan`
audits the actual source + running endpoint.

## License

Source-available under the **Cognis Open Collaboration License (COCL) v1.0** —
free for personal, internal-evaluation, research, and educational use;
**commercial / production use requires a license** (licensing@cognis.digital).
See [LICENSE](LICENSE).

## Responsible use

This is dual-use security software. Use it only against systems, data, and
identities you own or are explicitly authorized in writing to test, and in
compliance with applicable law.

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow
Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*

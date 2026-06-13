# mcpscan — Scan MCP servers for RCE/SSRF/no-auth/tool-poisoning vulnerabilities

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> Cognis Open Collaboration License (COCL) v1.0 · domain: `ai-security`

[![install](https://img.shields.io/badge/install-git%2B%20%C2%B7%20pipx%20%C2%B7%20uv-6b46c1.svg)](#install--every-way-every-platform)
[![CI](https://github.com/cognis-digital/mcpscan/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/mcpscan/actions)
[![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE)
[![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)

**A vulnerability scanner for Model Context Protocol (MCP) servers and the
agents that drive them.** It maps findings to the **OWASP LLM Top-10**, a
**CWE** id, and the **Microsoft agent-threat taxonomy** — statically from
source (with real AST taint dataflow), by probing a live endpoint, by fetching
a remote GitHub URL, and via an **opt-in AI review layer**.

*AI Security & Governance — securing LLMs, agents, and the MCP supply chain.*

<!-- cognis:layman:start -->
## What is this?

mcpscan is a security scanner for MCP (Model Context Protocol) servers — the software plugins that let AI assistants like Claude access tools, files, and external services. It checks your MCP server code for dangerous security holes such as remote code execution, unauthorized access, and hardcoded passwords, then gives you a plain report listing exactly what it found and how to fix it. You can point it at a folder of source code, a live running server, or even a public GitHub link, and it works entirely on your own machine with no cloud service required. It is aimed at developers and security teams who build or deploy AI-connected tools and want to catch vulnerabilities before attackers do.
<!-- cognis:layman:end -->

## What it detects

**Static** (point it at a directory/file of MCP server source):

- **RCE / command exec** — `eval`, `exec`, `os.system`, `os.popen`,
  `subprocess(..., shell=True)`, and JS `child_process.exec`, `eval`,
  `new Function`, `spawn({shell:true})`. Python is parsed with the `ast` module.
- **AST TAINT dataflow** — real **source → sink** tracking for Python: a tool
  argument or `request.*` source that flows (through variables, f-strings,
  concatenation, `.format()`) into a command/eval/SSRF/path/deserialize sink is
  flagged `taint.*` even when the source and sink are on *different lines* — not
  just a single-line signature match.
- **SSRF** — outbound HTTP (`requests`, `urllib`, `httpx`, `fetch`, `axios`, …)
  with a non-literal URL (`CWE-918`).
- **Path traversal** — file ops (`open`, `os.remove`, `fs.*`, `send_file`) on a
  dynamic path (`CWE-22`).
- **Insecure deserialization** — `pickle`/`yaml.load`/`marshal`/`dill` on
  untrusted data (`CWE-502`); `yaml.safe_load` is recognized as safe.
- **SSTI** — templates compiled from user input (`jinja2.Template`,
  `render_template_string`, handlebars/ejs/pug) (`CWE-1336`).
- **Secret exposure** — hard-coded AWS / GitHub / Slack / OpenAI / Google keys
  and private-key blocks (`CWE-798`).
- **MCP / agent classes** — **tool poisoning** (prompt-injection in tool
  descriptions/docstrings), **confused-deputy / token passthrough** (forwarding
  an inbound `Authorization` header or token to a downstream call), **excessive
  agency** (unconfirmed destructive tools), and **rug-pull / version drift**
  (unpinned `requirements.txt` / floating `package.json` deps).
- **Shell tool runs user input** — a tool/function that feeds one of its own
  parameters into a shell subprocess (`subprocess(..., shell=True)`,
  `os.system`/`os.popen`) is flagged `static.shell_tool_input` (`CWE-78`,
  OWASP-LLM `LLM06`) via a confined per-function AST pass.

**MCP config hygiene** (JSON client/server config — `.mcp.json`, `mcp.json`,
`claude_desktop_config.json`, …, auto-discovered by `scan`):

- **Hard-coded bearer / secret in config** — a baked-in credential in a
  server's `env`, `headers`, or `args` (`config.hardcoded_secret`, `CWE-798`,
  `LLM02`). Env-var placeholders (`${VAR}`) are recognized as clean.
- **Server bound to `0.0.0.0` with no auth** — a listener on all interfaces
  with no authentication in the same file (`config.open_bind_no_auth`,
  `CWE-306`, `LLM06`).
- **Remote transport without TLS** — a non-loopback MCP transport URL over
  cleartext `http://` (`config.no_tls_remote`, `CWE-319`, `LLM02`); loopback
  and `https://` are clean.

**Live** (probe a running HTTP MCP endpoint over `urllib`):

- **Missing authentication** (`live.no_auth`), **cleartext transport**
  (`live.no_tls`), and **overly-broad capabilities** — destructive tools
  reachable without auth, tools with no input schema, and
  `additionalProperties: true` schemas.

**Remote** — `mcpscan scan-url <github-or-raw-url>` fetches a public MCP server
file over `urllib` (auto-normalizing `github.com/.../blob/...` to raw) and scans
it without cloning.

<!-- cognis:domains:start -->
## Domains

**Primary domain:** Cyber & Security  ·  **JTF MERIDIAN division:** NULLBYTE · SPECTER

**Topics:** `cognis` `security` `infosec` `cybersecurity` `blue-team` `mcp` `agent-security`

Part of the **Cognis Neural Suite** — 300+ source-available tools organized across 12 domains under the JTF MERIDIAN command structure. See the [suite on GitHub](https://github.com/cognis-digital) and [jtf-meridian](https://github.com/cognis-digital/jtf-meridian) for how the pieces fit together.
<!-- cognis:domains:end -->

<!-- cognis:install:start -->
## Install

`mcpscan` is source-available (not published to PyPI) — every method below installs
straight from GitHub. Pick whichever you prefer; the one-line scripts auto-detect
the best tool available on your machine.

**One-liner (Linux / macOS):**
```sh
curl -fsSL https://raw.githubusercontent.com/cognis-digital/mcpscan/HEAD/install.sh | sh
```

**One-liner (Windows PowerShell):**
```powershell
irm https://raw.githubusercontent.com/cognis-digital/mcpscan/HEAD/install.ps1 | iex
```

**Or install manually — any one of:**
```sh
pipx install "git+https://github.com/cognis-digital/mcpscan.git"     # isolated (recommended)
uv tool install "git+https://github.com/cognis-digital/mcpscan.git"  # uv
pip install "git+https://github.com/cognis-digital/mcpscan.git"      # pip
```

**From source:**
```sh
git clone https://github.com/cognis-digital/mcpscan.git
cd mcpscan && pip install .
```

Then run:
```sh
mcpscan --help
```
<!-- cognis:install:end -->

## Install

```bash
pip install "git+https://github.com/cognis-digital/mcpscan.git"
# or, from this repo:
pip install -e ".[dev]"
```

Standard-library only — no runtime dependencies.

## Quick start

```bash
mcpscan --version
mcpscan scan demos/01-basic/                                  # static scan a dir
mcpscan scan demos/02-deep/                                   # deep rule pack + taint
mcpscan scan demos/03-config/                                 # MCP config hygiene + shell-tool input
mcpscan scan path/to/server.py --format sarif --out r.sarif   # SARIF for code-scanning
mcpscan scan path/to/server.py --format html  --out r.html    # self-contained HTML report
mcpscan scan path/to/server.py --format badge                 # shields.io endpoint JSON
mcpscan scan path/to/server/ --fail-on high                   # CI gate (exits 1)
mcpscan scan-url https://github.com/owner/repo/blob/main/server.py   # scan a remote file
mcpscan scan path/to/server/ --ai                             # opt-in AI review layer
mcpscan probe http://127.0.0.1:8080/mcp --fail-on high        # live no-auth probe
mcpscan probe https://mcp.example.com/mcp --token "$TOKEN"    # authenticated probe
```

## Output formats

- **Table** (default) — human-readable terminal summary with a 0-100 score and
  the CWE / OWASP / MS-taxonomy tags per finding.
- **JSON** — machine-readable findings for pipelines (`--format json`).
- **SARIF 2.1.0** — drops into GitHub code-scanning / IDE problem panes; rule
  metadata carries `cwe`, `owasp-llm`, and `ms-agent-taxonomy` (`--format sarif`).
- **HTML** — a clean, self-contained (no external assets) report you can attach
  to a PR or email (`--format html`).
- **Badge** — a [shields.io endpoint](https://shields.io/badges/endpoint-badge)
  JSON object `{schemaVersion,label,message,color}` so you can show a live
  status badge (`--format badge`).

`--fail-on {critical,high,medium,low,info}` makes the process exit `1` when any
finding is at or above the given severity — wire it straight into CI.

### Status badge

Publish the badge JSON somewhere reachable (e.g. commit it, or push it to a
gist) and point a shields.io endpoint badge at it:

```bash
mcpscan scan . --format badge --out mcpscan-badge.json
```

```markdown
![mcpscan](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/OWNER/REPO/main/mcpscan-badge.json)
```

## Opt-in AI review (`--ai`)

`--ai` is **OFF by default** — without it, mcpscan is **byte-for-byte
deterministic**. When enabled, mcpscan runs the same source through a local
**Cognis fleet** LLM backend (OpenAI-compatible llama.cpp / Ollama — nothing
leaves the box) to surface *novel* logic flaws beyond the signature rules. AI
findings are merged tagged `source="ai"` (and `novel` where applicable) and
de-duped against the rule findings by CWE + line.

```bash
export COGNIS_AI_BACKEND=uncensored-fleet     # or COGNIS_AI_ENDPOINT=http://127.0.0.1:8774/v1
mcpscan scan path/to/server/ --ai
```

If `--ai` is given but the backend is unconfigured or unreachable, mcpscan
prints a clear note and continues with the deterministic rule findings — it
**never crashes**.

## CI / GitHub Action

mcpscan ships a reusable Action. Add it to any MCP server repo and every PR is
scanned, the findings table is posted as a PR comment, and the build fails on
your chosen severity:

```yaml
# .github/workflows/mcpscan-action.yml
name: mcpscan
on: [push, pull_request]
permissions:
  contents: read
  pull-requests: write
jobs:
  mcpscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cognis-digital/mcpscan@main
        with:
          path: .
          fail-on: high
          comment-pr: "true"   # comments findings on the PR via gh api
          # ai: "false"        # opt-in; set COGNIS_AI_* env to enable
```

That single `uses: cognis-digital/mcpscan@main` step is all a consumer needs.

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

<a name="verification"></a>
## Verification

[![tests](https://img.shields.io/badge/tests-77%20passing-2ea44f.svg)](AUDIT.md)

Every push is verified end-to-end. Latest audit (2026-06-13):

```text
tests        : 77 passed, 0 failed, 0 errored
compile      : all modules parse
cli          : C:\Python314\python.exe: No module named https
package      : https
```

<details><summary>CLI surface (<code>--help</code>)</summary>

```text
C:\Python314\python.exe: No module named https
```
</details>

Full machine-readable results: [`AUDIT.md`](AUDIT.md) · regenerate with `python -m https --help` + `pytest -q`.

<div align="right"><a href="#top">↑ back to top</a></div>


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

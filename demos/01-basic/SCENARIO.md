# Demo 01 — Scanning a vulnerable MCP server

This scenario runs `mcpscan` against `vulnerable_mcp_server.py`, a small but
deliberately insecure Python MCP server (built on FastMCP). Every issue below
is intentional so you can see the scanner light up.

## Run it

```bash
# human-readable table
python -m mcpscan scan demos/01-basic/vulnerable_mcp_server.py

# machine-readable JSON for pipelines
python -m mcpscan scan demos/01-basic/vulnerable_mcp_server.py --format json

# SARIF for GitHub code-scanning / IDE problem panes
python -m mcpscan scan demos/01-basic/vulnerable_mcp_server.py --format sarif --out mcpscan.sarif

# gate CI on high+ findings (exits 1)
python -m mcpscan scan demos/01-basic/vulnerable_mcp_server.py --fail-on high
```

## What it should catch

| Sink / pattern                                   | Rule                       | Severity |
|--------------------------------------------------|----------------------------|----------|
| `subprocess.run(cmd, shell=True)` on user input  | `static.subprocess_shell`  | critical |
| `eval(expr)` on user input                       | `static.dynamic_eval`      | critical |
| `os.system("rm -rf " + path)`                    | `static.command_exec`      | critical |
| `urllib.request.urlopen(url)` on user input      | `static.ssrf`              | high     |
| tool `description=` smuggling hidden instructions| `static.tool_poisoning`    | critical |

Because critical/high findings are present, `--fail-on high` exits non-zero,
failing any CI gate that wraps it. The bundled `safe_echo` tool is clean and
produces no findings — proving the scanner does not just flag everything.

## Probing a live endpoint

If you have a running HTTP MCP server, point the live probe at it:

```bash
python -m mcpscan probe http://127.0.0.1:8080/mcp --fail-on high
python -m mcpscan probe https://mcp.example.com/mcp --token "$MCP_TOKEN"
```

The probe issues an unauthenticated `tools/list` and flags **missing
authentication** (`live.no_auth`), cleartext transport (`live.no_tls`), and
destructive tools reachable without auth (`live.dangerous_capability`).

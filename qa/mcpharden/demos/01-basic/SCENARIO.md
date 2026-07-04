# Demo 01 — Auditing a leaky MCP server

This scenario runs MCPHARDEN against `weather-server.json`, a realistic but
deliberately under-hardened MCP server manifest.

## Run it

```bash
python -m mcpharden audit demos/01-basic/weather-server.json
# machine-readable output:
python -m mcpharden audit demos/01-basic/weather-server.json --format json
# gate a CI pipeline on high+ findings only:
python -m mcpharden audit demos/01-basic/weather-server.json --min-severity high
```

## What it should catch

The manifest looks innocuous — a weather server — but contains several
real hardening failures:

| Domain      | Issue                                                                 | Severity |
|-------------|-----------------------------------------------------------------------|----------|
| Transport   | HTTP transport bound to `0.0.0.0` (reachable off-host)                | critical |
| Transport   | No TLS on a network transport                                         | high     |
| Transport   | No auth declared — anyone who reaches the port can call tools         | high     |
| Capability  | Exposes tools but does not advertise `capabilities.tools`             | high     |
| Tooling     | `delete_cache` is side-effecting but has no input schema              | high     |
| Tooling     | `delete_cache` does not request confirmation                          | medium   |
| Tooling     | `get_forecast` has no description                                     | medium   |
| Secrets     | An API key is hard-coded in the manifest                             | critical |

Because critical/high findings are present, the process exits non-zero,
failing any CI gate that wraps it.

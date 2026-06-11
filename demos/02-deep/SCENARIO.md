# Demo 02 — Deep detection: OWASP LLM Top-10 + MCP/agent classes + taint

This scenario runs `mcpscan` against `vulnerable_agent_server.py`, which packs
the vulnerability classes added in v0.2 — including a **multi-line tainted
dataflow** that only real source->sink analysis (not a single-line regex) can
catch.

## Run it

```bash
python -m mcpscan scan demos/02-deep/vulnerable_agent_server.py
python -m mcpscan scan demos/02-deep/vulnerable_agent_server.py --format html --out report.html
python -m mcpscan scan demos/02-deep/vulnerable_agent_server.py --format badge
```

## What it should catch

| Pattern                                              | Rule                          | CWE      | OWASP |
|------------------------------------------------------|-------------------------------|----------|-------|
| `pickle.loads(blob)` on attacker bytes               | `static.deserialization`      | CWE-502  | LLM05 |
| `Template("Hello " + name).render()`                 | `static.ssti`                 | CWE-1336 | LLM05 |
| `open(filename)` on a dynamic path                   | `static.path_traversal`       | CWE-22   | LLM06 |
| `OPENAI_KEY = "sk-…"` hard-coded                      | `static.secret_exposure`      | CWE-798  | LLM02 |
| forwarding the inbound `Authorization` header        | `static.confused_deputy`      | CWE-441  | LLM06 |
| `cmd = "…" + target; subprocess.run(cmd, shell=True)`| `taint.command_injection`     | CWE-78   | LLM06 |

The last row is the headline: `target` is a tool argument (attacker-controlled),
flows into `cmd` on one line, and reaches a shell sink on another. The AST
**taint engine** tracks that dataflow across statements — a regex that only
looks at the `subprocess.run` line would miss the source.

Every finding is tagged with its **CWE**, its **OWASP LLM Top-10** category, and
the **Microsoft agent-threat taxonomy** bucket, so the output drops straight
into a governance report.

## Opt-in AI layer

```bash
# OFF by default — deterministic. Turn on the local Cognis fleet reviewer:
export COGNIS_AI_BACKEND=uncensored-fleet     # or COGNIS_AI_ENDPOINT=...
python -m mcpscan scan demos/02-deep/vulnerable_agent_server.py --ai
```

If the backend is unreachable, mcpscan prints a note and continues with the
deterministic rule findings — it never crashes.

## Scan a remote MCP server straight from GitHub

```bash
python -m mcpscan scan-url https://github.com/owner/repo/blob/main/server.py --fail-on high
```

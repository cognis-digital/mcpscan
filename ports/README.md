# mcpscan language ports

Minimal, self-contained ports of mcpscan's **core passive check** — the
offline analysis of a captured MCP `tools/list` response that flags:

* **dangerous capabilities** — tools whose name/description advertise a
  destructive or side-effecting verb (delete, drop, exec, wipe, …);
* **tool poisoning** — prompt-injection text embedded in a tool description
  (`ignore previous instructions`, `exfiltrate`, …);
* **open schema** — `additionalProperties: true` on a tool input schema.

These ports are **passive and offline by design** — they read a JSON capture
from stdin or a file and emit findings. They do **no** network I/O, so there
is nothing to authorization-gate here; the gated ACTIVE probe lives only in
the full Python tool.

| Port | Location | Build / test |
|------|----------|--------------|
| Go         | `ports/go`   | `go test ./...` |
| Rust       | `ports/rust` | `cargo test` |
| TypeScript | `ports/ts`   | `npm ci && npm test` |

> The Go and Rust toolchains are **not** verified locally — they are built and
> tested on GitHub Actions runners (see `.github/workflows/ports.yml`). The
> Python core is the reference implementation and is locally test-green.

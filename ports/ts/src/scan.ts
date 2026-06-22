// Minimal TypeScript port of mcpscan's core PASSIVE check: offline analysis
// of a captured MCP tools/list response. No network I/O.

export const CRITICAL = "critical";
export const HIGH = "high";
export const MEDIUM = "medium";

export const DANGEROUS_VERBS = [
  "delete", "remove", "drop", "wipe", "destroy", "exec", "execute", "shell",
  "command", "spawn", "kill", "format", "overwrite", "truncate", "rm ",
  "rmdir", "unlink", "purge", "erase",
];

export const INJECTION_MARKERS = [
  "ignore previous instructions", "ignore all previous", "disregard previous",
  "exfiltrate", "system prompt", "send to", "leak", "override your",
  "you are now",
];

export interface Finding {
  rule: string;
  severity: string;
  message: string;
  location: string;
}

interface Tool {
  name?: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
  input_schema?: Record<string, unknown>;
}

function sevRank(s: string): number {
  switch (s) {
    case CRITICAL: return 0;
    case HIGH: return 1;
    case MEDIUM: return 2;
    default: return 4;
  }
}

function containsAny(hay: string, needles: string[]): boolean {
  return needles.some((n) => hay.includes(n));
}

// Extract the tool list from a capture: JSON-RPC envelope, bare
// {"tools":[...]}, or a top-level array.
export function extractTools(v: unknown): Tool[] {
  if (Array.isArray(v)) return v as Tool[];
  if (v && typeof v === "object") {
    const obj = v as Record<string, unknown>;
    const result = obj["result"] as Record<string, unknown> | undefined;
    if (result && Array.isArray(result["tools"])) return result["tools"] as Tool[];
    if (Array.isArray(obj["tools"])) return obj["tools"] as Tool[];
  }
  return [];
}

export function assess(v: unknown): Finding[] {
  const out: Finding[] = [];
  for (const tool of extractTools(v)) {
    const nameRaw = (tool.name ?? "").trim();
    const name = nameRaw || "<unnamed>";
    const desc = (tool.description ?? "").toLowerCase();
    const hay = `${name.toLowerCase()} ${desc}`;

    if (containsAny(desc, INJECTION_MARKERS)) {
      out.push({
        rule: "live.tool_poisoning", severity: CRITICAL,
        message: `Tool '${name}' description contains prompt-injection / tool-poisoning text.`,
        location: name,
      });
    }
    if (containsAny(hay, DANGEROUS_VERBS)) {
      out.push({
        rule: "live.dangerous_capability", severity: HIGH,
        message: `Tool '${name}' exposes a destructive/side-effecting capability.`,
        location: name,
      });
      const schema = tool.inputSchema ?? tool.input_schema;
      if (!schema) {
        out.push({
          rule: "live.unconstrained_tool", severity: HIGH,
          message: `Side-effecting tool '${name}' advertises no inputSchema.`,
          location: name,
        });
      } else if ((schema as Record<string, unknown>)["additionalProperties"] === true) {
        out.push({
          rule: "live.open_schema", severity: MEDIUM,
          message: `Tool '${name}' inputSchema sets additionalProperties=true.`,
          location: name,
        });
      }
    }
  }
  out.sort((a, b) => sevRank(a.severity) - sevRank(b.severity));
  return out;
}

// Top-level passive entry point: parse + assess a raw capture string.
export function scanCapture(raw: string): Finding[] {
  const v = JSON.parse(raw);
  return assess(v);
}

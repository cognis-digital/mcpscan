// Package mcpscan is a minimal Go port of mcpscan's core PASSIVE check:
// offline analysis of a captured MCP tools/list response. No network I/O.
package mcpscan

import (
	"encoding/json"
	"sort"
	"strings"
)

// Severity levels, mirroring the Python tool.
const (
	Critical = "critical"
	High     = "high"
	Medium   = "medium"
	Info     = "info"
)

// DangerousVerbs are destructive / side-effecting capability markers.
var DangerousVerbs = []string{
	"delete", "remove", "drop", "wipe", "destroy", "exec", "execute",
	"shell", "command", "spawn", "kill", "format", "overwrite", "truncate",
	"rm ", "rmdir", "unlink", "purge", "erase",
}

// InjectionMarkers are tool-poisoning / prompt-injection phrases.
var InjectionMarkers = []string{
	"ignore previous instructions", "ignore all previous",
	"disregard previous", "exfiltrate", "system prompt",
	"send to", "leak", "override your", "you are now",
}

// Finding is one detected issue.
type Finding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Location string `json:"location"`
}

type tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
	InputSchema2 map[string]interface{} `json:"input_schema"`
}

// ExtractTools pulls the tool list out of a raw capture (JSON-RPC envelope,
// bare {"tools":[...]}, or a top-level array).
func ExtractTools(raw []byte) ([]tool, error) {
	// try object form
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err == nil {
		if res, ok := obj["result"]; ok {
			var inner map[string]json.RawMessage
			if json.Unmarshal(res, &inner) == nil {
				if t, ok := inner["tools"]; ok {
					return parseTools(t)
				}
			}
		}
		if t, ok := obj["tools"]; ok {
			return parseTools(t)
		}
		return nil, nil
	}
	// try bare array form
	return parseTools(raw)
}

func parseTools(raw json.RawMessage) ([]tool, error) {
	var ts []tool
	if err := json.Unmarshal(raw, &ts); err != nil {
		return nil, err
	}
	return ts, nil
}

func containsAny(haystack string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

// AssessTools applies the passive rule pack to a parsed tool list.
func AssessTools(tools []tool) []Finding {
	var out []Finding
	for _, t := range tools {
		name := strings.TrimSpace(t.Name)
		if name == "" {
			name = "<unnamed>"
		}
		hay := strings.ToLower(name + " " + t.Description)
		desc := strings.ToLower(t.Description)

		if containsAny(desc, InjectionMarkers) {
			out = append(out, Finding{
				Rule:     "live.tool_poisoning",
				Severity: Critical,
				Message:  "Tool '" + name + "' description contains prompt-injection / tool-poisoning text.",
				Location: name,
			})
		}
		if containsAny(hay, DangerousVerbs) {
			schema := t.InputSchema
			if schema == nil {
				schema = t.InputSchema2
			}
			out = append(out, Finding{
				Rule:     "live.dangerous_capability",
				Severity: High,
				Message:  "Tool '" + name + "' exposes a destructive/side-effecting capability.",
				Location: name,
			})
			if schema == nil {
				out = append(out, Finding{
					Rule:     "live.unconstrained_tool",
					Severity: High,
					Message:  "Side-effecting tool '" + name + "' advertises no inputSchema.",
					Location: name,
				})
			} else if ap, ok := schema["additionalProperties"].(bool); ok && ap {
				out = append(out, Finding{
					Rule:     "live.open_schema",
					Severity: Medium,
					Message:  "Tool '" + name + "' inputSchema sets additionalProperties=true.",
					Location: name,
				})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return sevRank(out[i].Severity) < sevRank(out[j].Severity)
	})
	return out
}

func sevRank(s string) int {
	switch s {
	case Critical:
		return 0
	case High:
		return 1
	case Medium:
		return 2
	default:
		return 4
	}
}

// ScanCapture is the top-level passive entry point.
func ScanCapture(raw []byte) ([]Finding, error) {
	tools, err := ExtractTools(raw)
	if err != nil {
		return nil, err
	}
	return AssessTools(tools), nil
}

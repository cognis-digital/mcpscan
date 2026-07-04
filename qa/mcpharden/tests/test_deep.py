"""Deep behavior tests for MCPHARDEN — string transports, scan, SARIF/HTML, MCP.

Standard library only, no network. These exercise the fixes that turned the
README's documented contract into working code.
"""

import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcpharden import (  # noqa: E402
    audit_manifest,
    scan,
    scan_to_dict,
    to_sarif,
    to_html,
)
from mcpharden.cli import main  # noqa: E402
from mcpharden import mcp_server  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMOS = os.path.join(REPO_ROOT, "demos")


def _rules(report):
    return {f.rule for f in report.findings}


class TestStringTransportNormalization(unittest.TestCase):
    """The central fix: transport expressed as a bare string + top-level auth."""

    def test_string_http_no_auth_flags_network_risks(self):
        m = {"name": "pub", "transport": "http", "auth": "none",
             "capabilities": {}, "tools": [{"name": "t", "description": "does things"}]}
        r = _rules(audit_manifest(m))
        self.assertIn("transport.no_auth", r)
        self.assertIn("transport.no_tls", r)

    def test_string_stdio_with_oauth_is_clean(self):
        # demo 02 — the "best-practice template": must yield zero findings.
        m = {
            "name": "internal", "transport": "stdio", "auth": "oauth2",
            "capabilities": {"tools": {"list": True}},
            "tools": [{"name": "search_tickets",
                       "description": "Search Jira tickets by JQL query in project ENGR"}],
        }
        report = audit_manifest(m)
        self.assertFalse(report.failed, report.to_dict())
        self.assertEqual(report.score, 100)

    def test_object_transport_still_works(self):
        m = {"name": "x", "transport": {"type": "http", "host": "0.0.0.0"}}
        r = _rules(audit_manifest(m))
        self.assertIn("transport.bind_all", r)
        self.assertIn("transport.no_tls", r)

    def test_top_level_auth_satisfies_object_transport(self):
        m = {"name": "x", "transport": {"type": "http", "tls": True},
             "auth": "bearer", "capabilities": {"tools": {}}}
        r = _rules(audit_manifest(m))
        self.assertNotIn("transport.no_auth", r)
        self.assertNotIn("transport.no_tls", r)

    def test_numeric_transport_is_malformed_not_crash(self):
        r = _rules(audit_manifest({"name": "x", "transport": 7}))
        self.assertIn("transport.malformed", r)


class TestScan(unittest.TestCase):
    def test_scan_single_file(self):
        reports = scan(os.path.join(DEMOS, "01-basic", "weather-server.json"))
        self.assertEqual(len(reports), 1)
        self.assertTrue(reports[0].failed)

    def test_scan_directory_finds_multiple(self):
        reports = scan(os.path.join(DEMOS, "03-shared-multi-server"))
        names = {r.server_name for r in reports}
        self.assertIn("github-mcp", names)
        self.assertIn("slack-mcp", names)
        # github fails (no auth/tls), slack is clean.
        by_name = {r.server_name: r for r in reports}
        self.assertTrue(by_name["github-mcp"].failed)
        self.assertFalse(by_name["slack-mcp"].failed)

    def test_scan_to_dict_aggregates(self):
        d = scan_to_dict(DEMOS)
        self.assertGreaterEqual(d["servers_scanned"], 4)
        self.assertTrue(d["failed"])
        self.assertEqual(
            d["total_findings"],
            sum(len(r["findings"]) for r in d["reports"]),
        )

    def test_scan_bad_json_is_graceful(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "broken.json")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("not json {")
            reports = scan(tmp)
            self.assertEqual(len(reports), 1)
            self.assertIn("manifest.unreadable", _rules(reports[0]))

    def test_scan_missing_target_raises(self):
        from mcpharden.core import ManifestError
        with self.assertRaises(ManifestError):
            scan(os.path.join(DEMOS, "does-not-exist-xyz"))


class TestSerializers(unittest.TestCase):
    def test_sarif_shape(self):
        reports = scan(DEMOS)
        doc = to_sarif(reports)
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "mcpharden")
        self.assertTrue(run["results"])
        for res in run["results"]:
            self.assertIn(res["level"], ("error", "warning", "note"))
            self.assertIn("ruleId", res)
        # every result's rule is declared in the driver rules list.
        declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
        used = {r["ruleId"] for r in run["results"]}
        self.assertTrue(used.issubset(declared))

    def test_html_is_self_contained(self):
        html = to_html(scan(DEMOS))
        self.assertTrue(html.lstrip().startswith("<!doctype html>"))
        self.assertIn("<table>", html)
        self.assertIn("RESULT:", html)
        # injection content must be escaped, never raw.
        self.assertNotIn("<script>", html)


class TestCliFormatsAndGates(unittest.TestCase):
    def test_audit_sarif_to_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "r.sarif")
            rc = main(["audit", os.path.join(DEMOS, "01-basic", "weather-server.json"),
                       "--format", "sarif", "--out", out])
            self.assertEqual(rc, 1)  # critical/high present
            with open(out, encoding="utf-8") as fh:
                doc = json.load(fh)
            self.assertEqual(doc["version"], "2.1.0")

    def test_scan_html_to_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "r.html")
            main(["scan", DEMOS, "--format", "html", "--out", out])
            with open(out, encoding="utf-8") as fh:
                self.assertIn("<table>", fh.read())

    def test_fail_on_critical_passes_high_only_server(self):
        rc = main(["audit", os.path.join(DEMOS, "03-shared-multi-server", "github-mcp.json"),
                   "--fail-on", "critical"])
        self.assertEqual(rc, 0)  # only high findings, so critical gate passes

    def test_fail_on_high_fails_high_server(self):
        rc = main(["audit", os.path.join(DEMOS, "03-shared-multi-server", "github-mcp.json"),
                   "--fail-on", "high", "--format", "json"])
        self.assertEqual(rc, 1)

    def test_scan_clean_dir_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "clean.json")
            with open(p, "w", encoding="utf-8") as fh:
                json.dump({"name": "c", "transport": "stdio", "auth": "oauth2",
                           "capabilities": {"tools": {}},
                           "tools": [{"name": "echo",
                                      "description": "Echo back the provided text payload.",
                                      "inputSchema": {"type": "object",
                                                      "additionalProperties": False}}]}, fh)
            self.assertEqual(main(["scan", tmp]), 0)

    def test_rules_subcommand(self):
        self.assertEqual(main(["rules"]), 0)


class TestMcpServer(unittest.TestCase):
    def _roundtrip(self, requests):
        stdin = io.StringIO("\n".join(json.dumps(r) for r in requests) + "\n")
        stdout = io.StringIO()
        mcp_server.run_mcp_server(stdin=stdin, stdout=stdout)
        return [json.loads(l) for l in stdout.getvalue().splitlines() if l.strip()]

    def test_initialize_and_list(self):
        out = self._roundtrip([
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        ])
        # notification produces no response → 2 responses.
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0]["result"]["serverInfo"]["name"], "mcpharden")
        names = {t["name"] for t in out[1]["result"]["tools"]}
        self.assertEqual(names, {"scan", "audit_manifest", "posture"})

    def test_tools_call_scan(self):
        target = os.path.join(DEMOS, "01-basic", "weather-server.json")
        out = self._roundtrip([
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
             "params": {"name": "scan", "arguments": {"target": target}}},
        ])
        res = out[0]["result"]
        self.assertTrue(res["isError"])
        payload = json.loads(res["content"][0]["text"])
        self.assertTrue(payload["failed"])
        self.assertGreater(payload["total_findings"], 0)

    def test_tools_call_audit_manifest_inline(self):
        out = self._roundtrip([
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
             "params": {"name": "audit_manifest",
                        "arguments": {"manifest": {"name": "n", "transport": "stdio",
                                                   "capabilities": {"tools": {}}}}}},
        ])
        payload = json.loads(out[0]["result"]["content"][0]["text"])
        self.assertIn("findings", payload)

    def test_unknown_tool_is_jsonrpc_error(self):
        out = self._roundtrip([
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
             "params": {"name": "nope", "arguments": {}}},
        ])
        self.assertEqual(out[0]["error"]["code"], -32602)

    def test_parse_error(self):
        stdin = io.StringIO("{not json\n")
        stdout = io.StringIO()
        mcp_server.run_mcp_server(stdin=stdin, stdout=stdout)
        out = json.loads(stdout.getvalue().strip())
        self.assertEqual(out["error"]["code"], -32700)

    def test_unknown_method(self):
        out = self._roundtrip([
            {"jsonrpc": "2.0", "id": 6, "method": "totally/unknown"},
        ])
        self.assertEqual(out[0]["error"]["code"], -32601)


if __name__ == "__main__":
    unittest.main()

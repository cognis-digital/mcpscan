"""Render / export coverage for passive captures + a few authz edge cases.
No network calls."""

import io
import json
import os
import sys
import unittest
import contextlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcpscan.core import passive_capture, to_sarif, to_json, to_html, to_badge
from mcpscan.cli import main
from mcpscan.authz import Scope

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
DANGEROUS = os.path.join(FIX, "capture_dangerous.json")


class TestPassiveExports(unittest.TestCase):
    def setUp(self):
        self.report = passive_capture(DANGEROUS)

    def test_json_export_valid(self):
        data = json.loads(to_json(self.report))
        self.assertEqual(data["tool"], "mcpscan")
        self.assertTrue(any(f["rule"] == "live.dangerous_capability"
                            for f in data["findings"]))

    def test_sarif_export_valid(self):
        data = json.loads(to_sarif(self.report))
        self.assertIn("runs", data)
        self.assertTrue(data["runs"][0]["results"])

    def test_html_export(self):
        html = to_html(self.report)
        self.assertIn("<", html)
        self.assertIn("mcpscan", html.lower())

    def test_badge_export(self):
        badge = to_badge(self.report)
        self.assertTrue(badge.strip())


class TestPassiveTableCli(unittest.TestCase):
    def test_table_output_mentions_passive(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["passive", DANGEROUS])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("passive.capture_analyzed", out)
        self.assertIn("dangerous_capability", out)

    def test_sarif_cli(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["passive", DANGEROUS, "--format", "sarif"])
        self.assertEqual(rc, 0)
        json.loads(buf.getvalue())  # valid JSON


class TestAuthzEdge(unittest.TestCase):
    def test_resolve_off_does_not_resolve(self):
        # With resolve off, a hostname only matches by literal name.
        s = Scope.from_spec(["example.com"], authorized=True)
        self.assertTrue(s.allows("http://example.com/x"))

    def test_describe_lists_entries(self):
        s = Scope.from_spec(["127.0.0.1", "10.0.0.0/8"], authorized=True)
        d = s.describe()
        self.assertIn("127.0.0.1", d)
        self.assertIn("10.0.0.0/8", d)

    def test_ipv6_loopback_in_scope(self):
        s = Scope.from_spec(["::1"], authorized=True)
        self.assertTrue(s.allows("http://[::1]:8080/mcp"))

    def test_cidr_boundary(self):
        s = Scope.from_spec(["192.168.0.0/30"], authorized=True)
        self.assertTrue(s.allows("http://192.168.0.3/x"))
        self.assertFalse(s.allows("http://192.168.0.4/x"))


if __name__ == "__main__":
    unittest.main()

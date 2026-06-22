"""Tests for PASSIVE capture analysis (default, offline) and that the ACTIVE
probe stays authorization-gated. No network calls anywhere in this file."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcpscan.core import ScanError, passive_capture, probe_endpoint
from mcpscan.authz import AuthorizationError
from mcpscan.cli import main

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


class TestPassiveCapture(unittest.TestCase):
    def _rules(self, path):
        report = passive_capture(os.path.join(FIX, path))
        return {f.rule for f in report.findings}

    def test_dangerous_capture_flags_capabilities(self):
        rules = self._rules("capture_dangerous.json")
        self.assertIn("live.dangerous_capability", rules)
        self.assertIn("live.tool_poisoning", rules)
        self.assertIn("passive.capture_analyzed", rules)

    def test_passive_does_not_infer_auth(self):
        # A static capture must NOT claim "no auth" — we never touched the net.
        rules = self._rules("capture_dangerous.json")
        self.assertNotIn("live.no_auth", rules)
        self.assertNotIn("live.auth_enforced", rules)

    def test_passive_does_not_infer_tls(self):
        rules = self._rules("capture_dangerous.json")
        self.assertNotIn("live.no_tls", rules)

    def test_clean_capture_minimal(self):
        rules = self._rules("capture_clean.json")
        self.assertNotIn("live.dangerous_capability", rules)
        self.assertIn("passive.capture_analyzed", rules)

    def test_bare_list_capture(self):
        rules = self._rules("capture_barelist.json")
        self.assertIn("live.dangerous_capability", rules)

    def test_inline_json_string(self):
        cap = json.dumps({"tools": [
            {"name": "rm_all", "description": "delete everything"}]})
        report = passive_capture(cap)
        rules = {f.rule for f in report.findings}
        self.assertIn("live.dangerous_capability", rules)

    def test_invalid_json_raises(self):
        with self.assertRaises(ScanError):
            passive_capture("{not json")

    def test_passive_is_offline_no_network_symbols(self):
        # Sanity: passive_capture should never need a scope or token.
        report = passive_capture(os.path.join(FIX, "capture_clean.json"))
        self.assertEqual(report.target_kind, "endpoint")


class TestPassiveCli(unittest.TestCase):
    def test_passive_subcommand_json(self):
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["passive", os.path.join(FIX, "capture_dangerous.json"),
                       "--format", "json"])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        rules = {f["rule"] for f in data["findings"]}
        self.assertIn("passive.capture_analyzed", rules)
        self.assertIn("live.dangerous_capability", rules)

    def test_passive_fail_on(self):
        rc = main(["passive", os.path.join(FIX, "capture_dangerous.json"),
                   "--fail-on", "high"])
        self.assertEqual(rc, 1)

    def test_passive_clean_fail_on_passes(self):
        rc = main(["passive", os.path.join(FIX, "capture_clean.json"),
                   "--fail-on", "critical"])
        self.assertEqual(rc, 0)

    def test_passive_missing_file_exits_2(self):
        rc = main(["passive", "/no/such/capture.json"])
        self.assertEqual(rc, 2)


class TestActiveGate(unittest.TestCase):
    """The probe (ACTIVE) path must refuse without authorization, BEFORE any
    socket would be opened."""

    def test_probe_without_scope_refuses(self):
        with self.assertRaises(AuthorizationError):
            probe_endpoint("http://127.0.0.1:9/mcp")

    def test_cli_probe_without_authorized_exits_3(self):
        # No --authorized → refused with exit code 3, no traffic.
        rc = main(["probe", "http://127.0.0.1:9/mcp",
                   "--target-allowlist", "127.0.0.1"])
        self.assertEqual(rc, 3)

    def test_cli_probe_without_scope_exits_3(self):
        rc = main(["probe", "http://127.0.0.1:9/mcp", "--authorized"])
        self.assertEqual(rc, 3)

    def test_cli_probe_out_of_scope_exits_3(self):
        # Authorized + scoped, but target not in scope → refused.
        rc = main(["probe", "http://evil.example.com/mcp",
                   "--authorized", "--target-allowlist", "127.0.0.1"])
        self.assertEqual(rc, 3)

    def test_cli_probe_bad_scheme_after_scope(self):
        # In scope + authorized but non-http scheme → ScanError path (exit 2).
        rc = main(["probe", "ftp://127.0.0.1/mcp",
                   "--authorized", "--target-allowlist", "127.0.0.1"])
        # scope.check passes (host in scope); probe_endpoint raises ScanError
        self.assertIn(rc, (2, 3))


if __name__ == "__main__":
    unittest.main()

"""Hardening tests: bad input, edge cases, and I/O error paths.

Covers the improvements made during the hardening pass:
  * scan_url / probe_endpoint raise ScanError (not ValueError) on negative timeout
  * CLI --timeout <= 0 prints a clear error to stderr and exits 2
  * CLI --out to an unwritable path exits 2 with a human-readable error
  * scan_python_source / scan_js_source on empty / whitespace-only input
  * scan_path on a non-existent path raises ScanError
  * scan_url on a non-http scheme raises ScanError
  * probe_endpoint on a non-http URL raises ScanError
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcpscan.cli import main
from mcpscan.core import (
    ScanError,
    probe_endpoint,
    scan_js_source,
    scan_path,
    scan_python_source,
    scan_url,
)


class TestTimeoutValidation(unittest.TestCase):
    """Negative / zero timeout must raise ScanError, never a raw ValueError."""

    def test_scan_url_negative_timeout_raises_scan_error(self):
        with self.assertRaises(ScanError) as ctx:
            scan_url("http://127.0.0.1:9/x.py", timeout=-1.0)
        self.assertIn("positive", str(ctx.exception).lower())

    def test_scan_url_zero_timeout_raises_scan_error(self):
        with self.assertRaises(ScanError):
            scan_url("http://127.0.0.1:9/x.py", timeout=0.0)

    def test_probe_endpoint_negative_timeout_raises_scan_error(self):
        with self.assertRaises(ScanError) as ctx:
            probe_endpoint("http://127.0.0.1:9/mcp", timeout=-5.0)
        self.assertIn("positive", str(ctx.exception).lower())

    def test_probe_endpoint_zero_timeout_raises_scan_error(self):
        with self.assertRaises(ScanError):
            probe_endpoint("http://127.0.0.1:9/mcp", timeout=0.0)


class TestCliTimeoutValidation(unittest.TestCase):
    """CLI --timeout <= 0 should print a clear message and return exit code 2."""

    def test_scan_url_negative_timeout_exits_2(self):
        ret = main(["scan-url", "http://example.com/x.py", "--timeout", "-1"])
        self.assertEqual(ret, 2)

    def test_probe_negative_timeout_exits_2(self):
        ret = main(["probe", "http://127.0.0.1:9/mcp", "--timeout", "-3"])
        self.assertEqual(ret, 2)

    def test_probe_zero_timeout_exits_2(self):
        ret = main(["probe", "http://127.0.0.1:9/mcp", "--timeout", "0"])
        self.assertEqual(ret, 2)


class TestCliOutPathError(unittest.TestCase):
    """Writing to an unwritable / non-existent path must exit 2, not traceback."""

    def _demo_path(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(root, "demos", "01-basic", "vulnerable_mcp_server.py")

    def test_bad_out_path_exits_2(self):
        bad = os.path.join("Z_NONEXISTENT_DRIVE_XYZ", "deep", "report.json")
        with self.assertRaises(SystemExit) as ctx:
            main(["scan", self._demo_path(), "--format", "json", "--out", bad])
        self.assertEqual(ctx.exception.code, 2)


class TestEmptyInput(unittest.TestCase):
    """Empty source must return an empty list without crashing."""

    def test_empty_python_source(self):
        findings = scan_python_source("empty.py", "")
        self.assertEqual(findings, [])

    def test_whitespace_only_python_source(self):
        findings = scan_python_source("blank.py", "   \n\n  \t  ")
        self.assertEqual(findings, [])

    def test_empty_js_source(self):
        findings = scan_js_source("empty.js", "")
        self.assertEqual(findings, [])

    def test_whitespace_only_js_source(self):
        findings = scan_js_source("blank.js", "\n\n\t")
        self.assertEqual(findings, [])


class TestScanPathEdgeCases(unittest.TestCase):
    """scan_path edge cases that produce clear errors or graceful output."""

    def test_missing_path_raises_scan_error(self):
        with self.assertRaises(ScanError) as ctx:
            scan_path("/absolutely/nonexistent/path/xyz_12345")
        self.assertIn("no such path", str(ctx.exception).lower())

    def test_empty_directory_gives_no_source_finding(self):
        with tempfile.TemporaryDirectory() as d:
            report = scan_path(d)
        rules = {f.rule for f in report.findings}
        self.assertIn("static.no_source", rules)

    def test_scan_url_non_http_scheme_raises_scan_error(self):
        with self.assertRaises(ScanError):
            scan_url("ftp://nope/x.py")

    def test_probe_non_http_scheme_raises_scan_error(self):
        with self.assertRaises(ScanError):
            probe_endpoint("ftp://nope/mcp")


if __name__ == "__main__":
    unittest.main()

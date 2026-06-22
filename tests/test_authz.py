"""Tests for the active-scan authorization gate (mcpscan.authz).

These tests make NO network calls. They verify the gate is fail-closed:
OFF by default, scope-enforced, and rate-limited.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcpscan.authz import (
    AuthorizationError,
    RateLimiter,
    Scope,
    _parse_entry,
    _split_host_port,
    emit_banner,
)

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


class TestSplitHostPort(unittest.TestCase):
    def test_plain_host(self):
        self.assertEqual(_split_host_port("example.com"), ("example.com", None))

    def test_host_port(self):
        self.assertEqual(_split_host_port("example.com:8080"),
                         ("example.com", 8080))

    def test_url(self):
        self.assertEqual(_split_host_port("https://example.com:9000/mcp"),
                         ("example.com", 9000))

    def test_url_default_port_is_none(self):
        host, port = _split_host_port("http://example.com/mcp")
        self.assertEqual(host, "example.com")
        self.assertIsNone(port)

    def test_ipv4(self):
        self.assertEqual(_split_host_port("127.0.0.1"), ("127.0.0.1", None))

    def test_ipv4_port(self):
        self.assertEqual(_split_host_port("127.0.0.1:6000"),
                         ("127.0.0.1", 6000))

    def test_ipv6_plain(self):
        host, port = _split_host_port("::1")
        self.assertEqual(host, "::1")
        self.assertIsNone(port)

    def test_ipv6_bracket_port(self):
        self.assertEqual(_split_host_port("[::1]:8080"), ("::1", 8080))

    def test_case_normalized(self):
        self.assertEqual(_split_host_port("EXAMPLE.COM")[0], "example.com")


class TestParseEntry(unittest.TestCase):
    def test_comment_skipped(self):
        self.assertIsNone(_parse_entry("# a comment"))

    def test_blank_skipped(self):
        self.assertIsNone(_parse_entry("   "))

    def test_hostname(self):
        e = _parse_entry("example.com")
        self.assertEqual(e.host, "example.com")
        self.assertIsNone(e.network)

    def test_cidr(self):
        e = _parse_entry("10.0.0.0/24")
        self.assertIsNotNone(e.network)

    def test_bare_ip_becomes_network(self):
        e = _parse_entry("192.168.1.5")
        self.assertIsNotNone(e.network)


class TestScopeAuthorization(unittest.TestCase):
    def test_unauthorized_by_default(self):
        s = Scope.from_spec(["127.0.0.1"], authorized=False)
        with self.assertRaises(AuthorizationError):
            s.require_authorized()

    def test_authorized_but_empty_scope_refused(self):
        s = Scope.from_spec([], authorized=True)
        with self.assertRaises(AuthorizationError):
            s.require_authorized()

    def test_authorized_with_scope_ok(self):
        s = Scope.from_spec(["127.0.0.1"], authorized=True)
        s.require_authorized()  # no raise

    def test_check_refuses_out_of_scope(self):
        s = Scope.from_spec(["127.0.0.1"], authorized=True)
        with self.assertRaises(AuthorizationError):
            s.check("http://evil.example.com/mcp")

    def test_check_allows_in_scope(self):
        s = Scope.from_spec(["127.0.0.1"], authorized=True)
        s.check("http://127.0.0.1:9000/mcp")  # no raise

    def test_check_unauthorized_refused_even_if_in_scope(self):
        s = Scope.from_spec(["127.0.0.1"], authorized=False)
        with self.assertRaises(AuthorizationError):
            s.check("http://127.0.0.1/mcp")


class TestScopeMatching(unittest.TestCase):
    def test_hostname_match(self):
        s = Scope.from_spec(["mcp.example.com"], authorized=True)
        self.assertTrue(s.allows("https://mcp.example.com/x"))
        self.assertFalse(s.allows("https://other.example.com/x"))

    def test_cidr_match(self):
        s = Scope.from_spec(["10.0.0.0/24"], authorized=True)
        self.assertTrue(s.allows("http://10.0.0.55:8080/mcp"))
        self.assertFalse(s.allows("http://10.0.1.55:8080/mcp"))

    def test_port_constraint(self):
        s = Scope.from_spec(["127.0.0.1:8080"], authorized=True)
        self.assertTrue(s.allows("http://127.0.0.1:8080/mcp"))
        self.assertFalse(s.allows("http://127.0.0.1:9090/mcp"))

    def test_port_any_when_unspecified(self):
        s = Scope.from_spec(["127.0.0.1"], authorized=True)
        self.assertTrue(s.allows("http://127.0.0.1:1234/mcp"))
        self.assertTrue(s.allows("http://127.0.0.1:5678/mcp"))

    def test_empty_scope_allows_nothing(self):
        s = Scope.from_spec([], authorized=True)
        self.assertFalse(s.allows("http://127.0.0.1/mcp"))

    def test_comma_separated_spec(self):
        s = Scope.from_spec(["127.0.0.1, 10.0.0.0/8"], authorized=True)
        self.assertTrue(s.allows("http://127.0.0.1/x"))
        self.assertTrue(s.allows("http://10.1.2.3/x"))

    def test_multiple_allow_flags(self):
        s = Scope.from_spec(["a.example", "b.example"], authorized=True)
        self.assertTrue(s.allows("http://a.example/x"))
        self.assertTrue(s.allows("http://b.example/x"))
        self.assertFalse(s.allows("http://c.example/x"))


class TestScopeFromFile(unittest.TestCase):
    def test_load_file(self):
        s = Scope.from_spec(allow_file=os.path.join(FIX, "scope.txt"),
                            authorized=True)
        self.assertTrue(s.allows("http://127.0.0.1/x"))
        self.assertTrue(s.allows("http://10.0.0.9/x"))
        self.assertTrue(s.allows("http://mcp.internal.example:8080/x"))
        self.assertFalse(s.allows("http://mcp.internal.example:9999/x"))

    def test_missing_file_raises(self):
        with self.assertRaises(AuthorizationError):
            Scope.from_spec(allow_file="/no/such/scope.txt", authorized=True)


class TestRateLimit(unittest.TestCase):
    def test_bad_rate_rejected(self):
        with self.assertRaises(AuthorizationError):
            Scope.from_spec(["127.0.0.1"], authorized=True, rate_limit=0)

    def test_limiter_first_call_no_wait(self):
        t = [0.0]
        slept = []
        rl = RateLimiter(2.0, clock=lambda: t[0], sleep=lambda s: slept.append(s))
        self.assertEqual(rl.acquire(), 0.0)

    def test_limiter_paces_subsequent_calls(self):
        t = [0.0]
        slept = []

        def clk():
            return t[0]

        def slp(s):
            slept.append(s)
            t[0] += s  # virtual time advances by the sleep

        rl = RateLimiter(2.0, clock=clk, sleep=slp)  # min interval 0.5s
        rl.acquire()
        waited = rl.acquire()
        self.assertAlmostEqual(waited, 0.5, places=6)
        self.assertEqual(len(slept), 1)

    def test_limiter_rejects_zero(self):
        with self.assertRaises(ValueError):
            RateLimiter(0)


class TestBanner(unittest.TestCase):
    def test_banner_mentions_authorized(self):
        import io
        buf = io.StringIO()
        s = Scope.from_spec(["127.0.0.1"], authorized=True, rate_limit=2.0)
        emit_banner(s, stream=buf)
        text = buf.getvalue()
        self.assertIn("AUTHORIZED USE ONLY", text)
        self.assertIn("127.0.0.1", text)
        self.assertIn("2 req/s", text)


if __name__ == "__main__":
    unittest.main()

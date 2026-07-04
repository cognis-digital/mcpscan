"""Deep / integration tests for mcpauth — exercise the live proxy end-to-end."""

import json
import os
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcpauth.core import (
    ProxyConfig,
    TokenStore,
    build_demo_upstream,
    build_server,
    free_port,
    generate_token,
    make_record,
    run_demo,
    verify_token,
)


def _wait_request(url, headers=None, timeout=5.0):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            req = urllib.request.Request(url, headers=headers or {}, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except (urllib.error.URLError, ConnectionError) as e:
            last = e
            time.sleep(0.05)
    raise RuntimeError(f"never connected: {last}")


class TestLiveProxy(unittest.TestCase):
    def setUp(self):
        # Fake unauthenticated upstream.
        self.upstream = build_demo_upstream()
        self.up_port = self.upstream.server_address[1]
        self._ut = threading.Thread(target=self.upstream.serve_forever, daemon=True)
        self._ut.start()

        # Token store with one valid token.
        self.token = generate_token()
        self.store = TokenStore("<mem>", [make_record(self.token, label="live")])

        self.events = []
        self.proxy_port = free_port()
        cfg = ProxyConfig(
            upstream=f"http://127.0.0.1:{self.up_port}",
            store_path="<mem>",
            host="127.0.0.1",
            port=self.proxy_port,
            audit_sink=self.events.append,
        )
        self.httpd = build_server(cfg, self.store)
        self._pt = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._pt.start()
        self.base = f"http://127.0.0.1:{self.proxy_port}/mcp"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.upstream.shutdown()
        self.upstream.server_close()

    def test_no_token_is_401_with_challenge(self):
        status, body = _wait_request(self.base)
        self.assertEqual(status, 401)
        self.assertIn(b"unauthorized", body)

    def test_bad_token_is_401(self):
        status, _ = _wait_request(self.base, {"Authorization": "Bearer wrong"})
        self.assertEqual(status, 401)

    def test_valid_token_forwards_200(self):
        status, body = _wait_request(
            self.base, {"Authorization": f"Bearer {self.token}"})
        self.assertEqual(status, 200)
        payload = json.loads(body)
        # The upstream echoed the path back through the proxy.
        self.assertEqual(payload["result"]["path"], "/mcp")
        self.assertEqual(payload["result"]["server"], "demo-mcp")

    def test_audit_records_both_decisions(self):
        _wait_request(self.base)
        _wait_request(self.base, {"Authorization": f"Bearer {self.token}"})
        # Give the handler threads a beat to append.
        time.sleep(0.2)
        reasons = {e.reason for e in self.events}
        self.assertIn("missing_header", reasons)
        self.assertIn("ok", reasons)
        allowed = [e for e in self.events if e.allowed]
        self.assertTrue(all(e.token_id for e in allowed))


class TestBadGateway(unittest.TestCase):
    def test_unreachable_upstream_is_502(self):
        token = generate_token()
        store = TokenStore("<mem>", [make_record(token)])
        port = free_port()
        # Point at a port nobody is listening on.
        cfg = ProxyConfig(
            upstream=f"http://127.0.0.1:{free_port()}",
            store_path="<mem>", host="127.0.0.1", port=port,
            timeout=2.0, audit_sink=lambda e: None,
        )
        httpd = build_server(cfg, store)
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        try:
            status, _ = _wait_request(
                f"http://127.0.0.1:{port}/x",
                {"Authorization": f"Bearer {token}"})
            self.assertEqual(status, 502)
        finally:
            httpd.shutdown()
            httpd.server_close()


class TestConstantTimeVerify(unittest.TestCase):
    def test_checks_all_records(self):
        toks = [generate_token() for _ in range(5)]
        recs = [make_record(t, label=str(i)) for i, t in enumerate(toks)]
        # The last token should still verify even though earlier ones mismatch.
        self.assertIsNotNone(verify_token(toks[-1], recs))
        self.assertIsNone(verify_token("nope", recs))


class TestRunDemoHelper(unittest.TestCase):
    def test_run_demo_passes(self):
        result = run_demo()
        self.assertTrue(result["ok"])
        self.assertEqual(result["no_token_status"], 401)
        self.assertEqual(result["with_token_status"], 200)
        self.assertGreaterEqual(len(result["events"]), 2)


if __name__ == "__main__":
    unittest.main()

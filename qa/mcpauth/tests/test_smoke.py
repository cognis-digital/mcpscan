"""Smoke tests for mcpauth. Standard library only."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcpauth import TOOL_NAME, TOOL_VERSION
from mcpauth.cli import main
from mcpauth.core import (
    TokenStore,
    decide,
    generate_token,
    make_record,
    parse_bearer,
    verify_token,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestMetadata(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "mcpauth")
        self.assertTrue(TOOL_VERSION)


class TestTokens(unittest.TestCase):
    def test_token_is_strong_and_prefixed(self):
        t = generate_token()
        self.assertTrue(t.startswith("mcpauth_"))
        self.assertGreater(len(t), 40)
        self.assertNotEqual(t, generate_token())  # randomness

    def test_hash_roundtrip_verifies(self):
        t = generate_token()
        rec = make_record(t, label="k")
        self.assertIsNotNone(verify_token(t, [rec]))
        self.assertIsNone(verify_token(t + "x", [rec]))
        self.assertIsNone(verify_token("", [rec]))

    def test_plaintext_not_stored(self):
        t = generate_token()
        rec = make_record(t)
        self.assertNotIn(t, json.dumps(rec.to_dict()))


class TestAuthDecision(unittest.TestCase):
    def test_parse_bearer(self):
        self.assertEqual(parse_bearer("Bearer abc"), "abc")
        self.assertEqual(parse_bearer("bearer abc"), "abc")
        self.assertIsNone(parse_bearer("Basic abc"))
        self.assertIsNone(parse_bearer("Bearer"))
        self.assertIsNone(parse_bearer(None))

    def test_decide_paths(self):
        t = generate_token()
        store = TokenStore("<mem>", [make_record(t, label="ci")])
        self.assertEqual(decide(None, store).reason, "missing_header")
        self.assertEqual(decide("Basic x", store).reason, "malformed_header")
        self.assertEqual(decide("Bearer nope", store).reason, "invalid_token")
        ok = decide(f"Bearer {t}", store)
        self.assertTrue(ok.allowed)
        self.assertEqual(ok.reason, "ok")
        self.assertEqual(ok.label, "ci")


class TestStorePersistence(unittest.TestCase):
    def test_save_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "tokens.json")
            store = TokenStore(path)
            t = generate_token()
            store.add(make_record(t, label="a"))
            store.save()
            self.assertTrue(os.path.exists(path))
            loaded = TokenStore.load(path)
            self.assertEqual(len(loaded.records), 1)
            self.assertIsNotNone(loaded.verify(t))

    def test_missing_store_is_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            loaded = TokenStore.load(os.path.join(tmp, "none.json"))
            self.assertEqual(loaded.records, [])


class TestCli(unittest.TestCase):
    def test_gen_token_then_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "tokens.json")
            self.assertEqual(main(["gen-token", "--tokens", path, "--label", "x"]), 0)
            self.assertTrue(os.path.exists(path))
            self.assertEqual(main(["list", "--tokens", path]), 0)

    def test_wrap_requires_tokens(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "empty.json")
            rc = main(["wrap", "--upstream", "http://127.0.0.1:8000",
                       "--tokens", path, "--port", "0"])
            self.assertEqual(rc, 2)

    def test_no_command_exits_2(self):
        self.assertEqual(main([]), 2)

    def test_demo_subcommand_passes(self):
        # Exercises end-to-end through __main__ as a subprocess.
        proc = subprocess.run(
            [sys.executable, "-m", "mcpauth", "demo", "--format", "json"],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertTrue(data["ok"])
        self.assertEqual(data["no_token_status"], 401)
        self.assertEqual(data["with_token_status"], 200)


if __name__ == "__main__":
    unittest.main()

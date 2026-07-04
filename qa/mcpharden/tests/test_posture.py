"""Tests for the fleet-posture correlation engine (mcpharden.posture).

Standard library only, fully offline. Two layers:

  * unit  — each cross-server correlator in isolation, built from hand-made
            ServerSummary objects so the assertions pin exact behavior;
  * e2e   — assess() over committed manifest fixtures + the CLI `posture`
            subcommand in every output format and gate.

No network, no fabricated intel: every secret/CVE-shaped value is an obvious
synthetic test token.
"""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcpharden import posture  # noqa: E402
from mcpharden.posture import (  # noqa: E402
    PostureReport,
    ServerSummary,
    analyze,
    assess,
    summarize,
)
from mcpharden.core import audit_manifest, Report  # noqa: E402
from mcpharden.cli import main  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FLEET = os.path.join(REPO_ROOT, "tests", "fixtures", "fleet")
CLEAN_FLEET = os.path.join(REPO_ROOT, "tests", "fixtures", "clean_fleet")


def mk(name, *, transport="stdio", network=False, failed=False, score=100,
       rules=(), tool_names=(), secrets=(), has_auth=True, has_tls=False):
    return ServerSummary(
        source=f"<{name}>",
        name=name,
        transport_type=transport,
        network=network,
        failed=failed,
        score=score,
        rules=frozenset(rules),
        tool_names=tuple(tool_names),
        secrets=tuple(secrets),
        has_auth=has_auth,
        has_tls=has_tls,
    )


def rules_of(pr):
    return {f.rule for f in pr.findings}


# --------------------------------------------------------------------------
# Tool-name collision correlator
# --------------------------------------------------------------------------
class TestToolCollision(unittest.TestCase):
    def test_collision_across_two_servers(self):
        pr = analyze([mk("a", tool_names=["read_file"]),
                      mk("b", tool_names=["read_file"])])
        self.assertIn("fleet.tool_collision", rules_of(pr))

    def test_no_collision_when_unique(self):
        pr = analyze([mk("a", tool_names=["a_read"]),
                      mk("b", tool_names=["b_read"])])
        self.assertNotIn("fleet.tool_collision", rules_of(pr))

    def test_collision_lists_all_owners(self):
        pr = analyze([mk("a", tool_names=["search"]),
                      mk("b", tool_names=["search"]),
                      mk("c", tool_names=["search"])])
        f = next(f for f in pr.findings if f.rule == "fleet.tool_collision")
        for nm in ("a", "b", "c"):
            self.assertIn(nm, f.message)

    def test_collision_is_high_severity(self):
        pr = analyze([mk("a", tool_names=["x"]), mk("b", tool_names=["x"])])
        f = next(f for f in pr.findings if f.rule == "fleet.tool_collision")
        self.assertEqual(f.severity, "high")

    def test_same_server_duplicate_does_not_collide(self):
        # one server registering the same tool twice is a per-server concern,
        # not a cross-server collision.
        pr = analyze([mk("a", tool_names=["x", "x"])])
        self.assertNotIn("fleet.tool_collision", rules_of(pr))

    def test_multiple_distinct_collisions(self):
        pr = analyze([mk("a", tool_names=["read", "write"]),
                      mk("b", tool_names=["read", "write"])])
        cols = [f for f in pr.findings if f.rule == "fleet.tool_collision"]
        self.assertEqual(len(cols), 2)

    def test_collision_location_names_tool(self):
        pr = analyze([mk("a", tool_names=["danger"]), mk("b", tool_names=["danger"])])
        f = next(f for f in pr.findings if f.rule == "fleet.tool_collision")
        self.assertEqual(f.location, "tool:danger")

    def test_empty_tool_names_no_finding(self):
        pr = analyze([mk("a"), mk("b")])
        self.assertNotIn("fleet.tool_collision", rules_of(pr))


# --------------------------------------------------------------------------
# Shared-secret correlator
# --------------------------------------------------------------------------
class TestSharedSecret(unittest.TestCase):
    SEC = "sk_live_ABCD1234EFGH5678"

    def test_shared_secret_flagged(self):
        pr = analyze([mk("a", secrets=[self.SEC]), mk("b", secrets=[self.SEC])])
        self.assertIn("fleet.shared_secret", rules_of(pr))

    def test_shared_secret_is_critical(self):
        pr = analyze([mk("a", secrets=[self.SEC]), mk("b", secrets=[self.SEC])])
        f = next(f for f in pr.findings if f.rule == "fleet.shared_secret")
        self.assertEqual(f.severity, "critical")

    def test_distinct_secrets_not_flagged(self):
        pr = analyze([mk("a", secrets=["sk_live_AAAAAAAAAAAA"]),
                      mk("b", secrets=["sk_live_BBBBBBBBBBBB"])])
        self.assertNotIn("fleet.shared_secret", rules_of(pr))

    def test_secret_value_never_leaked_in_full(self):
        pr = analyze([mk("a", secrets=[self.SEC]), mk("b", secrets=[self.SEC])])
        f = next(f for f in pr.findings if f.rule == "fleet.shared_secret")
        self.assertNotIn(self.SEC, f.message)
        self.assertIn("…", f.message)  # fingerprint marker

    def test_single_server_secret_not_shared(self):
        pr = analyze([mk("a", secrets=[self.SEC])])
        self.assertNotIn("fleet.shared_secret", rules_of(pr))

    def test_same_server_listed_once_not_shared(self):
        # a server appearing once with a secret is not "shared".
        pr = analyze([mk("a", secrets=[self.SEC, self.SEC])])
        self.assertNotIn("fleet.shared_secret", rules_of(pr))

    def test_three_way_share_lists_owners(self):
        pr = analyze([mk("a", secrets=[self.SEC]),
                      mk("b", secrets=[self.SEC]),
                      mk("c", secrets=[self.SEC])])
        f = next(f for f in pr.findings if f.rule == "fleet.shared_secret")
        self.assertIn("3 manifests", f.message)


# --------------------------------------------------------------------------
# Concentration / lateral-movement correlator
# --------------------------------------------------------------------------
class TestConcentration(unittest.TestCase):
    def test_lateral_movement_rce_plus_exposed_peer(self):
        pr = analyze([
            mk("rce", network=False, rules=["tool.shell_exec"]),
            mk("edge", network=True, failed=True,
               rules=["transport.no_auth", "transport.bind_all"]),
        ])
        self.assertIn("fleet.lateral_movement", rules_of(pr))

    def test_no_lateral_movement_without_rce(self):
        pr = analyze([
            mk("edge", network=True, failed=True, rules=["transport.no_auth"]),
            mk("safe", network=True, rules=[]),
        ])
        self.assertNotIn("fleet.lateral_movement", rules_of(pr))

    def test_no_lateral_movement_without_exposed_peer(self):
        pr = analyze([
            mk("rce", network=False, rules=["tool.shell_exec"]),
            mk("safe", network=True, has_auth=True, has_tls=True, rules=[]),
        ])
        self.assertNotIn("fleet.lateral_movement", rules_of(pr))

    def test_unpinned_command_counts_as_rce(self):
        pr = analyze([
            mk("supply", network=False, rules=["transport.unpinned_command"]),
            mk("edge", network=True, failed=True, rules=["transport.cors_wildcard"]),
        ])
        self.assertIn("fleet.lateral_movement", rules_of(pr))

    def test_failure_concentration_majority(self):
        pr = analyze([
            mk("a", failed=True, score=20),
            mk("b", failed=True, score=40),
            mk("c", failed=False, score=100),
        ])
        self.assertIn("fleet.failure_concentration", rules_of(pr))

    def test_failure_concentration_minority_not_flagged(self):
        pr = analyze([
            mk("a", failed=True, score=20),
            mk("b", failed=False),
            mk("c", failed=False),
            mk("d", failed=False),
        ])
        self.assertNotIn("fleet.failure_concentration", rules_of(pr))

    def test_failure_concentration_single_failure_not_flagged(self):
        # 1/2 is 50% but failing must be >= 2 to flag a fleet program.
        pr = analyze([mk("a", failed=True), mk("b", failed=False)])
        self.assertNotIn("fleet.failure_concentration", rules_of(pr))

    def test_lateral_movement_is_high(self):
        pr = analyze([
            mk("rce", rules=["tool.shell_exec"]),
            mk("edge", network=True, failed=True, rules=["transport.no_auth"]),
        ])
        f = next(f for f in pr.findings if f.rule == "fleet.lateral_movement")
        self.assertEqual(f.severity, "high")


# --------------------------------------------------------------------------
# Trust-tier correlator
# --------------------------------------------------------------------------
class TestTrustTier(unittest.TestCase):
    def test_auth_inconsistency_flagged(self):
        pr = analyze([
            mk("a", network=True, has_auth=True),
            mk("b", network=True, has_auth=False),
        ])
        self.assertIn("fleet.trust_tier_inconsistency", rules_of(pr))

    def test_all_authed_no_finding(self):
        pr = analyze([
            mk("a", network=True, has_auth=True),
            mk("b", network=True, has_auth=True),
        ])
        self.assertNotIn("fleet.trust_tier_inconsistency", rules_of(pr))

    def test_single_network_server_no_tier_finding(self):
        pr = analyze([mk("a", network=True, has_auth=True),
                      mk("b", network=False, has_auth=False)])
        self.assertNotIn("fleet.trust_tier_inconsistency", rules_of(pr))

    def test_local_servers_ignored_for_tiers(self):
        pr = analyze([
            mk("a", network=False, has_auth=True),
            mk("b", network=False, has_auth=False),
        ])
        self.assertNotIn("fleet.trust_tier_inconsistency", rules_of(pr))

    def test_tls_inconsistency_flagged(self):
        pr = analyze([
            mk("a", network=True, has_auth=True, has_tls=True),
            mk("b", network=True, has_auth=True, has_tls=False),
        ])
        self.assertIn("fleet.tls_inconsistency", rules_of(pr))

    def test_tls_all_on_no_finding(self):
        pr = analyze([
            mk("a", network=True, has_tls=True),
            mk("b", network=True, has_tls=True),
        ])
        self.assertNotIn("fleet.tls_inconsistency", rules_of(pr))

    def test_trust_tier_is_high(self):
        pr = analyze([mk("a", network=True, has_auth=True),
                      mk("b", network=True, has_auth=False)])
        f = next(f for f in pr.findings if f.rule == "fleet.trust_tier_inconsistency")
        self.assertEqual(f.severity, "high")

    def test_tls_inconsistency_is_medium(self):
        pr = analyze([mk("a", network=True, has_tls=True),
                      mk("b", network=True, has_tls=False)])
        f = next(f for f in pr.findings if f.rule == "fleet.tls_inconsistency")
        self.assertEqual(f.severity, "medium")


# --------------------------------------------------------------------------
# PostureReport scoring / grade / rollup
# --------------------------------------------------------------------------
class TestPostureReport(unittest.TestCase):
    def test_empty_fleet_is_perfect(self):
        pr = analyze([])
        self.assertEqual(pr.fleet_score, 100)
        self.assertEqual(pr.grade, "A")
        self.assertFalse(pr.failed)

    def test_clean_fleet_grade_a(self):
        pr = analyze([mk("a", network=False, score=100),
                      mk("b", network=False, score=100)])
        self.assertEqual(pr.grade, "A")
        self.assertEqual(pr.fleet_score, 100)

    def test_score_is_penalized_by_correlations(self):
        clean = analyze([mk("a", network=True, has_auth=True, score=90),
                         mk("b", network=True, has_auth=True, score=90)])
        dirty = analyze([mk("a", network=True, has_auth=True, score=90),
                         mk("b", network=True, has_auth=False, score=90)])
        self.assertLess(dirty.fleet_score, clean.fleet_score)

    def test_score_never_negative(self):
        sec = "sk_live_SHAREDSHAREDSHARED"
        pr = analyze([
            mk("a", network=True, has_auth=True, has_tls=True, failed=True, score=0,
               rules=["tool.shell_exec"], tool_names=["x"], secrets=[sec]),
            mk("b", network=True, has_auth=False, has_tls=False, failed=True, score=0,
               rules=["transport.no_auth", "transport.bind_all"],
               tool_names=["x"], secrets=[sec]),
        ])
        self.assertGreaterEqual(pr.fleet_score, 0)

    def test_grade_boundaries(self):
        cases = [(95, "A"), (85, "B"), (72, "C"), (60, "D"), (10, "F")]
        for score, want in cases:
            pr = PostureReport(target="x", servers=[mk("s", score=score)])
            self.assertEqual(pr.grade, want, f"score {score}")

    def test_failed_true_when_high(self):
        pr = analyze([mk("a", network=True, has_auth=True),
                      mk("b", network=True, has_auth=False)])
        self.assertTrue(pr.failed)

    def test_top_remediation_is_worst_finding(self):
        sec = "sk_live_TOPTOPTOPTOP"
        pr = analyze([mk("a", network=True, has_auth=True, secrets=[sec]),
                      mk("b", network=True, has_auth=False, secrets=[sec])])
        # shared_secret (critical) should outrank trust-tier (high).
        self.assertIn("secret store", pr.top_remediation)

    def test_top_remediation_none_when_clean(self):
        pr = analyze([mk("a"), mk("b")])
        self.assertIsNone(pr.top_remediation)

    def test_counts_aggregate(self):
        sec = "sk_live_CCCCCCCCCCCC"
        pr = analyze([mk("a", network=True, has_auth=True, secrets=[sec]),
                      mk("b", network=True, has_auth=False, secrets=[sec])])
        self.assertEqual(pr.counts["critical"], 1)
        self.assertGreaterEqual(pr.counts["high"], 1)

    def test_network_count(self):
        pr = analyze([mk("a", network=True), mk("b", network=False),
                      mk("c", network=True)])
        self.assertEqual(pr.network_count, 2)
        self.assertEqual(pr.server_count, 3)

    def test_findings_sorted_by_severity(self):
        sec = "sk_live_SORTSORTSORT"
        pr = analyze([mk("a", network=True, has_auth=True, secrets=[sec],
                         tool_names=["x"]),
                      mk("b", network=True, has_auth=False, secrets=[sec],
                         tool_names=["x"])])
        sevs = [f.severity for f in pr.findings]
        self.assertEqual(sevs[0], "critical")
        # non-decreasing severity order
        from mcpharden.core import SEVERITY_ORDER
        ranks = [SEVERITY_ORDER[s] for s in sevs]
        self.assertEqual(ranks, sorted(ranks))


# --------------------------------------------------------------------------
# to_dict serialization
# --------------------------------------------------------------------------
class TestToDict(unittest.TestCase):
    def test_to_dict_round_trips_json(self):
        pr = analyze([mk("a", network=True, has_auth=True),
                      mk("b", network=True, has_auth=False)])
        d = pr.to_dict()
        s = json.dumps(d)  # must be serializable
        self.assertIn("fleet_score", json.loads(s))

    def test_to_dict_has_servers_and_correlations(self):
        pr = analyze([mk("a", network=True, has_auth=True),
                      mk("b", network=True, has_auth=False)])
        d = pr.to_dict()
        self.assertEqual(len(d["servers"]), 2)
        self.assertTrue(any(c["rule"] == "fleet.trust_tier_inconsistency"
                            for c in d["correlations"]))

    def test_to_dict_grade_present(self):
        d = analyze([]).to_dict()
        self.assertEqual(d["grade"], "A")

    def test_to_dict_no_full_secret(self):
        sec = "sk_live_NEVERLEAKTHIS9"
        d = analyze([mk("a", secrets=[sec]), mk("b", secrets=[sec])]).to_dict()
        self.assertNotIn(sec, json.dumps(d))


# --------------------------------------------------------------------------
# summarize() — manifest -> ServerSummary
# --------------------------------------------------------------------------
class TestSummarize(unittest.TestCase):
    def _summ(self, m):
        report = audit_manifest(m, source="<t>")
        return summarize(report, m)

    def test_network_detected_for_http(self):
        s = self._summ({"name": "x", "transport": {"type": "http"}})
        self.assertTrue(s.network)
        self.assertEqual(s.transport_type, "http")

    def test_stdio_is_local(self):
        s = self._summ({"name": "x", "transport": "stdio"})
        self.assertFalse(s.network)

    def test_tool_names_extracted(self):
        s = self._summ({"name": "x", "transport": "stdio",
                        "tools": [{"name": "foo", "description": "long enough desc"}]})
        self.assertIn("foo", s.tool_names)

    def test_secret_extracted(self):
        m = {"name": "x", "transport": "stdio",
             "auth": {"token": "ghp_ABCDEFGHIJKLMNOPQRST1234"}}
        report = audit_manifest(m, source="<t>")
        # core stashes _raw_text; emulate load by injecting raw text
        m["_raw_text"] = json.dumps(m)
        s = summarize(report, m)
        self.assertTrue(any("ghp_" in x for x in s.secrets))

    def test_placeholder_secret_ignored(self):
        m = {"name": "x", "transport": "stdio"}
        m["_raw_text"] = '{"api_key": "ghp_YOUR_TOKEN_HERE_PLACEHOLDER"}'
        report = audit_manifest(m, source="<t>")
        s = summarize(report, m)
        self.assertEqual(s.secrets, ())

    def test_has_auth_reflects_transport_auth(self):
        s = self._summ({"name": "x", "transport": {"type": "http", "auth": {"type": "oauth2"}}})
        self.assertTrue(s.has_auth)

    def test_has_auth_false_for_none(self):
        s = self._summ({"name": "x", "transport": "http", "auth": "none"})
        self.assertFalse(s.has_auth)


# --------------------------------------------------------------------------
# assess() over committed fixtures
# --------------------------------------------------------------------------
class TestAssessFixtures(unittest.TestCase):
    def test_dirty_fleet_fails(self):
        pr = assess(FLEET)
        self.assertTrue(pr.failed)
        self.assertEqual(pr.server_count, 4)

    def test_dirty_fleet_finds_all_classes(self):
        pr = assess(FLEET)
        r = rules_of(pr)
        self.assertIn("fleet.shared_secret", r)
        self.assertIn("fleet.tool_collision", r)
        self.assertIn("fleet.lateral_movement", r)
        self.assertIn("fleet.trust_tier_inconsistency", r)

    def test_dirty_fleet_grade_low(self):
        pr = assess(FLEET)
        self.assertIn(pr.grade, ("D", "F"))

    def test_clean_fleet_passes(self):
        pr = assess(CLEAN_FLEET)
        self.assertFalse(pr.failed)
        self.assertEqual(rules_of(pr), set())

    def test_clean_fleet_grade_a(self):
        pr = assess(CLEAN_FLEET)
        self.assertEqual(pr.grade, "A")

    def test_assess_single_file(self):
        pr = assess(os.path.join(CLEAN_FLEET, "svc-a.json"))
        self.assertEqual(pr.server_count, 1)
        self.assertFalse(pr.failed)

    def test_assess_skips_unreadable(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "good.json"), "w") as fh:
                json.dump({"name": "g", "transport": "stdio"}, fh)
            with open(os.path.join(d, "bad.json"), "w") as fh:
                fh.write("{not json")
            pr = assess(d)
            self.assertEqual(pr.server_count, 1)  # bad one skipped


# --------------------------------------------------------------------------
# CLI integration
# --------------------------------------------------------------------------
class TestPostureCLI(unittest.TestCase):
    def _run(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(argv)
        return rc, buf.getvalue()

    def test_cli_table(self):
        rc, out = self._run(["posture", FLEET])
        self.assertIn("fleet posture", out)
        self.assertIn("grade", out)

    def test_cli_json_valid(self):
        rc, out = self._run(["posture", FLEET, "--format", "json"])
        d = json.loads(out)
        self.assertEqual(d["server_count"], 4)
        self.assertIn("correlations", d)

    def test_cli_html(self):
        rc, out = self._run(["posture", FLEET, "--format", "html"])
        self.assertIn("<!doctype html>", out)
        self.assertIn("fleet posture", out)

    def test_cli_clean_fleet_rc_zero(self):
        rc, _ = self._run(["posture", CLEAN_FLEET])
        self.assertEqual(rc, 0)

    def test_cli_fail_on_high(self):
        rc, _ = self._run(["posture", FLEET, "--fail-on", "high"])
        self.assertEqual(rc, 1)

    def test_cli_fail_on_critical(self):
        rc, _ = self._run(["posture", FLEET, "--fail-on", "critical"])
        self.assertEqual(rc, 1)

    def test_cli_fail_on_clean_passes(self):
        rc, _ = self._run(["posture", CLEAN_FLEET, "--fail-on", "critical"])
        self.assertEqual(rc, 0)

    def test_cli_min_grade_b_fails_dirty(self):
        rc, _ = self._run(["posture", FLEET, "--min-grade", "B"])
        self.assertEqual(rc, 1)

    def test_cli_min_grade_f_passes_anything(self):
        rc, _ = self._run(["posture", FLEET, "--min-grade", "F"])
        self.assertEqual(rc, 0)

    def test_cli_min_grade_a_clean_passes(self):
        rc, _ = self._run(["posture", CLEAN_FLEET, "--min-grade", "A"])
        self.assertEqual(rc, 0)

    def test_cli_out_file(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "p.json")
            rc, _ = self._run(["posture", FLEET, "--format", "json", "--out", out])
            self.assertTrue(os.path.exists(out))
            with open(out) as fh:
                self.assertIn("fleet_score", json.load(fh))

    def test_cli_missing_target_errors(self):
        rc, _ = self._run(["posture", os.path.join(REPO_ROOT, "no_such_dir_xyz")])
        self.assertEqual(rc, 2)


# --------------------------------------------------------------------------
# MCP server tool exposure
# --------------------------------------------------------------------------
class TestPostureOverMCP(unittest.TestCase):
    def test_posture_listed_as_tool(self):
        from mcpharden import mcp_server
        resp = mcp_server.handle_request(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        names = {t["name"] for t in resp["result"]["tools"]}
        self.assertIn("posture", names)

    def test_posture_call_returns_json(self):
        from mcpharden import mcp_server
        resp = mcp_server.handle_request({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "posture", "arguments": {"target": FLEET}},
        })
        text = resp["result"]["content"][0]["text"]
        d = json.loads(text)
        self.assertIn("fleet_score", d)
        self.assertTrue(resp["result"]["isError"])  # dirty fleet -> error

    def test_posture_call_clean_not_error(self):
        from mcpharden import mcp_server
        resp = mcp_server.handle_request({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "posture", "arguments": {"target": CLEAN_FLEET}},
        })
        self.assertFalse(resp["result"]["isError"])

    def test_posture_call_missing_target(self):
        from mcpharden import mcp_server
        resp = mcp_server.handle_request({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "posture", "arguments": {}},
        })
        self.assertIn("error", resp)


# --------------------------------------------------------------------------
# render helpers (don't crash, contain expected content)
# --------------------------------------------------------------------------
class TestRenderers(unittest.TestCase):
    def test_render_table_clean(self):
        out = posture.render_table(analyze([mk("a"), mk("b")]))
        self.assertIn("No cross-server correlation findings.", out)
        self.assertIn("RESULT: PASS", out)

    def test_render_table_dirty(self):
        pr = assess(FLEET)
        out = posture.render_table(pr)
        self.assertIn("CROSS-SERVER CORRELATIONS", out)
        self.assertIn("TOP PRIORITY", out)
        self.assertIn("RESULT: FAIL", out)

    def test_render_html_escapes(self):
        pr = PostureReport(target="x", servers=[mk("a<script>")])
        html = posture.render_html(pr)
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_render_html_has_grade(self):
        html = posture.render_html(assess(FLEET))
        self.assertIn("Top priority", html)


if __name__ == "__main__":
    unittest.main()

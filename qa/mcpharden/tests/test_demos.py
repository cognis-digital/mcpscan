"""Tests for the runnable demo scenarios and their bundled fixtures.

Every scenario must run offline, exit cleanly, and exercise the real API against
the sample manifests in demos/fixtures/. These tests assert both that the demos
run and that the fixtures still produce the findings the demos narrate, so the
demos can't silently drift from the engine.
"""

import io
import os
import sys
import unittest
from contextlib import redirect_stdout

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMOS = os.path.join(REPO_ROOT, "demos")
FIXTURES = os.path.join(DEMOS, "fixtures")
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, DEMOS)

from mcpharden import (  # noqa: E402
    audit_path,
    posture,
    build_baseline,
    diff_baseline,
    load_manifest,
    audit_config_path,
    vulndb,
)


def _fx(*parts):
    return os.path.join(FIXTURES, *parts)


class TestDemoScenariosRun(unittest.TestCase):
    """Each scenario's main() runs offline and prints output without raising."""

    SCENARIOS = [
        "01_ai_platform_review",
        "02_server_author_lint",
        "03_auditor_cve_mapping",
        "04_blue_team_rugpull",
        "05_red_team_fleet_posture",
    ]

    def test_each_scenario_runs(self):
        import importlib

        for name in self.SCENARIOS:
            mod = importlib.import_module(name)
            buf = io.StringIO()
            with redirect_stdout(buf):
                mod.main()
            self.assertTrue(buf.getvalue().strip(), f"{name} produced no output")

    def test_run_all(self):
        import importlib

        run_all = importlib.import_module("run_all")
        buf = io.StringIO()
        with redirect_stdout(buf):
            run_all.main()
        self.assertIn("All demo scenarios completed", buf.getvalue())


class TestFixtureFindings(unittest.TestCase):
    """The fixtures must keep producing the findings the demos describe."""

    def test_hardened_server_passes(self):
        r = audit_path(_fx("hardened-server.json"))
        self.assertFalse(r.failed, r.to_dict())
        self.assertEqual(r.score, 100)

    def test_poisoned_server_is_tool_poisoning(self):
        r = audit_path(_fx("poisoned-server.json"))
        rules = {f.rule for f in r.findings}
        self.assertIn("tool.injection_in_description", rules)
        self.assertIn("tool.mutable_registration", rules)
        # And it maps to the catalog class the auditor demo cites.
        self.assertEqual(vulndb.BY_RULE["tool.injection_in_description"].id, "MCP-TP-01")

    def test_public_rce_server_is_critical(self):
        r = audit_path(_fx("public-rce-server.json"))
        rules = {f.rule for f in r.findings}
        self.assertTrue(r.failed)
        for expected in ("transport.bind_all", "tool.shell_exec",
                         "manifest.embedded_secret", "transport.cors_wildcard"):
            self.assertIn(expected, rules)

    def test_rugpull_diff_detects_drift(self):
        base = build_baseline(load_manifest(_fx("payments-trusted.json")))
        report = diff_baseline(base, load_manifest(_fx("payments-rugpulled.json")))
        rules = {f.rule for f in report.findings}
        self.assertTrue(report.failed)
        self.assertIn("rugpull.tool_changed", rules)   # send_payment mutated
        self.assertIn("rugpull.tool_added", rules)     # export_history added

    def test_fleet_posture_correlations(self):
        pr = posture.assess(_fx("fleet"))
        rules = {f.rule for f in pr.findings}
        self.assertIn("fleet.shared_secret", rules)
        self.assertIn("fleet.tool_collision", rules)
        self.assertIn("fleet.lateral_movement", rules)
        self.assertEqual(pr.grade, "F")
        self.assertTrue(pr.failed)

    def test_client_config_findings(self):
        r = audit_config_path(_fx("claude_desktop_config.json"))
        rules = {f.rule for f in r.findings}
        self.assertIn("config.unpinned_command", rules)
        self.assertIn("config.secret_in_env", rules)
        self.assertIn("config.shell_exec", rules)
        self.assertIn("config.auto_approve", rules)


if __name__ == "__main__":
    unittest.main()

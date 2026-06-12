"""v0.3 tests for the 4 new MCP-config-hygiene + shell-tool rules.

Each rule must FIRE on a crafted vulnerable sample and must NOT false-positive
on the matching clean sample. Standard library only, no network.

Rules under test:
  * config.hardcoded_secret  (CWE-798 / LLM02) — baked-in bearer/secret in cfg
  * config.open_bind_no_auth (CWE-306 / LLM06) — 0.0.0.0 bind, no auth
  * config.no_tls_remote     (CWE-319 / LLM02) — cleartext http:// remote
  * static.shell_tool_input  (CWE-78  / LLM06) — tool param -> shell subprocess
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcpscan.core import (
    RULE_META,
    scan_config_secret,
    scan_no_tls_remote,
    scan_open_bind,
    scan_path,
    scan_python_source,
    _scan_config,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CFG_DIR = os.path.join(REPO_ROOT, "demos", "03-config")


def _read(name):
    with open(os.path.join(CFG_DIR, name), encoding="utf-8") as fh:
        return fh.read()


def _cfg_rules(src):
    return {f.rule for f in _scan_config("c.json", src)}


def _py_rules(src):
    return {f.rule for f in scan_python_source("s.py", src)}


# --- Rule 1: hardcoded bearer / secret in MCP config ----------------------

class TestHardcodedSecretInConfig(unittest.TestCase):
    def test_fires_on_env_secret(self):
        cfg = json.dumps({"mcpServers": {"s": {
            "env": {"GITHUB_API_KEY": "sk-live-9f8e7d6c5b4a3f2e1d0c9b8a"}}}})
        self.assertIn("config.hardcoded_secret",
                      {f.rule for f in scan_config_secret("c.json", cfg)})

    def test_fires_on_bearer_header(self):
        cfg = json.dumps({"mcpServers": {"s": {
            "headers": {"Authorization": "Bearer s3cr3tT0ken1234567890abc"}}}})
        self.assertIn("config.hardcoded_secret",
                      {f.rule for f in scan_config_secret("c.json", cfg)})

    def test_fires_on_arg_token(self):
        cfg = json.dumps({"mcpServers": {"s": {
            "args": ["--token", "ghp_AbCdEf0123456789AbCdEf0123456789abcd"]}}})
        self.assertIn("config.hardcoded_secret",
                      {f.rule for f in scan_config_secret("c.json", cfg)})

    def test_env_placeholder_is_clean(self):
        cfg = json.dumps({"mcpServers": {"s": {
            "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"},
            "headers": {"Authorization": "Bearer ${REMOTE_TOKEN}"}}}})
        self.assertEqual(scan_config_secret("c.json", cfg), [])

    def test_non_string_values_do_not_crash(self):
        cfg = json.dumps({"mcpServers": {"s": {
            "env": {"PORT": 8080, "DEBUG": True},
            "args": [1, 2, None]}}})
        self.assertEqual(scan_config_secret("c.json", cfg), [])

    def test_clean_demo_config_silent(self):
        self.assertEqual(_cfg_rules(_read(".mcp.clean.json")), set())

    def test_vulnerable_demo_config_flags_secret(self):
        self.assertIn("config.hardcoded_secret",
                      _cfg_rules(_read("mcp.json")))


# --- Rule 2: 0.0.0.0 bind with no auth ------------------------------------

class TestOpenBindNoAuth(unittest.TestCase):
    def test_fires_on_keyword_bind(self):
        src = "def serve():\n    server = HTTPServer(host='0.0.0.0', port=80)\n"
        self.assertIn("config.open_bind_no_auth",
                      {f.rule for f in scan_open_bind("s.py", src)})

    def test_fires_on_positional_run(self):
        src = "def serve():\n    app.run('0.0.0.0', 8931)\n"
        self.assertIn("config.open_bind_no_auth",
                      {f.rule for f in scan_open_bind("s.py", src)})

    def test_auth_present_suppresses(self):
        src = ("VERIFY_TOKEN = True\n"
               "def serve():\n    app.run('0.0.0.0', 8931)\n")
        self.assertEqual(scan_open_bind("s.py", src), [])

    def test_loopback_bind_is_clean(self):
        src = "def serve():\n    app.run('127.0.0.1', 8931)\n"
        self.assertEqual(scan_open_bind("s.py", src), [])

    def test_vulnerable_demo_py_flags_open_bind(self):
        self.assertIn("config.open_bind_no_auth",
                      _py_rules(_read("shell_tool_server.py")))

    def test_clean_demo_py_silent_open_bind(self):
        self.assertNotIn("config.open_bind_no_auth",
                         _py_rules(_read("clean_server.py")))


# --- Rule 3: missing TLS on remote transport ------------------------------

class TestNoTlsRemote(unittest.TestCase):
    def test_fires_on_remote_http(self):
        cfg = json.dumps({"mcpServers": {"r": {
            "transport": "sse", "url": "http://tools.example.com:8080/sse"}}})
        self.assertIn("config.no_tls_remote",
                      {f.rule for f in scan_no_tls_remote("c.json", cfg)})

    def test_https_is_clean(self):
        cfg = json.dumps({"mcpServers": {"r": {
            "url": "https://tools.example.com/sse"}}})
        self.assertEqual(scan_no_tls_remote("c.json", cfg), [])

    def test_loopback_http_is_clean(self):
        cfg = json.dumps({"mcpServers": {"r": {
            "url": "http://127.0.0.1:8080/sse"}}})
        self.assertEqual(scan_no_tls_remote("c.json", cfg), [])

    def test_dedupes_per_host(self):
        cfg = ('{"url":"http://a.example/x","endpoint":"http://a.example/y"}')
        hits = [f for f in scan_no_tls_remote("c.json", cfg)
                if f.rule == "config.no_tls_remote"]
        self.assertEqual(len(hits), 1)  # one finding per remote host

    def test_vulnerable_demo_config_flags_no_tls(self):
        self.assertIn("config.no_tls_remote",
                      _cfg_rules(_read("mcp.json")))


# --- Rule 4: shell tool passes user input to subprocess -------------------

class TestShellToolInput(unittest.TestCase):
    def test_fires_on_shell_true_concat(self):
        src = ("import subprocess\n"
               "def run_command(user_cmd):\n"
               "    return subprocess.run('sh -c ' + user_cmd, shell=True)\n")
        self.assertIn("static.shell_tool_input", _py_rules(src))

    def test_fires_on_os_system_param(self):
        src = ("import os\n"
               "def ping(host):\n    return os.system('ping ' + host)\n")
        self.assertIn("static.shell_tool_input", _py_rules(src))

    def test_argv_list_no_shell_is_clean(self):
        src = ("import subprocess\n"
               "def run(args):\n"
               "    return subprocess.run(['ls', '-la'], shell=False)\n")
        self.assertNotIn("static.shell_tool_input", _py_rules(src))

    def test_no_param_constant_command_is_clean(self):
        src = ("import subprocess\n"
               "def run():\n"
               "    return subprocess.run('ls -la', shell=True)\n")
        self.assertNotIn("static.shell_tool_input", _py_rules(src))

    def test_vulnerable_demo_py_flags_shell_tool(self):
        self.assertIn("static.shell_tool_input",
                      _py_rules(_read("shell_tool_server.py")))

    def test_clean_demo_py_silent_shell_tool(self):
        self.assertNotIn("static.shell_tool_input",
                         _py_rules(_read("clean_server.py")))


# --- Taxonomy + integration ----------------------------------------------

class TestNewRuleTaxonomy(unittest.TestCase):
    def test_all_new_rules_mapped(self):
        for rule, cwe, owasp in (
            ("config.hardcoded_secret", "CWE-798", "LLM02"),
            ("config.open_bind_no_auth", "CWE-306", "LLM06"),
            ("config.no_tls_remote", "CWE-319", "LLM02"),
            ("static.shell_tool_input", "CWE-78", "LLM06"),
        ):
            self.assertIn(rule, RULE_META)
            self.assertEqual(RULE_META[rule]["cwe"], cwe)
            self.assertEqual(RULE_META[rule]["owasp_llm"], owasp)
            self.assertTrue(RULE_META[rule]["ms_taxonomy"])

    def test_finding_autopopulates_cwe(self):
        f = scan_config_secret("c.json", json.dumps({"mcpServers": {"s": {
            "headers": {"Authorization": "Bearer s3cr3tT0ken1234567890abc"}}}}))[0]
        self.assertEqual(f.cwe, "CWE-798")
        self.assertEqual(f.owasp_llm, "LLM02")
        self.assertTrue(f.ms_taxonomy)


class TestConfigDirIntegration(unittest.TestCase):
    def test_scan_path_picks_up_named_config(self):
        # a .mcp.json basename is auto-discovered by scan_path.
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "mcp.json")
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(_read("mcp.json"))
            report = scan_path(d)
        rules = {f.rule for f in report.findings}
        self.assertIn("config.hardcoded_secret", rules)
        self.assertIn("config.no_tls_remote", rules)


if __name__ == "__main__":
    unittest.main()

"""v0.2 tests: deep rule pack, AST taint dataflow, scan-url, AI merge
(fail-open), badge + HTML exporters, CWE/OWASP/MS-taxonomy mapping.

Standard library only. The AI tests deliberately run with NO backend
configured to prove the deterministic-by-default + fail-open contract."""

import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcpscan.core import (
    Finding,
    Report,
    ScanError,
    scan_js_source,
    scan_path,
    scan_python_source,
    scan_url,
    to_badge,
    to_html,
    to_sarif,
    _scan_manifest,
)


def _rules(src):
    return {f.rule for f in scan_python_source("t.py", src)}


class TestDeepRulePack(unittest.TestCase):
    def test_deserialization(self):
        self.assertIn("static.deserialization",
                      _rules("import pickle\ndef f(b):\n    return pickle.loads(b)\n"))

    def test_yaml_safe_loader_is_clean(self):
        src = "import yaml\ndef f(b):\n    return yaml.load(b, Loader=yaml.SafeLoader)\n"
        self.assertNotIn("static.deserialization", _rules(src))

    def test_ssti(self):
        src = ("from jinja2 import Template\n"
               "def f(name):\n    return Template('Hi ' + name).render()\n")
        self.assertIn("static.ssti", _rules(src))

    def test_path_traversal(self):
        self.assertIn("static.path_traversal",
                      _rules("def f(name):\n    return open(name).read()\n"))

    def test_secret_exposure(self):
        src = 'AWS = "AKIAIOSFODNN7EXAMPLE"\n'
        self.assertIn("static.secret_exposure", _rules(src))

    def test_confused_deputy_header_forward(self):
        src = ("import requests\n"
               "def f(authorization):\n"
               "    return requests.get('https://x', headers={'Authorization': authorization})\n")
        rules = _rules(src)
        self.assertTrue("static.confused_deputy" in rules
                        or "static.token_passthrough" in rules)

    def test_token_passthrough(self):
        src = ("import requests\n"
               "def f(token):\n    return requests.post('https://x', token=token)\n")
        self.assertIn("static.token_passthrough", _rules(src))

    def test_js_ssti_and_fs(self):
        rules = scan_js_source("s.js", "handlebars.compile(userTpl);\n"
                                        "fs.readFileSync(userPath);\n")
        names = {f.rule for f in rules}
        self.assertIn("static.ssti", names)
        self.assertIn("static.path_traversal", names)

    def test_clean_source_still_clean(self):
        src = ('def echo(text: str) -> str:\n'
               '    """Echo text. No side effects."""\n    return text\n')
        self.assertEqual(_rules(src), set())


class TestTaintDataflow(unittest.TestCase):
    def test_multiline_command_injection(self):
        # source and sink on DIFFERENT lines, joined via a variable.
        src = ("import os\n"
               "def tool(name):\n"
               "    cmd = 'ls ' + name\n"
               "    os.system(cmd)\n")
        self.assertIn("taint.command_injection", _rules(src))

    def test_request_source_to_eval(self):
        src = ("from flask import request\n"
               "def tool():\n"
               "    x = request.args.get('x')\n"
               "    return eval(x)\n")
        self.assertIn("taint.code_injection", _rules(src))

    def test_constant_is_not_tainted(self):
        src = ("import os\n"
               "def tool():\n"
               "    cmd = 'ls -la'\n"
               "    os.system(cmd)\n")
        # static.command_exec (literal) may fire, but NOT the taint rule.
        self.assertNotIn("taint.command_injection", _rules(src))

    def test_fstring_propagation_ssrf(self):
        src = ("import requests\n"
               "def tool(host):\n"
               "    url = f'https://{host}/api'\n"
               "    return requests.get(url)\n")
        self.assertIn("taint.ssrf", _rules(src))


class TestManifestDrift(unittest.TestCase):
    def test_requirements_unpinned(self):
        out = _scan_manifest("requirements.txt", "requests\nflask==2.0.0\n")
        msgs = [f.message for f in out]
        self.assertTrue(any("requests" in m for m in msgs))
        self.assertFalse(any("flask" in m for m in msgs))  # pinned → clean

    def test_package_json_floating(self):
        pkg = json.dumps({"dependencies": {"left-pad": "^1.0.0",
                                            "exact": "1.2.3"}})
        out = _scan_manifest("package.json", pkg)
        msgs = [f.message for f in out]
        self.assertTrue(any("left-pad" in m for m in msgs))
        self.assertFalse(any("exact" in m for m in msgs))


class TestTaxonomyMapping(unittest.TestCase):
    def test_cwe_and_owasp_populated(self):
        f = [x for x in scan_python_source(
            "t.py", "def f(x):\n    return eval(x)\n")
            if x.rule == "taint.code_injection"][0]
        self.assertEqual(f.cwe, "CWE-95")
        self.assertEqual(f.owasp_llm, "LLM06")
        self.assertTrue(f.ms_taxonomy)

    def test_sarif_carries_cwe(self):
        r = Report(source="x", target_kind="source")
        r.findings = [Finding("static.ssrf", "high", "m", "f.py:3", "fix")]
        doc = json.loads(to_sarif(r))
        rule = doc["runs"][0]["tool"]["driver"]["rules"][0]
        self.assertEqual(rule["properties"]["cwe"], "CWE-918")
        self.assertEqual(rule["properties"]["owasp-llm"], "LLM06")


class TestExporters(unittest.TestCase):
    def _report(self):
        r = Report(source="demo", target_kind="source", files_scanned=1)
        r.findings = [Finding("static.command_exec", "critical", "boom",
                              "f.py:1", "fix")]
        return r

    def test_badge_critical_red(self):
        b = json.loads(to_badge(self._report()))
        self.assertEqual(b["schemaVersion"], 1)
        self.assertEqual(b["label"], "mcpscan")
        self.assertEqual(b["color"], "red")
        self.assertIn("critical", b["message"])

    def test_badge_clean_green(self):
        r = Report(source="x", target_kind="source")
        b = json.loads(to_badge(r))
        self.assertEqual(b["color"], "brightgreen")
        self.assertEqual(b["message"], "no findings")

    def test_html_self_contained(self):
        html = to_html(self._report())
        self.assertTrue(html.lstrip().startswith("<!doctype html>"))
        self.assertIn("mcpscan", html)
        self.assertIn("static.command_exec", html)
        self.assertNotIn("http://", html.split("informationUri")[0]
                         if "informationUri" in html else "")  # no external CSS/JS

    def test_html_escapes(self):
        r = Report(source="x", target_kind="source")
        r.findings = [Finding("static.tool_poisoning", "critical",
                              "<script>alert(1)</script>", "f.py:1")]
        html = to_html(r)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)


class TestAIDefaultOff(unittest.TestCase):
    """With no COGNIS_AI_* env, --ai must fail-open to rules only."""

    def setUp(self):
        for k in ("COGNIS_AI_BACKEND", "COGNIS_AI_ENDPOINT", "COGNIS_AI_MODEL"):
            os.environ.pop(k, None)

    def _demo_file(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        return os.path.join(root, "demos", "01-basic",
                            "vulnerable_mcp_server.py")

    def test_ai_off_deterministic(self):
        r1 = scan_path(self._demo_file(), use_ai=False)
        r2 = scan_path(self._demo_file(), use_ai=False)
        self.assertEqual(r1.to_dict()["findings"], r2.to_dict()["findings"])
        self.assertFalse(r1.ai_used)

    def test_ai_on_but_no_backend_does_not_crash(self):
        r = scan_path(self._demo_file(), use_ai=True)
        self.assertFalse(r.ai_used)               # backend not configured
        self.assertTrue(r.ai_note)                # explains why
        self.assertFalse(any(f.source == "ai" for f in r.findings))
        # rule findings still present
        self.assertTrue(any(f.rule.startswith("static.") for f in r.findings))

    def test_ai_on_backend_down_endpoint_set(self):
        # endpoint set but nothing listening → health() False → fail-open
        os.environ["COGNIS_AI_ENDPOINT"] = "http://127.0.0.1:9/v1"
        os.environ["COGNIS_AI_MODEL"] = "ghost"
        try:
            r = scan_path(self._demo_file(), use_ai=True)
        finally:
            os.environ.pop("COGNIS_AI_ENDPOINT", None)
            os.environ.pop("COGNIS_AI_MODEL", None)
        self.assertFalse(r.ai_used)
        self.assertIn("unreachable", r.ai_note)
        self.assertTrue(any(f.rule.startswith("static.") for f in r.findings))


# --- scan-url: serve a vulnerable file over local HTTP and scan it --------

class _FileHandler(BaseHTTPRequestHandler):
    payload = (b"import os\n"
               b"def tool(name):\n"
               b"    os.system('rm ' + name)\n")

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(self.payload)))
        self.end_headers()
        self.wfile.write(self.payload)


class _Srv:
    def __enter__(self):
        self.httpd = HTTPServer(("127.0.0.1", 0), _FileHandler)
        self.port = self.httpd.server_address[1]
        self.t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.t.start()
        return f"http://127.0.0.1:{self.port}/server.py"

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()


class TestScanUrl(unittest.TestCase):
    def test_scan_url_flags_rce(self):
        with _Srv() as url:
            report = scan_url(url, timeout=5)
        rules = {f.rule for f in report.findings}
        self.assertEqual(report.target_kind, "url")
        self.assertIn("static.command_exec", rules)
        self.assertIn("taint.command_injection", rules)

    def test_scan_url_rejects_non_http(self):
        with self.assertRaises(ScanError):
            scan_url("ftp://nope/x.py")


if __name__ == "__main__":
    unittest.main()

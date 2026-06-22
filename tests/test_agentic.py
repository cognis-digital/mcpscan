"""OWASP Top 10 for Agentic Applications (2026) taxonomy + finding mapping."""

import json

from mcpscan.agentic import CATALOG, BY_ID, asi_for, asi_label


def test_catalog_is_ten_unique_classes():
    assert len(CATALOG) == 10
    ids = [c.id for c in CATALOG]
    assert ids == [f"ASI{i:02d}" for i in range(1, 11)]
    assert all(c.title and c.summary for c in CATALOG)


def test_ms_taxonomy_mapping_primary():
    assert asi_for(ms_taxonomy="agent-tool-poisoning").id == "ASI02"
    assert asi_for(ms_taxonomy="agent-impersonation").id == "ASI03"
    assert asi_for(ms_taxonomy="agent-knowledge-poisoning").id == "ASI06"
    assert asi_for(ms_taxonomy="agent-confused-deputy").id == "ASI03"


def test_owasp_llm_fallback():
    assert asi_for(owasp_llm="LLM01").id == "ASI01"   # prompt injection -> planning
    assert asi_for(owasp_llm="LLM06").id == "ASI02"   # excessive agency -> tool misuse
    assert asi_for(owasp_llm="LLM10").id == "ASI08"   # unbounded -> cascading


def test_cwe_exec_to_code_execution():
    assert asi_for(cwe="CWE-78").id == "ASI05"        # command injection
    assert asi_for(cwe="CWE-502").id == "ASI05"       # deserialization
    assert asi_for(cwe="CWE-79").id == "ASI02"        # other weakness -> tool bucket


def test_precedence_ms_over_llm():
    # MS taxonomy wins over the OWASP-LLM fallback
    assert asi_for(ms_taxonomy="agent-knowledge-poisoning", owasp_llm="LLM06").id == "ASI06"


def test_unmappable_returns_none():
    assert asi_for() is None


def test_asi_label_on_finding_like():
    class F:
        cwe = "CWE-78"; owasp_llm = "LLM06"; ms_taxonomy = "agent-excessive-agency"
    assert asi_label(F()) == "ASI02"


def test_cli_taxonomy_json(capsys):
    from mcpscan.cli import main
    rc = main(["taxonomy", "--format", "json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 10 and data[0]["id"] == "ASI01"


def test_cli_scan_json_carries_asi(tmp_path, capsys):
    # a tool that shells out -> a finding -> should carry an owasp_asi tag
    src = tmp_path / "server.py"
    src.write_text("import os\n\ndef run(cmd):\n    os.system(cmd)\n", encoding="utf-8")
    from mcpscan.cli import main
    main(["scan", str(src), "--format", "json"])
    data = json.loads(capsys.readouterr().out)
    assert any(f.get("owasp_asi", "").startswith("ASI") for f in data.get("findings", []))

"""Scenario 3 - security auditors / compliance.

An auditor does not just want "this is bad" — they want each finding tied to a
named MCP attack class and the real CVE / advisory behind it, in a form that
drops into a report and a SARIF code-scanning upload. This demo audits a poisoned
server, maps every finding to the mcpharden vulnerability catalog (class id +
CVEs), and emits the SARIF a pipeline would attach to the build.
"""
import json

from _common import fixture, rule, sev

from mcpharden import audit_path, vulndb, to_sarif


def main() -> None:
    rule("AUDITOR VIEW  -  every finding tied to an MCP attack class + CVE")

    report = audit_path(fixture("poisoned-server.json"))
    print(f"\nServer '{report.server_name}'  score {report.score}/100  "
          f"({'FAIL' if report.failed else 'PASS'})\n")

    for f in report.findings:
        vc = vulndb.BY_RULE.get(f.rule)
        print(f"  [{sev(f.severity)}] {f.rule}")
        if vc:
            cves = ", ".join(vc.cves) if vc.cves else "(no CVE; documented advisory)"
            print(f"        class : {vc.id}  {vc.name}")
            print(f"        CVE   : {cves}")
            print(f"        ref   : {vc.references[0]}")
        else:
            print("        class : (no catalog mapping)")
        print()

    print(f"Catalog coverage: {len(vulndb.CATALOG)} MCP vulnerability classes, "
          f"{len(vulndb.all_cves())} distinct CVEs tracked.")

    sarif = to_sarif([report])
    n_rules = len(sarif["runs"][0]["tool"]["driver"]["rules"])
    n_results = len(sarif["runs"][0]["results"])
    print(f"\nSARIF 2.1.0 emitted: {n_rules} rule(s), {n_results} result(s) — "
          "ready for GitHub code-scanning.")
    print("First SARIF result (abbreviated):")
    first = sarif["runs"][0]["results"][0]
    print("  " + json.dumps({"ruleId": first["ruleId"], "level": first["level"]}))


if __name__ == "__main__":
    main()

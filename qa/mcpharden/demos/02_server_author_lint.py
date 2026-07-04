"""Scenario 2 - MCP server authors.

You wrote an MCP server. Before you publish it, lint your own manifest the way a
careful client will, fix what it flags, and confirm the rewrite scores 100. This
demo audits a deliberately over-broad first draft, walks the findings with their
remediations, then audits the hardened rewrite and shows the score climb to a
clean pass.
"""
from _common import fixture, rule, sev

from mcpharden import audit_path


def main() -> None:
    rule("SERVER AUTHOR LINT  -  fix your manifest before you publish it")

    draft = audit_path(fixture("public-rce-server.json"))
    print(f"\nFirst draft: '{draft.server_name}'  ->  score {draft.score}/100  "
          f"({'FAIL' if draft.failed else 'PASS'})\n")
    print("Each finding tells you what to change:\n")
    for f in draft.findings:
        print(f"  [{sev(f.severity)}] {f.rule}")
        print(f"        problem: {f.message}")
        print(f"        fix    : {f.remediation}")
        print()

    counts = draft.counts
    print(f"Summary: critical={counts['critical']} high={counts['high']} "
          f"medium={counts['medium']} low={counts['low']}")

    print("\nNow audit the hardened rewrite (localhost + TLS + OAuth/PKCE,")
    print("strict inputSchemas, no shell tool, secrets out of the manifest):\n")
    fixed = audit_path(fixture("hardened-server.json"))
    print(f"  '{fixed.server_name}'  ->  score {fixed.score}/100  "
          f"({'FAIL' if fixed.failed else 'PASS'})")
    if not fixed.findings:
        print("  (no findings — ship it)")

    print(f"\nScore moved {draft.score} -> {fixed.score}. The linter is the checklist.")


if __name__ == "__main__":
    main()

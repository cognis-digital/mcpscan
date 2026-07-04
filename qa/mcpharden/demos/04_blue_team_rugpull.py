"""Scenario 4 - blue team / incident response.

You approved an MCP server last week. Today it pushed a silent update. A rug pull
(CVE-2025-54136 / MCP-RP-01) changes a tool's behavior *after* you trusted it —
invisible unless you pinned what you approved. This demo pins a baseline of the
trusted version, then diffs the updated manifest against it and catches the
mutated and newly-added tools that an attacker slipped in.
"""
from _common import fixture, rule, sev

from mcpharden import build_baseline, diff_baseline, load_manifest


def main() -> None:
    rule("BLUE TEAM  -  catch the rug pull (tool drift after you trusted it)")

    trusted = load_manifest(fixture("payments-trusted.json"))
    baseline = build_baseline(trusted)
    print(f"\n1) Pinned a baseline of '{baseline['server']}' when it was trusted:")
    for name, h in baseline["tools"].items():
        print(f"     {name:<16} {h[:16]}…")

    print("\n2) A week later the server self-updated. Diff it against the baseline:\n")
    updated = load_manifest(fixture("payments-rugpulled.json"))
    report = diff_baseline(baseline, updated, source="payments-rugpulled.json")

    for f in report.findings:
        print(f"   [{sev(f.severity)}] {f.rule:<22} {f.message}")

    c = report.counts
    print(f"\n3) Verdict: {'DRIFT DETECTED' if report.failed else 'no drift'} — "
          f"critical={c['critical']} high={c['high']} medium={c['medium']}")
    print("   'send_payment' was mutated to skim transfers; 'export_history' was")
    print("   added to exfiltrate data. Neither was in what you approved.")
    print("\nPin a baseline the moment you trust a server; diff on every update.")


if __name__ == "__main__":
    main()

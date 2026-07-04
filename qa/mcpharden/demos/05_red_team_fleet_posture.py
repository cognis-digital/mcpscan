"""Scenario 5 - red team / attack-surface review.

An agent host rarely connects to one MCP server — it connects to a *fleet* that
shares one model context and one trust boundary. The interesting risks live
*between* servers and are invisible to a per-server audit: a shared credential, a
tool-name collision (the precondition for cross-server shadowing), and an
RCE-prone server sitting next to an exposed network peer (a lateral-movement
pivot). This demo correlates the whole fleet the way an attacker would map it,
then rolls it up to one hardening grade and the single highest-leverage fix.
"""
from _common import fixture, rule, sev

from mcpharden import posture


def main() -> None:
    rule("RED TEAM  -  cross-server risks a per-server audit can't see")

    pr = posture.assess(fixture("fleet"))

    print(f"\nFleet of {pr.server_count} server(s), {pr.network_count} network-reachable.")
    print(f"Per-server scores (worst first):\n")
    for s in pr.servers:
        reach = "net  " if s.network else "local"
        print(f"   [{'FAIL' if s.failed else 'PASS'}] {s.score:>3}/100  {reach}  "
              f"{s.transport_type:<8} {s.name}")

    print(f"\nCROSS-SERVER CORRELATIONS ({len(pr.findings)}) — none visible in a single manifest:\n")
    for f in pr.findings:
        print(f"   [{sev(f.severity)}] {f.rule}")
        print(f"        {f.message}")
        print()

    print("-" * 70)
    print(f"Fleet hardening grade: {pr.grade}  ({pr.fleet_score}/100)")
    print(f"TOP PRIORITY: {pr.top_remediation}")
    print("\nThe attacker pivots through the weakest reachable peer. So does the fix.")


if __name__ == "__main__":
    main()

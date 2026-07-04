"""Scenario 1 - AI platform / security engineers.

An AI platform team is about to let agents connect to a new third-party MCP
server. Before it joins the trust boundary, gate it: audit the manifest, read
the hardening score, and fail closed on any critical/high finding. This demo
plays the gate against three real manifests — a hardened server that passes and
two that must be blocked — exactly as a CI admission check would.
"""
from _common import fixture, rule, print_findings

from mcpharden import audit_path


CANDIDATES = [
    ("hardened-server.json", "a well-built docs server"),
    ("poisoned-server.json", "a notes server with a poisoned tool description"),
    ("public-rce-server.json", "an ops server exposed to the world"),
]


def main() -> None:
    rule("AI PLATFORM REVIEW  -  gate every server before it joins the fleet")
    print("\nAdmission policy: a server may join only if it has no critical/high finding.\n")

    admitted, blocked = [], []
    for filename, blurb in CANDIDATES:
        report = audit_path(fixture(filename))
        verdict = "BLOCK " if report.failed else "ADMIT "
        print(f"[{verdict}] {report.server_name:<14} score {report.score:>3}/100  ({blurb})")
        print_findings(report.findings)
        print()
        (blocked if report.failed else admitted).append(report.server_name)

    print("-" * 70)
    print(f"Admitted to the agent trust boundary : {', '.join(admitted) or 'none'}")
    print(f"Blocked at the gate                  : {', '.join(blocked) or 'none'}")
    print("\nThe gate is the score + the fail-closed rule. Wire `mcpharden scan")
    print("--fail-on high` into CI and no over-broad server reaches your agents.")


if __name__ == "__main__":
    main()

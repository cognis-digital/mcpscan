"""Shared helpers for the mcpharden demo scenarios.

Every scenario runs offline against the bundled sample manifests in
``demos/fixtures/`` and uses the real mcpharden API — no network, no fabricated
output. Run a single scenario with ``python demos/NN_name.py`` or all of them
with ``python demos/run_all.py``.
"""
from __future__ import annotations

import os
import sys

# allow `python demos/NN_name.py` from anywhere
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def fixture(*parts: str) -> str:
    """Absolute path to a bundled sample manifest under demos/fixtures/."""
    return os.path.join(FIXTURES, *parts)


def rule(title: str) -> None:
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


_SEV_LABEL = {
    "critical": "CRIT", "high": "HIGH", "medium": "MED ",
    "low": "LOW ", "info": "INFO",
}


def sev(severity: str) -> str:
    """Fixed-width severity label for aligned, narrated output."""
    return _SEV_LABEL.get(severity, severity.upper())


def print_findings(findings, indent: str = "     ") -> None:
    """Pretty-print a list of core.Finding objects."""
    if not findings:
        print(f"{indent}(no findings — passes hardening checks)")
        return
    for f in findings:
        print(f"{indent}[{sev(f.severity)}] {f.rule:<32} {f.message}")

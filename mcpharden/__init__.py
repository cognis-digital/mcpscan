"""mcpharden — MCP server hardening linter. Part of the Cognis Neural Suite."""

from mcpharden.core import (
    TOOL_NAME,
    TOOL_VERSION,
    Finding,
    Report,
    ManifestError,
    SEVERITY_ORDER,
    audit_manifest,
    audit_path,
    load_manifest,
    scan,
    scan_to_dict,
    to_sarif,
    to_html,
)
from mcpharden import vulndb
from mcpharden.vulndb import VulnClass, CATALOG, BY_ID, BY_RULE, by_cve, all_cves
from mcpharden import configaudit, baseline
from mcpharden.configaudit import audit_config, audit_config_path, default_config_paths
from mcpharden.baseline import build_baseline, diff_baseline
from mcpharden import posture
from mcpharden.posture import (
    PostureReport,
    ServerSummary,
    assess,
    analyze,
    summarize,
)

__version__ = TOOL_VERSION

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "__version__",
    "Finding",
    "Report",
    "ManifestError",
    "SEVERITY_ORDER",
    "audit_manifest",
    "audit_path",
    "load_manifest",
    "scan",
    "scan_to_dict",
    "to_sarif",
    "to_html",
    "vulndb",
    "VulnClass",
    "CATALOG",
    "BY_ID",
    "BY_RULE",
    "by_cve",
    "all_cves",
    "configaudit",
    "baseline",
    "audit_config",
    "audit_config_path",
    "default_config_paths",
    "build_baseline",
    "diff_baseline",
    "posture",
    "PostureReport",
    "ServerSummary",
    "assess",
    "analyze",
    "summarize",
]

"""mcpscan — part of the Cognis Neural Suite."""
try:  # re-export the tool's public API + identity from core
    from mcpscan.core import *  # noqa: F401,F403
except Exception:  # pragma: no cover
    pass
try:
    from mcpscan.core import TOOL_NAME, TOOL_VERSION
except Exception:  # pragma: no cover
    TOOL_NAME = "mcpscan"
    TOOL_VERSION = "0.4.0"
__version__ = TOOL_VERSION

try:  # OWASP Top 10 for Agentic Applications (2026) taxonomy + mapping
    from mcpscan import agentic  # noqa: F401
    from mcpscan.agentic import CATALOG as ASI_CATALOG, asi_for, asi_label  # noqa: F401
except Exception:  # pragma: no cover
    pass

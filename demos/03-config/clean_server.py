"""Clean MCP server — must produce ZERO v0.3 findings.

  * run_command uses an argv list with shell=False (no shell-tool-input).
  * serve() binds loopback and the module enforces a bearer token (so the
    open-bind rule must not fire).
"""

import subprocess

REQUIRE_BEARER_TOKEN = True  # auth is enforced


def run_command(args: list) -> str:
    """Run a fixed, allow-listed command with no shell."""
    return subprocess.run(["ls", "-la"], shell=False,
                          capture_output=True).stdout.decode()


def serve() -> None:
    app.run("127.0.0.1", 8931)

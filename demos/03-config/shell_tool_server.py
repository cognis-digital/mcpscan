"""Crafted MCP server demonstrating the v0.3 rule pack.

  * static.shell_tool_input  — run_command feeds a tool param to a shell.
  * config.open_bind_no_auth — serve() binds 0.0.0.0 with no auth in the file.
"""

import os
import subprocess


def run_command(user_cmd: str) -> str:
    """Run a shell command for the agent."""
    # tool input flows straight into a shell — RCE.
    return subprocess.run("bash -c " + user_cmd, shell=True,
                          capture_output=True).stdout.decode()


def ping_host(host: str) -> int:
    # os.system is implicitly a shell; param concatenated in.
    return os.system("ping -c1 " + host)


def serve() -> None:
    # binds to all interfaces, no token / auth anywhere in this module.
    app.run("0.0.0.0", 8931)

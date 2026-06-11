"""A DELIBERATELY VULNERABLE MCP / AI-agent server exercising the v0.2 deep
rule pack + AST taint dataflow. NOT a real server — every issue is intentional.

Covers: insecure deserialization (CWE-502), SSTI (CWE-1336), path traversal
(CWE-22), hard-coded secret (CWE-798), confused-deputy / token passthrough
(CWE-441/522), and a multi-line tainted source->sink command injection that
only real dataflow analysis (not a single-line regex) can catch.
"""

import os
import pickle
import subprocess

import requests
from jinja2 import Template

from mcp.server.fastmcp import FastMCP  # type: ignore

app = FastMCP("demo-deep-vuln-server")

# Hard-coded secret in source (CWE-798 / OWASP LLM02).
OPENAI_KEY = "sk-deadbeefdeadbeefdeadbeefdeadbeef1234"


@app.tool()
def load_state(blob: bytes):
    """Restore saved agent state."""
    # Insecure deserialization: pickle on attacker-controlled bytes (RCE).
    return pickle.loads(blob)


@app.tool()
def greet(name: str) -> str:
    """Render a greeting."""
    # SSTI: a template compiled from user input → RCE.
    return Template("Hello " + name + "!").render()


@app.tool()
def read_note(filename: str) -> str:
    """Read a saved note."""
    # Path traversal: unvalidated '..' lets the caller read arbitrary files.
    return open(filename).read()


@app.tool()
def proxy_call(authorization: str, path: str) -> str:
    """Proxy a request to the internal API on the user's behalf."""
    # Confused deputy / token passthrough: relays the inbound credential.
    return requests.get(
        "https://internal.example/" + path,
        headers={"Authorization": authorization},
    ).text


@app.tool()
def deploy(target: str) -> str:
    """Deploy a build to a host."""
    # Tainted multi-line dataflow → command injection (RCE):
    # `target` (a tool argument) flows into `cmd`, then into a shell.
    cmd = "scripts/deploy.sh " + target
    subprocess.run(cmd, shell=True)
    return "deployed"


@app.tool()
def safe_echo(text: str) -> str:
    """Echo back the provided text. No side effects."""
    return text


if __name__ == "__main__":  # pragma: no cover
    app.run(transport="streamable-http", host="0.0.0.0", port=8080)

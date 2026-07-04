"""mcpscan — the MCP-server security suite. One command, seven modules.

Usage:
    mcpscan <module> [args...]

Modules:
    scan     scan for RCE/SSRF/no-auth/tool-poisoning vulnerabilities\n    harden   lint hardening: capability declarations, transport, tool safety\n    auth     drop-in token-auth gateway for unauthenticated MCP servers\n    pin      TOFU pinning & drift detection for MCP tool definitions\n    ssrf     consent-based SSRF probe for servers that fetch URLs\n    prompt   prompt-injection & indirect-injection scanner\n    trust    detect symlink-hijack / one-click-RCE / unsafe-trust settings\n
With no module (back-compat), runs `scan`.
"""
from __future__ import annotations
import sys, importlib

SUBS = {'scan': 'mcpscan.cli', 'harden': 'mcpharden.cli', 'auth': 'mcpauth.cli', 'pin': 'mcppin.cli', 'ssrf': 'ssrfmcp.cli', 'prompt': 'promptmirror.cli', 'trust': 'trustgate.cli'}
DESC = {'scan': 'scan for RCE/SSRF/no-auth/tool-poisoning vulnerabilities', 'harden': 'lint hardening: capability declarations, transport, tool safety', 'auth': 'drop-in token-auth gateway for unauthenticated MCP servers', 'pin': 'TOFU pinning & drift detection for MCP tool definitions', 'ssrf': 'consent-based SSRF probe for servers that fetch URLs', 'prompt': 'prompt-injection & indirect-injection scanner', 'trust': 'detect symlink-hijack / one-click-RCE / unsafe-trust settings'}


def _run(modpath, args):
    mod = importlib.import_module(modpath)
    try:
        return mod.main(list(args))
    except TypeError:
        old = sys.argv[:]
        sys.argv = [modpath] + list(args)
        try:
            return mod.main()
        finally:
            sys.argv = old


def _usage():
    print("mcpscan — the MCP-server security suite\n")
    print("usage: mcpscan <module> [args...]\n\nmodules:")
    for k in SUBS:
        print(f"  {k:<8} {DESC[k]}")
    print("\nrun `mcpscan <module> --help` for a module's options.")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv and argv[0] in SUBS:
        return _run(SUBS[argv[0]], argv[1:])
    if argv and argv[0] in ("-h", "--help", "help"):
        _usage(); return 0
    # back-compat: no known module -> the original scanner
    return _run("mcpscan.cli", argv)


if __name__ == "__main__":
    raise SystemExit(main())

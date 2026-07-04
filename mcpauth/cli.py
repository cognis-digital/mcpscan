"""Command-line interface for mcpauth.

Subcommands:
  gen-token   generate + store a hashed API token (prints plaintext once)
  wrap        run the authenticating reverse proxy in front of an upstream
  list        list stored token records (never reveals plaintext)
  demo        run the self-contained no-token-401 / token-200 demonstration
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    ProxyConfig,
    TokenStore,
    TokenStoreError,
    gen_token,
    run_demo,
    run_proxy,
)


# --------------------------------------------------------------------------
# Renderers
# --------------------------------------------------------------------------

def _render_gen_table(token: str, record) -> str:
    lines: List[str] = []
    lines.append(f"{TOOL_NAME}: generated API token")
    lines.append("=" * 60)
    lines.append("Store the token now — it is shown ONCE and only its hash is")
    lines.append("persisted. You cannot recover it later.")
    lines.append("-" * 60)
    lines.append(f"  token   : {token}")
    lines.append(f"  id      : {record.id}")
    lines.append(f"  label   : {record.label}")
    lines.append(f"  algo    : {record.algorithm} (rounds={record.rounds})")
    lines.append(f"  created : {record.created_at}")
    lines.append("-" * 60)
    lines.append("Use it as:  Authorization: Bearer <token>")
    return "\n".join(lines)


def _render_list_table(store: TokenStore) -> str:
    lines: List[str] = []
    lines.append(f"{TOOL_NAME}: stored tokens ({len(store.records)})")
    lines.append("=" * 60)
    if not store.records:
        lines.append("No tokens stored. Run `mcpauth gen-token` to create one.")
        return "\n".join(lines)
    for r in store.records:
        lines.append(f"[{r.id}] {r.label}")
        lines.append(f"        algo={r.algorithm} rounds={r.rounds}")
        lines.append(f"        created={r.created_at or '?'}"
                     + (f"  last_used={r.last_used_at}" if r.last_used_at else ""))
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Drop-in token-auth gateway in front of unauthenticated "
                    "MCP servers - a reverse proxy that requires a valid "
                    "Bearer token before forwarding to the upstream.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    gt = sub.add_parser("gen-token",
                        help="Generate + store a hashed API token.")
    gt.add_argument("--tokens", default="tokens.json",
                    help="Path to the token store JSON (default: tokens.json).")
    gt.add_argument("--label", default="",
                    help="Human label for the token (e.g. 'ci-runner').")
    gt.add_argument("--format", choices=("table", "json"), default="table",
                    help="Output format (default: table).")

    wr = sub.add_parser("wrap",
                        help="Run the authenticating reverse proxy.")
    wr.add_argument("--upstream", required=True,
                    help="Upstream MCP server URL, e.g. http://127.0.0.1:8000")
    wr.add_argument("--tokens", default="tokens.json",
                    help="Path to the token store JSON (default: tokens.json).")
    wr.add_argument("--host", default="127.0.0.1",
                    help="Bind address for the proxy (default: 127.0.0.1).")
    wr.add_argument("--port", type=int, default=9000,
                    help="Listen port for the proxy (default: 9000).")
    wr.add_argument("--timeout", type=float, default=30.0,
                    help="Upstream request timeout seconds (default: 30).")
    wr.add_argument("--realm", default="mcpauth",
                    help="WWW-Authenticate realm (default: mcpauth).")

    ls = sub.add_parser("list", help="List stored token records.")
    ls.add_argument("--tokens", default="tokens.json",
                    help="Path to the token store JSON (default: tokens.json).")
    ls.add_argument("--format", choices=("table", "json"), default="table",
                    help="Output format (default: table).")

    dm = sub.add_parser("demo",
                        help="Run the built-in 401-without / 200-with token demo.")
    dm.add_argument("--format", choices=("table", "json"), default="table",
                    help="Output format (default: table).")
    return p


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def _cmd_gen_token(args: argparse.Namespace) -> int:
    try:
        token, record = gen_token(args.tokens, label=args.label)
    except (OSError, TokenStoreError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        out = record.to_dict()
        out["token"] = token  # printed once; never persisted
        print(json.dumps(out, indent=2))
    else:
        print(_render_gen_table(token, record))
    return 0


def _cmd_wrap(args: argparse.Namespace) -> int:
    try:
        store = TokenStore.load(args.tokens)
    except (OSError, TokenStoreError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not store.records:
        print(f"error: no tokens in {args.tokens}; run `mcpauth gen-token` first.",
              file=sys.stderr)
        return 2
    cfg = ProxyConfig(
        upstream=args.upstream,
        store_path=args.tokens,
        host=args.host,
        port=args.port,
        timeout=args.timeout,
        realm=args.realm,
    )
    print(f"{TOOL_NAME}: proxy on http://{cfg.host}:{cfg.port} -> {cfg.upstream}  "
          f"({len(store.records)} token(s) loaded)", file=sys.stderr, flush=True)
    print(f"{TOOL_NAME}: every request requires 'Authorization: Bearer <token>'; "
          "auth decisions are logged to stdout.", file=sys.stderr, flush=True)
    try:
        run_proxy(cfg, store)
    except KeyboardInterrupt:
        print(f"\n{TOOL_NAME}: shutting down.", file=sys.stderr)
        return 0
    except OSError as exc:
        print(f"error: cannot bind {cfg.host}:{cfg.port}: {exc}", file=sys.stderr)
        return 2
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    try:
        store = TokenStore.load(args.tokens)
    except (OSError, TokenStoreError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps({"tokens": [r.to_dict() for r in store.records]}, indent=2))
    else:
        print(_render_list_table(store))
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    result = run_demo()
    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"{TOOL_NAME}: demo - auth gateway in front of a fake MCP upstream")
        print("=" * 60)
        print(f"  upstream         : {result['upstream']}")
        print(f"  proxy            : {result['proxy']}")
        print(f"  no token   -> {result['no_token_status']}  "
              f"(expected 401)")
        print(f"  valid token-> {result['with_token_status']}  "
              f"(expected 200)")
        print("-" * 60)
        print("  audit log:")
        for e in result["events"]:
            print(f"    {json.dumps(e, separators=(',', ':'))}")
        print("-" * 60)
        print("RESULT: " + ("PASS" if result["ok"] else "FAIL"))
    return 0 if result["ok"] else 1


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "gen-token":
        return _cmd_gen_token(args)
    if args.command == "wrap":
        return _cmd_wrap(args)
    if args.command == "list":
        return _cmd_list(args)
    if args.command == "demo":
        return _cmd_demo(args)
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

"""Command-line interface for mcppin.

    mcppin pin    <server_id> <tools.json>   record the trusted manifest
    mcppin verify <server_id> <tools.json>   check a live manifest (exit 1 on drift)
    mcppin list                              list pinned servers
    mcppin show   <server_id>                show a server's pinned tools

``tools.json`` may be either a bare JSON array of tool objects or the raw
``tools/list`` result object ``{"tools": [...]}``. The pin store defaults to
``~/.mcppin/pins.json`` (override with --store); the path is resolved from the
user's home directory, so the CLI works from any working directory.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from mcppin.core import DriftReport, PinStore

DEFAULT_STORE = str(Path.home() / ".mcppin" / "pins.json")


def _load_tools(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, dict) and "tools" in data:
        data = data["tools"]
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a JSON array of tools or an object with a 'tools' array")
    return data


def _format_drift(report: DriftReport) -> str:
    lines: list[str] = []
    for name in report.added:
        lines.append(f"  + added:   {name}")
    for name in report.removed:
        lines.append(f"  - removed: {name}")
    for change in report.changed:
        lines.append(f"  ~ changed: {change['name']} ({', '.join(change['fields'])})")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcppin", description=__doc__.splitlines()[0])
    parser.add_argument("--store", default=DEFAULT_STORE, help=f"pin store path (default: {DEFAULT_STORE})")
    sub = parser.add_subparsers(dest="command", required=True)

    p_pin = sub.add_parser("pin", help="record the trusted tool manifest for a server")
    p_pin.add_argument("server_id")
    p_pin.add_argument("tools", help="path to tools JSON")

    p_verify = sub.add_parser("verify", help="verify a live manifest against the pin")
    p_verify.add_argument("server_id")
    p_verify.add_argument("tools", help="path to tools JSON")
    p_verify.add_argument(
        "--tofu",
        action="store_true",
        help="trust-on-first-use: pin automatically if the server is not yet pinned",
    )

    sub.add_parser("list", help="list pinned servers")

    p_show = sub.add_parser("show", help="show a server's pinned tools")
    p_show.add_argument("server_id")

    args = parser.parse_args(argv)
    store = PinStore(args.store)

    if args.command == "pin":
        tools = _load_tools(args.tools)
        record = store.pin(args.server_id, tools)
        print(f"pinned {args.server_id}: {len(record['tools'])} tool(s), manifest {record['manifest'][:12]}")
        return 0

    if args.command == "verify":
        tools = _load_tools(args.tools)
        if not store.is_pinned(args.server_id):
            if args.tofu:
                record = store.pin(args.server_id, tools)
                print(f"TOFU: pinned {args.server_id} ({len(record['tools'])} tool(s)) on first use")
                return 0
            print(f"{args.server_id} is not pinned (run 'mcppin pin' or pass --tofu)", file=sys.stderr)
            return 2
        report = store.verify(args.server_id, tools)
        if not report.is_drift:
            print(f"OK: {args.server_id} matches its pin")
            return 0
        print(f"DRIFT detected for {args.server_id}:", file=sys.stderr)
        print(_format_drift(report), file=sys.stderr)
        return 1

    if args.command == "list":
        servers = store.servers()
        if not servers:
            print("(no servers pinned)")
        for server_id in servers:
            count = len(store.get(server_id)["tools"])
            print(f"{server_id}\t{count} tool(s)")
        return 0

    if args.command == "show":  # pragma: no branch
        if not store.is_pinned(args.server_id):
            print(f"{args.server_id} is not pinned", file=sys.stderr)
            return 2
        record = store.get(args.server_id)
        print(f"{args.server_id}  (manifest {record['manifest'][:12]})")
        for name in sorted(record["tools"]):
            print(f"  {name}\t{record['tools'][name]['fingerprint'][:12]}")
        return 0

    return 0  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

"""Core auth + reverse-proxy engine for mcpauth.

mcpauth puts a token-authenticating reverse proxy in front of an existing,
*unauthenticated* MCP HTTP server. Two concerns live here:

  * Token store  — generate cryptographically strong API tokens, persist only
    a salted hash (never the plaintext), and verify a presented token in
    constant time against the stored hashes.
  * Proxy        — a stdlib ``http.server`` based gateway that requires a
    valid ``Authorization: Bearer <token>`` header, forwards authorized
    requests to the upstream MCP server, streams the response back, and emits
    a structured audit record for every auth decision.

No third-party dependencies; standard library only. No outbound network calls
are made except the proxy forward to the configured upstream.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import socket
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

TOOL_NAME = "mcpauth"
TOOL_VERSION = "0.1.0"

# PBKDF2-HMAC-SHA256 work factor. Tokens are 256-bit random so a modest
# iteration count is plenty; the hash exists to avoid storing plaintext.
_PBKDF2_ROUNDS = 200_000
_TOKEN_BYTES = 32  # 256-bit token entropy
_PREFIX = "mcpauth_"  # human-recognizable token prefix

# Hop-by-hop headers that must not be forwarded (RFC 7230 §6.1).
_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
})


class TokenStoreError(ValueError):
    """Raised when a token store file is malformed or cannot be used."""


# --------------------------------------------------------------------------
# Token records + hashing
# --------------------------------------------------------------------------

@dataclass
class TokenRecord:
    """A single stored credential. The plaintext token is NEVER stored."""
    id: str
    label: str
    algorithm: str           # e.g. "pbkdf2_sha256"
    rounds: int
    salt: str                # hex
    hash: str                # hex
    created_at: str
    last_used_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _hash_token(token: str, salt_bytes: bytes, rounds: int = _PBKDF2_ROUNDS) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", token.encode("utf-8"), salt_bytes, rounds)
    return dk.hex()


def generate_token() -> str:
    """Return a fresh, URL-safe, 256-bit API token with a recognizable prefix."""
    return _PREFIX + secrets.token_urlsafe(_TOKEN_BYTES)


def make_record(token: str, label: str = "") -> TokenRecord:
    """Build a :class:`TokenRecord` (hash + salt) for a plaintext ``token``."""
    salt_bytes = secrets.token_bytes(16)
    return TokenRecord(
        id=secrets.token_hex(8),
        label=label or "unnamed",
        algorithm="pbkdf2_sha256",
        rounds=_PBKDF2_ROUNDS,
        salt=salt_bytes.hex(),
        hash=_hash_token(token, salt_bytes, _PBKDF2_ROUNDS),
        created_at=datetime.now(timezone.utc).isoformat(),
    )


def verify_token(token: str, records: List[TokenRecord]) -> Optional[TokenRecord]:
    """Constant-time verification of ``token`` against every stored record.

    Every record is checked (no early return on first mismatch) so that the
    work performed does not leak which/whether a token matched via timing.
    Returns the matching :class:`TokenRecord`, or ``None``.
    """
    if not token:
        return None
    matched: Optional[TokenRecord] = None
    for rec in records:
        try:
            salt_bytes = bytes.fromhex(rec.salt)
        except ValueError:
            continue
        candidate = _hash_token(token, salt_bytes, rec.rounds)
        # hmac.compare_digest is constant-time for equal-length inputs.
        if hmac.compare_digest(candidate, rec.hash):
            matched = rec
    return matched


# --------------------------------------------------------------------------
# Token store persistence
# --------------------------------------------------------------------------

class TokenStore:
    """A JSON-backed collection of :class:`TokenRecord` objects."""

    def __init__(self, path: str, records: Optional[List[TokenRecord]] = None):
        self.path = path
        self.records: List[TokenRecord] = records or []

    # -- IO --------------------------------------------------------------
    @classmethod
    def load(cls, path: str) -> "TokenStore":
        p = Path(path)
        if not p.exists():
            return cls(path, [])
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise TokenStoreError(f"invalid JSON in token store {path}: {exc}") from exc
        raw = data.get("tokens", data) if isinstance(data, dict) else data
        if not isinstance(raw, list):
            raise TokenStoreError("token store must contain a list of token records")
        records: List[TokenRecord] = []
        for item in raw:
            if not isinstance(item, dict):
                raise TokenStoreError("each token record must be an object")
            try:
                records.append(TokenRecord(
                    id=str(item["id"]),
                    label=str(item.get("label", "unnamed")),
                    algorithm=str(item.get("algorithm", "pbkdf2_sha256")),
                    rounds=int(item.get("rounds", _PBKDF2_ROUNDS)),
                    salt=str(item["salt"]),
                    hash=str(item["hash"]),
                    created_at=str(item.get("created_at", "")),
                    last_used_at=str(item.get("last_used_at", "")),
                ))
            except KeyError as exc:
                raise TokenStoreError(f"token record missing field {exc}") from exc
        return cls(path, records)

    def save(self) -> None:
        p = Path(self.path)
        if p.parent and not p.parent.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
        payload = {"tokens": [r.to_dict() for r in self.records]}
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.replace(tmp, p)
        # Best-effort: tighten perms on POSIX. No-op / harmless on Windows.
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass

    # -- mutation --------------------------------------------------------
    def add(self, record: TokenRecord) -> None:
        self.records.append(record)

    def verify(self, token: str) -> Optional[TokenRecord]:
        return verify_token(token, self.records)


def gen_token(store_path: str, label: str = "") -> Tuple[str, TokenRecord]:
    """Generate a token, append its hashed record to ``store_path``, save.

    Returns ``(plaintext_token, record)``. The plaintext is returned exactly
    once here and never persisted — the caller must surface it to the user.
    """
    store = TokenStore.load(store_path)
    token = generate_token()
    record = make_record(token, label=label)
    store.add(record)
    store.save()
    return token, record


# --------------------------------------------------------------------------
# Auth decision (header parsing) — pure + unit-testable
# --------------------------------------------------------------------------

@dataclass
class AuthDecision:
    allowed: bool
    reason: str                  # machine code, e.g. "ok" / "missing_header"
    token_id: str = ""
    label: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def parse_bearer(authorization_header: Optional[str]) -> Optional[str]:
    """Extract the token from an ``Authorization: Bearer <token>`` header."""
    if not authorization_header:
        return None
    parts = authorization_header.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1].strip()
    return token or None


def decide(authorization_header: Optional[str], store: TokenStore) -> AuthDecision:
    """Compute the auth decision for a presented Authorization header."""
    token = parse_bearer(authorization_header)
    if token is None:
        if authorization_header:
            return AuthDecision(False, "malformed_header")
        return AuthDecision(False, "missing_header")
    rec = store.verify(token)
    if rec is None:
        return AuthDecision(False, "invalid_token")
    return AuthDecision(True, "ok", token_id=rec.id, label=rec.label)


# --------------------------------------------------------------------------
# Audit logging
# --------------------------------------------------------------------------

@dataclass
class AuditEvent:
    ts: str
    client: str
    method: str
    path: str
    allowed: bool
    reason: str
    status: int
    token_id: str = ""
    label: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def format_audit(event: AuditEvent) -> str:
    """Render an audit event as a single-line JSON record."""
    return json.dumps(event.to_dict(), separators=(",", ":"))


# --------------------------------------------------------------------------
# Reverse proxy
# --------------------------------------------------------------------------

@dataclass
class ProxyConfig:
    upstream: str                 # e.g. "http://127.0.0.1:8000"
    store_path: str
    host: str = "127.0.0.1"
    port: int = 9000
    timeout: float = 30.0
    realm: str = "mcpauth"
    audit_sink: Optional[Callable[[AuditEvent], None]] = field(default=None)


def _normalize_upstream(upstream: str) -> str:
    u = upstream.strip()
    if not u.startswith(("http://", "https://")):
        u = "http://" + u
    return u.rstrip("/")


def _make_handler(config: ProxyConfig, store: TokenStore):
    upstream_base = _normalize_upstream(config.upstream)

    def _emit(event: AuditEvent) -> None:
        if config.audit_sink is not None:
            config.audit_sink(event)
        else:
            print(format_audit(event), flush=True)

    class _Handler(BaseHTTPRequestHandler):
        server_version = f"mcpauth/{TOOL_VERSION}"
        protocol_version = "HTTP/1.1"

        # Silence the default noisy stderr access log; we emit our own audit.
        def log_message(self, fmt: str, *args: Any) -> None:  # noqa: N802
            return

        # -- helpers ----------------------------------------------------
        def _client(self) -> str:
            try:
                return self.client_address[0]
            except Exception:
                return "?"

        def _audit(self, decision: AuthDecision, status: int) -> None:
            _emit(AuditEvent(
                ts=datetime.now(timezone.utc).isoformat(),
                client=self._client(),
                method=self.command,
                path=self.path,
                allowed=decision.allowed,
                reason=decision.reason,
                status=status,
                token_id=decision.token_id,
                label=decision.label,
            ))

        def _send_json(self, status: int, body: Dict[str, Any],
                       extra_headers: Optional[Dict[str, str]] = None) -> None:
            payload = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            for k, v in (extra_headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(payload)

        def _reject(self, decision: AuthDecision) -> None:
            status = 401
            self._send_json(
                status,
                {"error": "unauthorized", "reason": decision.reason},
                {"WWW-Authenticate": f'Bearer realm="{config.realm}"'},
            )
            self._audit(decision, status)

        def _read_body(self) -> bytes:
            length = self.headers.get("Content-Length")
            if length is not None:
                try:
                    n = int(length)
                except ValueError:
                    return b""
                return self.rfile.read(n) if n > 0 else b""
            return b""

        # -- forwarding -------------------------------------------------
        def _forward(self, decision: AuthDecision) -> None:
            body = self._read_body()
            target = upstream_base + self.path
            fwd_headers: Dict[str, str] = {}
            for key in self.headers.keys():
                lk = key.lower()
                if lk in _HOP_BY_HOP or lk == "authorization" or lk == "host":
                    continue
                fwd_headers[key] = self.headers[key]
            fwd_headers["X-Forwarded-For"] = self._client()
            fwd_headers["X-Forwarded-Host"] = self.headers.get("Host", "")
            fwd_headers["X-Mcpauth-Token-Id"] = decision.token_id

            req = urllib.request.Request(
                target, data=body if body else None,
                method=self.command, headers=fwd_headers,
            )
            try:
                with urllib.request.urlopen(req, timeout=config.timeout) as resp:
                    self._relay_response(resp.status, resp.headers, resp)
                    status = resp.status
            except urllib.error.HTTPError as exc:
                # Upstream returned a non-2xx; relay it faithfully.
                self._relay_response(exc.code, exc.headers, exc)
                status = exc.code
            except (urllib.error.URLError, socket.timeout, ConnectionError) as exc:
                self._send_json(502, {"error": "bad_gateway",
                                      "detail": str(getattr(exc, "reason", exc))})
                status = 502
            self._audit(decision, status)

        def _relay_response(self, status: int, headers, body_stream) -> None:
            data = body_stream.read()
            self.send_response(status)
            sent_len = False
            for key in headers.keys():
                lk = key.lower()
                if lk in _HOP_BY_HOP or lk == "content-length":
                    continue
                self.send_header(key, headers[key])
            self.send_header("Content-Length", str(len(data)))
            sent_len = True
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)
            _ = sent_len

        # -- dispatch ---------------------------------------------------
        def _handle(self) -> None:
            decision = decide(self.headers.get("Authorization"), store)
            if not decision.allowed:
                self._reject(decision)
                return
            self._forward(decision)

        # Map every common method onto the same gated handler.
        def do_GET(self):     self._handle()   # noqa: E704,N802
        def do_POST(self):    self._handle()   # noqa: E704,N802
        def do_PUT(self):     self._handle()   # noqa: E704,N802
        def do_DELETE(self):  self._handle()   # noqa: E704,N802
        def do_PATCH(self):   self._handle()   # noqa: E704,N802
        def do_HEAD(self):    self._handle()   # noqa: E704,N802
        def do_OPTIONS(self): self._handle()   # noqa: E704,N802

    return _Handler


def build_server(config: ProxyConfig,
                 store: Optional[TokenStore] = None) -> ThreadingHTTPServer:
    """Construct (but do not start) the proxy :class:`ThreadingHTTPServer`."""
    store = store if store is not None else TokenStore.load(config.store_path)
    handler = _make_handler(config, store)
    httpd = ThreadingHTTPServer((config.host, config.port), handler)
    httpd.daemon_threads = True
    return httpd


def run_proxy(config: ProxyConfig,
              store: Optional[TokenStore] = None,
              ready: Optional[threading.Event] = None) -> None:
    """Start the proxy and serve forever (blocking)."""
    httpd = build_server(config, store)
    if ready is not None:
        ready.set()
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()


# --------------------------------------------------------------------------
# Tiny demo upstream — a stand-in unauthenticated MCP HTTP server
# --------------------------------------------------------------------------

def build_demo_upstream(host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    """A minimal unauthenticated 'MCP' HTTP server used by the demo + tests.

    Replies 200 with a JSON-RPC-ish body to any request, echoing the path.
    """
    class _Upstream(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):  # noqa: N802
            return

        def _reply(self):
            body = json.dumps({
                "jsonrpc": "2.0",
                "result": {"server": "demo-mcp", "path": self.path,
                           "method": self.command},
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_GET(self):  self._reply()   # noqa: E704,N802
        def do_POST(self): self._reply()   # noqa: E704,N802
        def do_HEAD(self): self._reply()   # noqa: E704,N802

    httpd = ThreadingHTTPServer((host, port), _Upstream)
    httpd.daemon_threads = True
    return httpd


def free_port() -> int:
    """Return an OS-assigned free TCP port (best effort)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def run_demo(timeout: float = 5.0) -> Dict[str, Any]:
    """Self-contained demo: spin up upstream + proxy, fire two requests.

    Returns a dict with the two HTTP statuses (no-token -> 401, token -> 200)
    plus the captured audit events, so the CLI/tests can assert on it.
    """
    events: List[AuditEvent] = []

    # 1. Demo upstream on a free port.
    up = build_demo_upstream()
    up_port = up.server_address[1]
    up_thread = threading.Thread(target=up.serve_forever, daemon=True)
    up_thread.start()

    # 2. In-memory token store with one valid token.
    token = generate_token()
    store = TokenStore("<demo>", [make_record(token, label="demo-key")])

    # 3. Proxy in front of the upstream.
    proxy_port = free_port()
    cfg = ProxyConfig(
        upstream=f"http://127.0.0.1:{up_port}",
        store_path="<demo>",
        host="127.0.0.1",
        port=proxy_port,
        timeout=timeout,
        audit_sink=events.append,
    )
    httpd = build_server(cfg, store)
    proxy_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    proxy_thread.start()

    base = f"http://127.0.0.1:{proxy_port}/mcp"
    deadline = time.time() + timeout

    def _request(headers: Dict[str, str]) -> int:
        last_exc: Optional[Exception] = None
        while time.time() < deadline:
            try:
                req = urllib.request.Request(base, headers=headers, method="GET")
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    return r.status
            except urllib.error.HTTPError as e:
                return e.code
            except (urllib.error.URLError, ConnectionError) as e:
                last_exc = e
                time.sleep(0.05)
        raise RuntimeError(f"demo request never connected: {last_exc}")

    try:
        status_no_token = _request({})
        status_with_token = _request({"Authorization": f"Bearer {token}"})
    finally:
        httpd.shutdown()
        httpd.server_close()
        up.shutdown()
        up.server_close()

    return {
        "upstream": cfg.upstream,
        "proxy": f"http://127.0.0.1:{proxy_port}",
        "no_token_status": status_no_token,
        "with_token_status": status_with_token,
        "events": [e.to_dict() for e in events],
        "ok": status_no_token == 401 and status_with_token == 200,
    }

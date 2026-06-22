"""Authorization gate for mcpscan's ACTIVE (network) scanning.

mcpscan is a DEFENSIVE, authorized-use-only security scanner. Its default
mode is PASSIVE: it analyses input you already hold (source files, configs,
SBOMs, captured ``tools/list`` JSON) entirely OFFLINE with no network traffic.

Any capability that touches the network to talk to a live target ("ACTIVE"
mode — the ``probe`` command) is GATED behind this module:

  * OFF BY DEFAULT — an active scan refuses to run unless the operator passes
    ``--authorized`` to acknowledge they have permission to test the target.
  * SCOPE-ENFORCED — the operator MUST supply a target allowlist (one or more
    host[:port] / CIDR entries, or a file of them). A target that is not in
    scope is refused, never probed.
  * RATE-LIMITED — outbound probes are throttled to a configurable
    requests-per-second so a scan cannot become a flood / DoS.
  * LOUD — a banner is emitted to stderr before any active traffic stating
    that the run is authorized-use-only and naming the scope.

None of this module makes network calls. It only decides whether a target is
allowed and paces the caller. The scope check is intentionally fail-closed:
if anything is ambiguous, the target is refused.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence, Tuple
from urllib.parse import urlsplit


class AuthorizationError(PermissionError):
    """Raised when an active scan is attempted without proper authorization
    or against a target that is not in the operator-declared scope."""


BANNER = (
    "=" * 70 + "\n"
    "  mcpscan ACTIVE SCAN  --  AUTHORIZED USE ONLY\n"
    "  You are sending live network traffic to a target. Only do this\n"
    "  against systems you own or are explicitly permitted to test.\n"
    "  Unauthorized scanning may be illegal. This tool is DEFENSIVE.\n"
    + "=" * 70
)


def emit_banner(scope: "Scope", *, stream=None) -> None:
    """Print the authorized-use banner + the active scope to stderr."""
    stream = stream if stream is not None else sys.stderr
    print(BANNER, file=stream)
    print(f"  scope ({len(scope.entries)} entr"
          f"{'y' if len(scope.entries) == 1 else 'ies'}): "
          f"{scope.describe()}", file=stream)
    print(f"  rate limit: {scope.rate_limit:g} req/s", file=stream)
    print("=" * 70, file=stream)


def _split_host_port(text: str) -> Tuple[str, Optional[int]]:
    """Split ``host`` / ``host:port`` (also tolerates a bare URL)."""
    text = text.strip()
    if "://" in text:
        parts = urlsplit(text)
        return (parts.hostname or "").lower(), parts.port
    # bracketed IPv6 [::1]:8080
    m = re.match(r"^\[([0-9A-Fa-f:]+)\](?::(\d+))?$", text)
    if m:
        return m.group(1).lower(), int(m.group(2)) if m.group(2) else None
    # plain IPv6 (no port) — colons but parses as an address
    try:
        ipaddress.ip_address(text)
        return text.lower(), None
    except ValueError:
        pass
    if ":" in text:
        host, _, port = text.rpartition(":")
        if port.isdigit():
            return host.lower(), int(port)
    return text.lower(), None


@dataclass
class _Entry:
    """A single scope rule: a host/IP/CIDR, with an optional port."""
    raw: str
    host: Optional[str] = None         # literal hostname (lowercased)
    network: Optional[object] = None   # ipaddress network for IP/CIDR rules
    port: Optional[int] = None         # required port, or None = any port

    def matches(self, host: str, port: Optional[int]) -> bool:
        if self.port is not None and port is not None and self.port != port:
            return False
        host = (host or "").lower()
        if self.network is not None:
            try:
                addr = ipaddress.ip_address(host)
            except ValueError:
                return False
            return addr in self.network
        return self.host == host


def _parse_entry(text: str) -> Optional[_Entry]:
    text = text.strip()
    if not text or text.startswith("#"):
        return None
    host, port = _split_host_port(text)
    if not host:
        return None
    # CIDR?
    if "/" in host:
        try:
            net = ipaddress.ip_network(host, strict=False)
            return _Entry(raw=text, network=net, port=port)
        except ValueError:
            return None
    # bare IP becomes a /32 or /128 network so IP comparison is exact
    try:
        addr = ipaddress.ip_address(host)
        net = ipaddress.ip_network(
            f"{addr}/{addr.max_prefixlen}", strict=False)
        return _Entry(raw=text, network=net, port=port)
    except ValueError:
        return _Entry(raw=text, host=host, port=port)


@dataclass
class Scope:
    """An operator-declared active-scan scope + rate limit.

    ``allowed`` is the parsed allowlist. ``authorized`` mirrors the
    ``--authorized`` acknowledgement. A scope with ``authorized=False`` or an
    empty allowlist will refuse every target.
    """
    entries: List[_Entry] = field(default_factory=list)
    authorized: bool = False
    rate_limit: float = 1.0  # requests per second; >0
    resolve: bool = False    # also check DNS-resolved IPs of a hostname target

    def describe(self) -> str:
        return ", ".join(e.raw for e in self.entries) or "<empty>"

    # -- construction -----------------------------------------------------
    @classmethod
    def from_spec(
        cls,
        allow: Optional[Sequence[str]] = None,
        allow_file: Optional[str] = None,
        *,
        authorized: bool = False,
        rate_limit: float = 1.0,
        resolve: bool = False,
    ) -> "Scope":
        raw: List[str] = []
        if allow:
            for item in allow:
                raw.extend(re.split(r"[,\s]+", item))
        if allow_file:
            p = Path(allow_file)
            if not p.exists():
                raise AuthorizationError(
                    f"target-allowlist file not found: {allow_file}")
            for line in p.read_text(encoding="utf-8").splitlines():
                raw.append(line)
        entries: List[_Entry] = []
        for item in raw:
            e = _parse_entry(item)
            if e is not None:
                entries.append(e)
        if rate_limit <= 0:
            raise AuthorizationError("rate limit must be > 0 req/s")
        return cls(entries=entries, authorized=authorized,
                   rate_limit=float(rate_limit), resolve=resolve)

    # -- enforcement ------------------------------------------------------
    def require_authorized(self) -> None:
        """Fail-closed if active scanning has not been explicitly authorized."""
        if not self.authorized:
            raise AuthorizationError(
                "active scanning is OFF by default — re-run with --authorized "
                "to confirm you are permitted to test this target.")
        if not self.entries:
            raise AuthorizationError(
                "active scanning requires a target scope — pass "
                "--target-allowlist host[:port] (repeatable) or "
                "--target-allowlist-file PATH.")

    def _hosts_for(self, host: str) -> List[str]:
        hosts = [host]
        if self.resolve:
            try:
                for info in socket.getaddrinfo(host, None):
                    ip = info[4][0]
                    if ip not in hosts:
                        hosts.append(ip)
            except OSError:
                pass
        return hosts

    def allows(self, target: str) -> bool:
        """True if ``target`` (URL or host[:port]) is inside the scope."""
        if not self.entries:
            return False
        host, port = _split_host_port(target)
        if not host:
            return False
        for h in self._hosts_for(host):
            for e in self.entries:
                if e.matches(h, port):
                    return True
        return False

    def check(self, target: str) -> None:
        """Authorize + scope-check ``target`` or raise AuthorizationError."""
        self.require_authorized()
        if not self.allows(target):
            raise AuthorizationError(
                f"target {target!r} is not in the authorized scope "
                f"({self.describe()}) — refusing to probe.")


class RateLimiter:
    """Simple monotonic token-spacing limiter: blocks so that calls to
    :meth:`acquire` happen no faster than ``rate`` per second."""

    def __init__(self, rate: float, *, clock=time.monotonic, sleep=time.sleep):
        if rate <= 0:
            raise ValueError("rate must be > 0")
        self._min_interval = 1.0 / rate
        self._clock = clock
        self._sleep = sleep
        self._next_allowed = 0.0

    def acquire(self) -> float:
        """Block until the next call is permitted; return seconds waited."""
        now = self._clock()
        wait = self._next_allowed - now
        if wait > 0:
            self._sleep(wait)
        else:
            wait = 0.0
        start = self._clock()
        self._next_allowed = start + self._min_interval
        return wait

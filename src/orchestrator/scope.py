"""Target scope matching for WRAITH authorization.

This is the deterministic, non-LLM policy primitive that decides whether a
target is inside an authorized engagement scope. It replaces the earlier
prefix/substring matcher (WRAITH.md Section 11.1, Authorization / Rules of
Engagement), which could accept "example.com.attacker.test", accept an empty
allowlist entry, accept "C:/repository-evil" against "C:/repo", and reject a
valid host inside a CIDR.

Matching rules:
  * blocklist is evaluated first; a blocklist hit always denies.
  * empty or whitespace-only entries never match anything.
  * CIDRs use real network containment (ipaddress), not string prefixes.
  * domains match a host exactly or as a true subdomain at a label boundary.
  * URLs match on scheme, host, port and a path-boundary prefix.
  * repository paths match by canonical (symlink-resolved) containment.
  * with enabled = False, nothing is in scope (fail closed).

Note on SSRF and DNS rebinding: host classification here is a static check.
An adapter that actually opens a connection MUST re-resolve and re-validate the
host at connect time; a name that is in scope now can resolve to a private or
metadata address later. guard_url() blocks the cloud metadata address and, when
requested, private ranges, but it is not a substitute for connect-time checks.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_URL_SCHEMES = ("http", "https", "ws", "wss")
_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}
_METADATA_ADDRESSES = frozenset({"169.254.169.254", "fd00:ec2::254"})


def _clean(entries: list[str]) -> list[str]:
    """Drop empty and whitespace-only entries so they cannot match."""
    return [e.strip() for e in entries if e and e.strip()]


def _norm_host(host: str | None) -> str | None:
    if not host:
        return None
    h = unicodedata.normalize("NFKC", host.strip().rstrip(".")).lower()
    if not h:
        return None
    try:
        h = h.encode("idna").decode("ascii")
    except Exception:
        # Not an IDNA-encodable name (for example a bare IP or an invalid
        # label); fall back to the normalized ASCII form.
        pass
    return h


def _as_ip(value: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def _looks_like_path(value: str) -> bool:
    v = value.strip()
    if not v:
        return False
    if "://" in v:
        return False
    if v[0] in "/~.":
        return True
    if "\\" in v:
        return True
    # Windows drive letter, for example C:\ or C:/
    if len(v) >= 3 and v[1] == ":" and v[2] in "\\/":
        return True
    return False


def classify_target(target: str) -> str:
    """Classify a target so `scope add` files it into the right list.

    Returns one of: "url", "cidr", "repo_path", "domain".
    """
    t = target.strip()
    if "://" in t:
        return "url"
    try:
        ipaddress.ip_network(t, strict=False)
        return "cidr"
    except ValueError:
        pass
    if _as_ip(t) is not None:
        return "cidr"
    if _looks_like_path(t):
        return "repo_path"
    return "domain"


def _cidr_contains(cidrs: list[str], ip: IPAddress) -> bool:
    for entry in _clean(cidrs):
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if ip.version == net.version and ip in net:
            return True
    return False


def _domain_matches(host: str, domains: list[str]) -> bool:
    target = _norm_host(host)
    if not target:
        return False
    for entry in _clean(domains):
        allowed = _norm_host(entry)
        if not allowed:
            continue
        if target == allowed or target.endswith("." + allowed):
            return True
    return False


def _url_matches(target: str, urls: list[str]) -> bool:
    tp = urlsplit(target)
    if tp.scheme not in _URL_SCHEMES or not tp.hostname:
        return False
    t_host = _norm_host(tp.hostname)
    t_port = tp.port or _DEFAULT_PORTS.get(tp.scheme)
    t_path = tp.path or "/"
    for entry in _clean(urls):
        ap = urlsplit(entry)
        if ap.scheme != tp.scheme or not ap.hostname:
            continue
        if _norm_host(ap.hostname) != t_host:
            continue
        a_port = ap.port or _DEFAULT_PORTS.get(ap.scheme)
        if a_port != t_port:
            continue
        a_path = ap.path or "/"
        if a_path in ("", "/"):
            return True
        base = a_path.rstrip("/")
        if t_path == a_path or t_path == base or t_path.startswith(base + "/"):
            return True
    return False


def _repo_matches(target: str, repo_paths: list[str]) -> bool:
    try:
        t = Path(target).expanduser().resolve(strict=False)
    except (OSError, RuntimeError, ValueError):
        return False
    for entry in _clean(repo_paths):
        try:
            root = Path(entry).expanduser().resolve(strict=False)
        except (OSError, RuntimeError, ValueError):
            continue
        if t == root or t.is_relative_to(root):
            return True
    return False


@dataclass
class ScopeList:
    """One side of the scope policy (allow or block)."""

    cidrs: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    repo_paths: list[str] = field(default_factory=list)

    def matches(self, target: str) -> bool:
        t = target.strip()
        if not t:
            return False
        # URL: match by url list, and let host authorize via domain/cidr lists.
        parsed = urlsplit(t)
        if parsed.scheme in _URL_SCHEMES and parsed.hostname:
            if _url_matches(t, self.urls):
                return True
            host_ip = _as_ip(parsed.hostname)
            if host_ip is not None:
                return _cidr_contains(self.cidrs, host_ip)
            return _domain_matches(parsed.hostname, self.domains)
        # Bare IP.
        ip = _as_ip(t)
        if ip is not None:
            return _cidr_contains(self.cidrs, ip)
        # Filesystem path.
        if _looks_like_path(t):
            return _repo_matches(t, self.repo_paths)
        # Otherwise treat as a domain.
        return _domain_matches(t, self.domains)


@dataclass
class Scope:
    """Authorized-target policy. Fails closed: empty or disabled means deny."""

    allow: ScopeList = field(default_factory=ScopeList)
    block: ScopeList = field(default_factory=ScopeList)
    enabled: bool = False
    allow_metadata: bool = False
    block_private: bool = False

    def allows(self, target: str) -> bool:
        if not self.enabled:
            return False  # nothing is authorized until scope is enabled
        if not target or not target.strip():
            return False
        if self.block.matches(target):
            return False  # deny wins
        return self.allow.matches(target)

    def guard_url(self, target: str) -> tuple[bool, str]:
        """Static SSRF guard for a URL target.

        Returns (ok, reason). This does not replace connect-time re-resolution.
        """
        parsed = urlsplit(target)
        host = parsed.hostname
        if not host:
            return True, ""
        ip = _as_ip(host)
        if ip is None:
            # A name, not a literal address. Cannot classify without resolving;
            # the adapter must re-check after DNS resolution at connect time.
            return True, "unresolved-name: adapter must re-validate at connect"
        if str(ip) in _METADATA_ADDRESSES and not self.allow_metadata:
            return False, "cloud metadata address blocked"
        if self.block_private and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved):
            return False, "private or loopback address blocked"
        return True, ""

    def fingerprint(self) -> str:
        """Stable hash of the scope contents, used to bind engagement signatures."""
        payload = {
            "enabled": self.enabled,
            "allow": {
                "cidrs": sorted(_clean(self.allow.cidrs)),
                "domains": sorted(_clean(self.allow.domains)),
                "urls": sorted(_clean(self.allow.urls)),
                "repo_paths": sorted(_clean(self.allow.repo_paths)),
            },
            "block": {
                "cidrs": sorted(_clean(self.block.cidrs)),
                "domains": sorted(_clean(self.block.domains)),
                "urls": sorted(_clean(self.block.urls)),
                "repo_paths": sorted(_clean(self.block.repo_paths)),
            },
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

"""Find the visitor's real IP, without trusting headers an attacker can fake."""
from __future__ import annotations

import ipaddress

UNKNOWN_IP = "0.0.0.0"


def canonical_ip(value: str | None) -> str | None:
    """Return a standard IP string, or None when the value is not an IP."""
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    mapped = getattr(ip, "ipv4_mapped", None)
    return str(mapped or ip)


def resolve_client_ip(peer: str | None, forwarded_for: str | None, trusted_hops: int) -> str:
    """Pick the client IP using the configured number of trusted proxies.

    Each trusted proxy appends the address it saw to X-Forwarded-For, so the real client
    is `trusted_hops` entries from the right. Anything further left is attacker-controlled.
    With zero trusted proxies the header is ignored entirely.
    """
    peer_ip = canonical_ip(peer) or UNKNOWN_IP
    if trusted_hops <= 0 or not forwarded_for:
        return peer_ip
    entries = [part.strip() for part in forwarded_for.split(",") if part.strip()]
    if len(entries) < trusted_hops:
        return peer_ip
    return canonical_ip(entries[-trusted_hops]) or peer_ip

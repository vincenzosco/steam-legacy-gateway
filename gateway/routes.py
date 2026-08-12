"""Route table: every hostname the old Steam client may contact -> where it goes.

Routing happens by hostname because the Lion machine resolves all of these names
to the gateway IP via /etc/hosts (see gateway/hosts.py). The TLS forwarder matches
the SNI / Host header against this table.

Route kinds:
  forward  -> terminate TLS, re-establish modern TLS to the real Valve host
  local    -> terminate TLS, pipe to a local origin (the content bridge)
  drop     -> refuse (safety valve for hosts we never want to proxy)
"""
from __future__ import annotations

from dataclasses import dataclass, field

# --- Hostname tables ----------------------------------------------------------

# Real Valve hosts that we forward to (modern TLS 1.2/1.3 upstream).
FORWARD_HOSTS: dict[str, str] = {
    "api.steampowered.com": "api.steampowered.com",
    "store.steampowered.com": "store.steampowered.com",
    "login.steampowered.com": "login.steampowered.com",
    "steamcommunity.com": "steamcommunity.com",
    "www.steampowered.com": "www.steampowered.com",
    "help.steampowered.com": "help.steampowered.com",
    "cdn.steampowered.com": "cdn.steampowered.com",
    "steamcdn-a.akamaihd.net": "steamcdn-a.akamaihd.net",
    "client-update.akamaihd.net": "client-update.akamaihd.net",
}

# Content hosts -> the local content origin (serves from the depot cache).
# cs.steampowered.com is the content-server host this Oct-2015 client actually
# uses (confirmed in the binary); steampipe/cacheN cover other eras.
LOCAL_ORIGIN_HOSTS: set[str] = {
    "cs.steampowered.com",
    "steampipe.akamaized.net",
    "steamcontent.com",
    "edgecast.steamcontent.com",
    "xfer.steampipe.akamaized.net",
}

# Hosts we should refuse to proxy (e.g. anything Valve could use to tell a
# real client from a proxied one). Empty by default.
DROP_HOSTS: set[str] = set()

# Hostnames the old client uses for CM connections (TCP, not HTTPS).
# These appear in /etc/hosts so the TCP listener on ports 27017-27020 receives them.
CM_HOSTNAMES: list[str] = [f"cm{i}.steampowered.com" for i in range(8)] + [
    "steam.cm",
]

# Legacy content servers used for downloads (cacheN.steampowered.com).
CONTENT_CACHE_HOSTS: list[str] = [f"cache{i}.steampowered.com" for i in range(1, 11)]

# Hostnames that may appear as SNI/Host for the legacy content protocol
# (cacheN.steampowered.com etc.). Substring-matched at the start ("cache").
LOCAL_PREFIX_HOSTS: tuple[str, ...] = ("cache",)


@dataclass
class Route:
    kind: str  # "forward" | "local" | "drop"
    host: str  # upstream host (Valve host or local origin)
    port: int = 443
    tls: bool = True
    note: str = ""
    # matched rule, for debugging
    rule: str = field(default="", compare=False)


def _content_origin(host: str) -> Route:
    return Route(kind="local", host="127.0.0.1", port=0, tls=False,
                 note=f"content origin ({host})", rule="content")


def _strip_port(host: str) -> str:
    """Remove a :port suffix (or [v6]:port form) from a Host header value."""
    if host.startswith("["):
        end = host.find("]")
        return host[1:end] if end != -1 else host
    if ":" in host and host.rsplit(":", 1)[1].isdigit():
        return host.rsplit(":", 1)[0]
    return host


def route_for(host: str | None, content_origin_port: int) -> Route:
    """Resolve a hostname (SNI or Host header) to a Route."""
    host = _strip_port((host or "").strip().rstrip(".").lower())
    if not host:
        return Route(kind="drop", host="", note="no hostname", rule="default")

    if host in DROP_HOSTS:
        return Route(kind="drop", host=host, note="explicitly dropped", rule="drop")

    if host in LOCAL_ORIGIN_HOSTS:
        r = _content_origin(host)
        r.port = content_origin_port
        return r

    if host.startswith(LOCAL_PREFIX_HOSTS) and host.endswith(".steampowered.com"):
        r = _content_origin(host)
        r.port = content_origin_port
        return r

    if host in FORWARD_HOSTS:
        upstream = FORWARD_HOSTS[host]
        return Route(kind="forward", host=upstream, port=443, tls=True,
                     note=f"forward {host} -> {upstream}", rule="forward")

    # Anything else: try forwarding to the same hostname over modern TLS.
    # This keeps the gateway transparent for unexpected Valve endpoints.
    return Route(kind="forward", host=host, port=443, tls=True,
                 note=f"passthrough {host}", rule="default-forward")


def all_forward_hostnames() -> list[str]:
    """Every hostname the gateway will serve a certificate for (SAN list)."""
    names = set(FORWARD_HOSTS)
    names.update(LOCAL_ORIGIN_HOSTS)
    names.update(DROP_HOSTS)
    return sorted(names)

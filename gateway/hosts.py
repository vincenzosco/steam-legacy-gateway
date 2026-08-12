"""Generate /etc/hosts entries for the Lion machine.

The old client resolves every Steam hostname to the gateway IP, so all its
connections land on the gateway. This module renders the exact block to paste
into /etc/hosts on the Lion Mac (see scripts/install_hosts.sh).
"""
from __future__ import annotations

from gateway.routes import (
    CM_HOSTNAMES,
    CONTENT_CACHE_HOSTS,
    FORWARD_HOSTS,
    LOCAL_ORIGIN_HOSTS,
)

# Common *.steamcontent.com edges the modern CDN may redirect to.
STEAMCONTENT_EDGES: list[str] = [
    "steamcontent.com",
    "edgecast.steamcontent.com",
    "akamai.steamcontent.com",
    "mecdn.steamcontent.com",
    "ltsteamcontent.com",
]

_HEADER = """\
# --- steam-legacy-gateway (added by scripts/install_hosts.sh) ---
# Maps every Steam hostname to the gateway machine, which translates the
# legacy protocol to modern Valve servers. Remove this block to revert.
"""

_FOOTER = """\
# --- end steam-legacy-gateway ---
"""


def _entries(gateway_ip: str) -> list[str]:
    hosts: list[str] = []
    hosts.extend(sorted(FORWARD_HOSTS))
    hosts.extend(sorted(LOCAL_ORIGIN_HOSTS))
    hosts.extend(STEAMCONTENT_EDGES)
    hosts.extend(CONTENT_CACHE_HOSTS)
    hosts.extend(CM_HOSTNAMES)
    return sorted(set(hosts))


def render(gateway_ip: str) -> str:
    """Render the hosts block as text (install this on the Lion machine)."""
    lines = [_HEADER]
    for host in _entries(gateway_ip):
        lines.append(f"{gateway_ip}\t{host}")
    lines.append("")
    lines.append(_FOOTER)
    return "\n".join(lines)


def strip_block(text: str) -> str:
    """Remove a previously-installed gateway block from /etc/hosts content."""
    start = text.find(_HEADER)
    end = text.find(_FOOTER)
    if start != -1 and end != -1:
        return text[:start] + text[end + len(_FOOTER):]
    return text

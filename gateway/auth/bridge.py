"""Auth bridge.

The gateway owns the *modern* login (credentials + Steam Guard), because the
2013 client's username/password logon is no longer accepted by Valve's servers.
The old client is then told it logged in successfully (legacy session
emulation in cm/translator.py) — the real session belongs to the gateway.
"""
from __future__ import annotations

import logging
import sys
from dataclasses import dataclass
from typing import Any

log = logging.getLogger("gateway.auth")


@dataclass
class Credentials:
    username: str
    password: str
    two_factor_code: str | None = None


def credentials_from_config(cfg: dict[str, Any]) -> Credentials | None:
    acc = cfg.get("account", {})
    if not acc.get("username") or not acc.get("password"):
        log.warning(
            "No account credentials in config. Set config/gateway.local.yaml "
            "(account.username / account.password) or STEAM_USERNAME / STEAM_PASSWORD env vars."
        )
        return None
    return Credentials(
        username=acc["username"],
        password=acc["password"],
        two_factor_code=acc.get("steam_guard") or None,
    )


def resolve_guard_code(credentials: Credentials) -> Credentials:
    """Prompt for a Steam Guard code if one wasn't supplied in config/env."""
    if credentials.two_factor_code:
        return credentials
    if not sys.stdin.isatty():
        log.info("Non-interactive run and no Steam Guard code configured; "
                 "the modern login will fail unless the account needs no guard.")
        return credentials
    code = input(f"Steam Guard code for {credentials.username}: ").strip()
    credentials.two_factor_code = code or None
    return credentials

"""Configuration loading for the gateway."""
from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULTS_PATH = PROJECT_ROOT / "config" / "gateway.yaml"
LOCAL_PATH = PROJECT_ROOT / "config" / "gateway.local.yaml"

DEFAULTS: dict[str, Any] = {
    "gateway_ip": "192.168.1.50",
    "tls": {"listen_port": 443, "plain_port": 80, "cert_dir": "certs"},
    "cm": {"listen_ports": [27017, 27018, 27019, 27020], "modern_cm_host": ""},
    "account": {"username": "", "password": "", "steam_guard": ""},
    "content": {
        "cache_dir": "content-cache",
        "listen_port": 18081,
        "depot_downloader_path": "",
        "preload": [],
    },
    "log_level": "INFO",
}


def _deep_merge(base: dict, override: dict) -> dict:
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """Load gateway.local.yaml merged over gateway.yaml, then code defaults."""
    cfg = copy.deepcopy(DEFAULTS)
    for candidate in (path, LOCAL_PATH, DEFAULTS_PATH):
        if candidate is None:
            continue
        p = Path(candidate)
        if p.is_file():
            with p.open("r", encoding="utf-8") as fh:
                cfg = _deep_merge(cfg, yaml.safe_load(fh) or {})
    # Resolve paths relative to the project root.
    def _resolve(key: str) -> None:
        for section in ("tls", "content"):
            if key in cfg.get(section, {}):
                cfg[section][key] = str(PROJECT_ROOT / cfg[section][key])

    _resolve("cert_dir")
    _resolve("cache_dir")
    return cfg


def account_configured(cfg: dict[str, Any]) -> bool:
    return bool(cfg.get("account", {}).get("username")) and bool(
        cfg.get("account", {}).get("password")
    )


def env_override(cfg: dict[str, Any]) -> dict[str, Any]:
    """Allow credentials to come from the environment instead of the config file."""
    cfg = copy.deepcopy(cfg)
    acc = cfg.setdefault("account", {})
    if os.environ.get("STEAM_USERNAME"):
        acc["username"] = os.environ["STEAM_USERNAME"]
    if os.environ.get("STEAM_PASSWORD"):
        acc["password"] = os.environ["STEAM_PASSWORD"]
    if os.environ.get("STEAM_GUARD_CODE"):
        acc["steam_guard"] = os.environ["STEAM_GUARD_CODE"]
    return cfg

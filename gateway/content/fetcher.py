"""Depot fetching for the content bridge.

The old client's own download pipeline died in 2021 (server-side), so the
gateway fetches game content using a *modern* mechanism and serves it through
the legacy URL scheme.

Primary path: DepotDownloader (SteamRE) CLI, a headless modern Steam downloader.
  https://github.com/SteamRE/DepotDownloader
Set `depot_downloader_path` in the config.

Fallback: ValvePython/steam CDN support if available (needs the same `steam`
package as the CM back-end).
"""
from __future__ import annotations

import asyncio
import logging
import shlex
import subprocess
from pathlib import Path
from typing import Any

from gateway.auth.bridge import credentials_from_config
from gateway.content.cache import ChunkCache

log = logging.getLogger("gateway.content.fetcher")


class Fetcher:
    def __init__(self, cfg: dict, cache: ChunkCache):
        self.cfg = cfg
        self.cache = cache
        self._locks: dict[tuple[int, int], asyncio.Lock] = {}

    async def ensure_depot(self, appid: int, depotid: int) -> bool:
        """Ensure the depot is downloaded into the cache. Returns True on success."""
        key = (appid, depotid)
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            if self.cache.has_manifest(appid, depotid):
                return True
            dd_path = self.cfg["content"].get("depot_downloader_path", "")
            if dd_path:
                return await self._fetch_with_depot_downloader(appid, depotid, dd_path)
            return await self._fetch_with_python(appid, depotid)

    async def _fetch_with_depot_downloader(self, appid: int, depotid: int,
                                           dd_path: str) -> bool:
        creds = credentials_from_config(self.cfg)
        if creds is None:
            log.warning("depot %d/%d: no account configured", appid, depotid)
            return False
        out_dir = self.cache._depot_dir(appid, depotid) / "files"
        cmd = [
            dd_path, "-app", str(appid), "-depot", str(depotid),
            "-dir", str(out_dir),
            "-username", creds.username, "-password", creds.password,
        ]
        if creds.two_factor_code:
            cmd += ["-code", creds.two_factor_code]
        # Never log credentials: mask values of -password / -code.
        display = list(cmd)
        for i, token in enumerate(display):
            if token in ("-password", "-code") and i + 1 < len(display):
                display[i + 1] = "***"
        log.info("running DepotDownloader: %s", shlex.join(display))
        log.warning(
            "NOTE: DepotDownloader args are visible in `ps` while running; "
            "use an account dedicated to this gateway."
        )
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
        )
        try:
            output, _ = await asyncio.wait_for(proc.communicate(), timeout=3600)
        except asyncio.TimeoutError:
            proc.kill()
            log.error("DepotDownloader timed out for %d/%d", appid, depotid)
            return False
        if proc.returncode != 0:
            log.error("DepotDownloader failed for %d/%d:\n%s",
                      appid, depotid, output.decode("utf-8", "replace")[-2000:])
            return False
        log.info("depot %d/%d downloaded to %s", appid, depotid, out_dir)
        return True

    async def _fetch_with_python(self, appid: int, depotid: int) -> bool:
        # Best-effort with ValvePython/steam CDN; the CM back-end must already
        # be logged in. This path is secondary; DepotDownloader is recommended.
        log.info("attempting ValvePython CDN fetch for %d/%d", appid, depotid)
        try:
            from steam.content.manifest import DepotManifest  # type: ignore
            from steam.content import CDNClient  # type: ignore
        except Exception as exc:  # noqa: BLE001 - library layout varies by version
            log.warning(
                "ValvePython CDN fetch unavailable (%s). Install DepotDownloader "
                "and set content.depot_downloader_path, or run manually:\n"
                "  dotnet DepotDownloader.dll -app %d -depot %d -dir <dir>",
                exc, appid, depotid,
            )
            return False
        # NOTE: wiring CDNClient requires a logged-in SteamClient instance from
        # the modern session; see cm/modern.py `client()`. Filled in once the
        # ValvePython CDN API surface for this version is confirmed.
        return False

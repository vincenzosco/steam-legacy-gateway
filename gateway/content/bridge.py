"""Legacy content origin.

Serves the URL patterns the 2013-era client used against content servers
(cacheN.steampowered.com / steampipe.akamaized.net):

    /depot/<appid>/manifest/<gid>          -> depot manifest
    /depot/<depotid>/chunk/<gid>           -> chunk data
    /chunk/<gid>                           -> chunk data (alternate form)
    /depot/<depotid>/<filename>            -> whole-file serving

Every request is logged — that log is the ground truth for verifying the
legacy content protocol against a real client.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from gateway.content.cache import ChunkCache
from gateway.content.fetcher import Fetcher
from gateway.minihttp import Request, build_response

log = logging.getLogger("gateway.content.bridge")

_MANIFEST_RE = re.compile(r"^/depot/(\d+)/manifest/([0-9a-fA-F]+)/?$")
_CHUNK_RE = re.compile(r"^/depot/(\d+)/chunk/([0-9a-fA-F]+)/?$")
_CHUNK_ALT_RE = re.compile(r"^/chunk/([0-9a-fA-F]+)/?$")
_FILE_RE = re.compile(r"^/depot/(\d+)/([^/]+)$")


class ContentBridge:
    def __init__(self, cfg: dict, cache: ChunkCache, fetcher: Fetcher):
        self.cfg = cfg
        self.cache = cache
        self.fetcher = fetcher
        self.preloaded: set[tuple[int, int]] = set()

    async def warm_preload(self) -> None:
        for entry in self.cfg["content"].get("preload", []):
            appid, depotid = int(entry["appid"]), int(entry["depot"])
            log.info("preloading depot %d/%d", appid, depotid)
            await self.fetcher.ensure_depot(appid, depotid)
            self.preloaded.add((appid, depotid))

    async def handle(self, req: Request, writer) -> None:
        log.info("content request: %s %s", req.method, req.target)

        if req.method != "GET" and req.method != "HEAD":
            writer.write(build_response(405, {"Content-Type": "text/plain"}, b"method not allowed"))
            await writer.drain()
            return

        m = _MANIFEST_RE.match(req.path)
        if m:
            appid = int(m.group(1))
            depotid = await self._first_depot_for_appid(appid)
            if depotid is not None:
                await self.fetcher.ensure_depot(appid, depotid)
                if self.cache.has_manifest(appid, depotid):
                    await self._respond(writer, self.cache.manifest_path(appid, depotid).read_bytes(),
                                        content_type="application/octet-stream")
                    return
            await self._respond(writer, b"manifest not cached\n", status=404)
            return

        m = _CHUNK_RE.match(req.path)
        if m:
            depotid, chunkid = int(m.group(1)), m.group(2).lower()
            appid = await self._appid_for_depot(depotid)
            if appid is not None and self.cache.has_chunk(appid, depotid, chunkid):
                await self._respond(writer, self.cache.chunk_path(appid, depotid, chunkid).read_bytes())
            else:
                await self._respond(writer, b"chunk not cached\n", status=404)
            return

        m = _CHUNK_ALT_RE.match(req.path)
        if m:
            chunkid = m.group(1).lower()
            await self._respond(writer, b"chunk id without depot context - cannot route\n", status=404)
            return

        m = _FILE_RE.match(req.path)
        if m:
            depotid, fname = int(m.group(1)), m.group(2)
            appid = await self._appid_for_depot(depotid)
            if appid is not None:
                files = self.cache._depot_dir(appid, depotid) / "files"
                candidate = (files / fname).resolve()
                if candidate.is_file() and files.resolve() in candidate.parents:
                    await self._respond(writer, candidate.read_bytes())
                    return
            await self._respond(writer, b"file not cached\n", status=404)
            return

        await self._respond(writer, b"unknown content path\n", status=404)

    async def _appid_for_depot(self, depotid: int) -> int | None:
        # Reconstruct appid from cache layout (<cache>/<appid>/<depotid>/).
        for appid_dir in self.cache.root.iterdir():
            if appid_dir.is_dir() and (appid_dir / str(depotid)).is_dir():
                return int(appid_dir.name)
        return None

    async def _first_depot_for_appid(self, appid: int) -> int | None:
        # Manifest URLs carry the appid but not the depot id; find the first
        # depot folder under <cache>/<appid>/.
        appid_dir = self.cache.root / str(appid)
        if not appid_dir.is_dir():
            return None
        for depotid_dir in appid_dir.iterdir():
            if depotid_dir.is_dir():
                return int(depotid_dir.name)
        return None

    async def _respond(self, writer, body: bytes, status: int = 200,
                       content_type: str = "application/octet-stream") -> None:
        writer.write(build_response(status, {"Content-Type": content_type}, body))
        await writer.drain()

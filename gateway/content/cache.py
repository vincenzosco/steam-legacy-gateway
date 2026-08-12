"""On-disk cache for depot manifests and chunks.

Layout:
    <cache_dir>/<appid>/<depotid>/manifest
    <cache_dir>/<appid>/<depotid>/chunks/<chunkid>
"""
from __future__ import annotations

from pathlib import Path


class ChunkCache:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _depot_dir(self, appid: int | str, depotid: int | str) -> Path:
        d = self.root / str(appid) / str(depotid)
        d.mkdir(parents=True, exist_ok=True)
        return d

    def manifest_path(self, appid: int | str, depotid: int | str) -> Path:
        return self._depot_dir(appid, depotid) / "manifest"

    def chunk_path(self, appid: int | str, depotid: int | str, chunkid: str) -> Path:
        return self._depot_dir(appid, depotid) / "chunks" / chunkid

    def has_manifest(self, appid: int | str, depotid: int | str) -> bool:
        return self.manifest_path(appid, depotid).is_file()

    def has_chunk(self, appid: int | str, depotid: int | str, chunkid: str) -> bool:
        return self.chunk_path(appid, depotid, chunkid).is_file()

    def store_manifest(self, appid: int | str, depotid: int | str, data: bytes) -> None:
        self.manifest_path(appid, depotid).write_bytes(data)

    def store_chunk(self, appid: int | str, depotid: int | str,
                    chunkid: str, data: bytes) -> None:
        self.chunk_path(appid, depotid, chunkid).write_bytes(data)

    def total_bytes(self) -> int:
        return sum(p.stat().st_size for p in self.root.rglob("*") if p.is_file())

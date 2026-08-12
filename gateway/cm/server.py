"""Legacy CM TCP listener on ports 27017-27020.

The old client resolves cm0-cm7.steampowered.com to the gateway IP (hosts file)
and connects on 27017 (falling back to 27018+). Each connection gets a
TranslatorSession that terminates the legacy protocol.
"""
from __future__ import annotations

import asyncio
import logging
import struct
import time
from pathlib import Path
from typing import Any

from gateway.cm.framing import FramingError, read_frame
from gateway.cm.modern import ModernSession
from gateway.cm.translator import TranslatorSession

log = logging.getLogger("gateway.cm.server")


class _CaptureWriter:
    """Wraps a StreamWriter and tees outbound bytes into a capture file.

    Outbound bytes are prefixed with ">", inbound with "<" (see _handle_conn).
    The file is flushed after every write so a crash never loses a handshake.
    """

    def __init__(self, inner: asyncio.StreamWriter, fh):
        self._inner = inner
        self._fh = fh

    def write(self, data: bytes) -> None:
        self._fh.write(b">" + data)
        self._fh.flush()
        self._inner.write(data)

    async def drain(self) -> None:
        await self._inner.drain()

    def close(self) -> None:
        try:
            self._inner.close()
        except Exception:
            pass


def _open_capture(capture_dir: str, peer) -> object | None:
    if not capture_dir:
        return None
    Path(capture_dir).mkdir(parents=True, exist_ok=True)
    stamp = f"{int(time.time() * 1000)}"
    fname = f"conn-{stamp}-{peer[0]}-{peer[1]}.bin"
    fh = (Path(capture_dir) / fname).open("wb")
    log.info("capturing connection bytes to %s", fname)
    return fh


async def _handle_conn(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                       cfg: dict, modern: ModernSession | None) -> None:
    peer = writer.get_extra_info("peername")
    capture_fh = _open_capture(cfg["cm"].get("capture_dir", "") or "", peer)
    if capture_fh is not None:
        writer = _CaptureWriter(writer, capture_fh)
    session = TranslatorSession(writer, cfg, modern)
    log.info("legacy CM connection from %s", peer)
    try:
        # Server-initiated channel encryption: send ChannelEncryptRequest(130).
        await session.start_handshake()
        while True:
            try:
                frame = await asyncio.wait_for(read_frame(reader), timeout=180)
            except FramingError as exc:
                log.warning("framing error from %s: %s", peer, exc)
                break
            except asyncio.IncompleteReadError:
                break
            except asyncio.TimeoutError:
                log.info("idle legacy connection from %s timed out", peer)
                break
            if frame is None:
                break
            if capture_fh is not None:
                # Rebuild the exact wire bytes: 4-byte length prefix + payload.
                capture_fh.write(b"<" + struct.pack("<I", len(frame.raw)) + frame.raw)
                capture_fh.flush()
            await session.handle(frame)
    except (ConnectionResetError, BrokenPipeError):
        pass
    except asyncio.CancelledError:
        raise
    except Exception:
        log.exception("CM handler error for %s", peer)
    finally:
        await session.close()
        if capture_fh is not None:
            capture_fh.close()
        log.info("legacy CM connection from %s closed", peer)


async def run_cm_server(cfg: dict, modern: ModernSession,
                        stop_event: asyncio.Event) -> list[asyncio.Server]:
    servers: list[asyncio.Server] = []
    for port in cfg["cm"]["listen_ports"]:
        server = await asyncio.start_server(
            lambda r, w: _handle_conn(r, w, cfg, modern),
            "0.0.0.0",
            port,
        )
        servers.append(server)
        log.info("legacy CM listener on :%s", port)
    return servers

"""Legacy CM TCP listener on ports 27017-27020.

The old client resolves cm0-cm7.steampowered.com to the gateway IP (hosts file)
and connects on 27017 (falling back to 27018+). Each connection gets a
TranslatorSession that terminates the legacy protocol.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from gateway.cm.framing import FramingError, read_frame
from gateway.cm.modern import ModernSession
from gateway.cm.translator import TranslatorSession

log = logging.getLogger("gateway.cm.server")


async def _handle_conn(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                       cfg: dict, modern: ModernSession) -> None:
    peer = writer.get_extra_info("peername")
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
            await session.handle(frame)
    except (ConnectionResetError, BrokenPipeError):
        pass
    except asyncio.CancelledError:
        raise
    except Exception:
        log.exception("CM handler error for %s", peer)
    finally:
        await session.close()
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

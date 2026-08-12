"""TLS-terminating HTTPS forwarder.

Terminates the old client's connection (TLS 1.0-era is attempted; OpenSSL 3.x
may refuse the very oldest ciphers, see note in `_server_context`), reads the
first HTTP request, resolves the route by Host header, then:
  - forward:  re-establishes modern TLS (>= 1.2) to the real Valve host and
              pumps bytes bidirectionally
  - local:    pumps bytes to the local content origin (plaintext on loopback)
  - drop:     refuses with a 403

Connections are closed after the upstream response completes ("close after one
request"), which is all an HTTP/1.1-era Steam client needs.
"""
from __future__ import annotations

import asyncio
import logging
import ssl
from pathlib import Path

from gateway import routes
from gateway.certs import ensure_bundle_cert
from gateway.minihttp import MAX_HEADER_BYTES

log = logging.getLogger("gateway.tls_proxy")

MAX_PEEK_BYTES = MAX_HEADER_BYTES


def _server_context(cert_dir: Path) -> ssl.SSLContext:
    cert_path, key_path = ensure_bundle_cert(cert_dir)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    # Try to accept the oldest TLS the Lion client can offer. OpenSSL 3.x builds
    # usually still include TLS 1.0/1.1 ciphers; if your build refuses them,
    # drop the minimum to TLSv1 (the old client cannot do better).
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    return ctx


def _upstream_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_default_certs()  # trust the system CA store for Valve's real certs
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # modern Valve endpoints require this
    return ctx


async def _read_first_request(reader: asyncio.StreamReader) -> tuple[str, bytes] | None:
    """Read just enough to see the request line + headers. Returns (host, raw_bytes)."""
    try:
        raw = await reader.readuntil(b"\r\n\r\n")
    except (asyncio.IncompleteReadError, ValueError):
        return None
    if len(raw) > MAX_PEEK_BYTES:
        return None
    header_block = raw.decode("latin-1", errors="replace").lower()
    host = ""
    for line in header_block.split("\r\n")[1:]:
        if line.startswith("host:"):
            host = line[5:].strip()
    # Also honour the absolute-form target ("GET http://host/path HTTP/1.1").
    request_line = header_block.split("\r\n")[0]
    parts = request_line.split(" ")
    if len(parts) >= 2 and parts[1].startswith("http://"):
        host = parts[1].split("/")[2].split(":")[0]
    return host, raw


async def _pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
    try:
        while True:
            chunk = await src.read(64 * 1024)
            if not chunk:
                break
            dst.write(chunk)
            await dst.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
        pass
    finally:
        try:
            dst.close()
        except Exception:
            pass


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                  content_origin_port: int) -> None:
    peer = writer.get_extra_info("peername")
    try:
        try:
            peeked = await asyncio.wait_for(_read_first_request(reader), timeout=30)
        except asyncio.TimeoutError:
            peeked = None
        if peeked is None:
            await writer.close()
            return
        host, first_bytes = peeked
        route = routes.route_for(host, content_origin_port)
        log.info("conn %s host=%r -> %s", peer, host, route.note)

        if route.kind == "drop":
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            await writer.close()
            return

        if route.kind == "forward":
            upstream = await asyncio.open_connection(
                route.host, route.port, ssl=_upstream_context(),
                server_hostname=route.host,
            )
        else:  # local origin
            upstream = await asyncio.open_connection(route.host, route.port)

        up_reader, up_writer = upstream
        up_writer.write(first_bytes)
        await up_writer.drain()

        # Pump BOTH directions: the request body (POSTs, chunk uploads) sits in
        # the client reader after the headers and must be forwarded too.
        to_up = asyncio.create_task(_pump(reader, up_writer))
        to_client = asyncio.create_task(_pump(up_reader, writer))
        try:
            done, pending = await asyncio.wait(
                {to_up, to_client}, return_when=asyncio.FIRST_COMPLETED, timeout=90
            )
            if to_client in done:
                # Upstream closed: response complete. Stop forwarding client bytes.
                for task in pending:
                    task.cancel()
            elif done:
                # Client closed first: drain the remaining upstream response.
                try:
                    await asyncio.wait_for(to_client, timeout=30)
                except (asyncio.TimeoutError, ConnectionError, asyncio.CancelledError):
                    to_client.cancel()
            else:
                # Nothing completed within the idle budget: close everything.
                for task in pending:
                    task.cancel()
        finally:
            for task in (to_up, to_client):
                if not task.done():
                    task.cancel()
            await asyncio.gather(to_up, to_client, return_exceptions=True)
            for w in (writer, up_writer):
                try:
                    w.close()
                except Exception:
                    pass
    except ssl.SSLError as exc:
        log.info("TLS handshake failed from %s: %s", peer, exc)
        try:
            writer.close()
        except Exception:
            pass
    except (ConnectionResetError, BrokenPipeError, asyncio.TimeoutError):
        try:
            writer.close()
        except Exception:
            pass
    except Exception:
        log.exception("proxy error for peer %s", peer)
        try:
            writer.close()
        except Exception:
            pass


async def run_tls_proxy(cfg: dict, stop_event: asyncio.Event) -> list[asyncio.Server]:
    """Start the 443 (TLS) and 80 (plain) listeners. Returns server objects."""
    cert_dir = Path(cfg["tls"]["cert_dir"])
    content_port = cfg["content"]["listen_port"]
    servers: list[asyncio.Server] = []

    ssl_ctx = _server_context(cert_dir)
    tls_server = await asyncio.start_server(
        lambda r, w: _handle(r, w, content_port),
        "0.0.0.0",
        cfg["tls"]["listen_port"],
        ssl=ssl_ctx,
    )
    servers.append(tls_server)
    log.info("TLS forwarder on :%s", cfg["tls"]["listen_port"])

    plain_server = await asyncio.start_server(
        lambda r, w: _handle(r, w, content_port),
        "0.0.0.0",
        cfg["tls"]["plain_port"],
    )
    servers.append(plain_server)
    log.info("Plain HTTP forwarder on :%s", cfg["tls"]["plain_port"])
    return servers

"""Minimal async HTTP/1.1 server used by the content bridge.

No external framework: just enough to parse a request line + headers, hand the
request to a handler, and stream a response. Supports keep-alive and
Content-Length bodies (chunked is passed through raw for proxying).
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

log = logging.getLogger("gateway.minihttp")

MAX_HEADER_BYTES = 64 * 1024
MAX_BODY_BYTES = 256 * 1024 * 1024  # chunk bodies are large; cap defensively


@dataclass
class Request:
    method: str
    target: str
    version: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    @property
    def path(self) -> str:
        return self.target.split("?", 1)[0]

    @property
    def query(self) -> dict[str, str]:
        from urllib.parse import parse_qs, urlsplit

        qs = parse_qs(urlsplit(self.target).query)
        return {k: v[0] for k, v in qs.items()}


def build_response(status: int, headers: dict[str, str], body: bytes = b"") -> bytes:
    reason = {200: "OK", 301: "Moved Permanently", 404: "Not Found",
              500: "Internal Server Error", 502: "Bad Gateway"}.get(status, "Unknown")
    lines = [f"HTTP/1.1 {status} {reason}"]
    headers.setdefault("Content-Length", str(len(body)))
    headers.setdefault("Connection", "keep-alive")
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


async def _read_headers(reader: asyncio.StreamReader) -> tuple[str, dict[str, str], int]:
    raw = await reader.readuntil(b"\r\n\r\n")
    if len(raw) > MAX_HEADER_BYTES:
        raise ValueError("headers too large")
    header_block = raw[:-4].decode("latin-1")
    lines = header_block.split("\r\n")
    request_line = lines[0]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    content_length = int(headers.get("content-length", "0"))
    return request_line, headers, content_length


async def handle_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    handler,
) -> None:
    """Serve keep-alive requests on one connection. `handler(req, writer)` async."""
    peer = writer.get_extra_info("peername")
    try:
        while True:
            try:
                request_line, headers, content_length = await asyncio.wait_for(
                    _read_headers(reader), timeout=30
                )
            except (asyncio.IncompleteReadError, ValueError, asyncio.TimeoutError):
                break
            if content_length > MAX_BODY_BYTES:
                writer.write(build_response(413, {}, b"body too large"))
                await writer.drain()
                break
            body = await reader.readexactly(content_length) if content_length else b""

            method, target, version = request_line.split(" ", 2)
            req = Request(method=method, target=target, version=version,
                          headers=headers, body=body)
            try:
                await handler(req, writer)
            except Exception:
                log.exception("handler error for %s %s (peer=%s)", method, target, peer)
                try:
                    writer.write(build_response(500, {}, b"gateway error"))
                    await writer.drain()
                except Exception:
                    break
            if headers.get("connection", "").lower() == "close" or version == "HTTP/1.0":
                break
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        try:
            await writer.drain()
            writer.close()
        except Exception:
            pass


async def serve(host: str, port: int, handler) -> asyncio.Server:
    server = await asyncio.start_server(
        lambda r, w: handle_connection(r, w, handler), host, port
    )
    log.info("mini-http listening on %s:%s", host, port)
    return server

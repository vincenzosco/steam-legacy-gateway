import asyncio

from gateway.minihttp import build_response, Request, _read_headers


def test_build_response():
    resp = build_response(200, {"Content-Type": "text/plain"}, b"ok")
    assert resp.startswith(b"HTTP/1.1 200 OK\r\n")
    assert b"Content-Length: 2" in resp
    assert resp.endswith(b"\r\n\r\nok")


def test_read_headers_parses_host():
    raw = b"GET /depot/220/manifest/123 HTTP/1.1\r\nHost: cache1.steampowered.com\r\n\r\n"

    async def run():
        reader = asyncio.StreamReader()
        reader.feed_data(raw)
        reader.feed_eof()
        return await _read_headers(reader)

    line, headers, length = asyncio.run(run())
    assert line.startswith("GET /depot/220")
    assert headers["host"] == "cache1.steampowered.com"
    assert length == 0


def test_request_helpers():
    req = Request(method="GET", target="/depot/220/chunk/abc?x=1&x=2", version="HTTP/1.1")
    assert req.path == "/depot/220/chunk/abc"
    assert req.query == {"x": "1"}  # first value wins

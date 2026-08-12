import asyncio

from gateway.cm.server import run_cm_server
from gateway.cm.sim_client import run_handshake


def _cfg() -> dict:
    return {"cm": {"listen_ports": [0], "capture_dir": ""}, "account": {}}


def _run_scenario():
    async def scenario():
        cfg = _cfg()
        servers = await run_cm_server(cfg, None, None)
        server = servers[0]
        port = server.sockets[0].getsockname()[1]
        try:
            return await run_handshake("127.0.0.1", port, account="simuser")
        finally:
            server.close()
            await server.wait_closed()

    return asyncio.run(scenario())


def test_handshake_end_to_end():
    res = _run_scenario()
    # Channel encryption accepted.
    assert res.channel_result == 1
    # No modern session configured -> the logon must be refused (not silently
    # accepted), but still answered with a valid protobuf 940.
    assert res.logon_eresult is not None
    assert res.logon_eresult != 1
    assert res.session_token is None  # no token on refusal
    # Exact frame sequence the real client would walk through.
    assert [f.name for f in res.frames] == [
        "ChannelEncryptRequest",
        "ChannelEncryptResponse",
        "ChannelEncryptResult",
        "ClientLogon",
        "ClientLogOnResponse",
    ]
    assert res.ok


def test_capture_render_contains_frames():
    res = _run_scenario()
    text = res.render_capture()
    assert "ChannelEncryptRequest" in text
    assert "ChannelEncryptResult" in text
    assert "00000000" in text  # hexdump rows present

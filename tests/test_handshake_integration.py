import asyncio

from gateway.cm.server import run_cm_server
from gateway.cm.sim_client import run_handshake


def _cfg() -> dict:
    return {"cm": {"listen_ports": [0], "capture_dir": "",
                   "sentry_store": ""},
            "account": {}, "gateway_ip": "127.0.0.1"}


class _FakeModern:
    """Stand-in modern session: always ready, fixed steamid."""

    def is_ready(self) -> bool:
        return True

    def steam_id(self) -> int:
        return 76561197960265728


def _run_scenario(modern=None):
    async def scenario():
        cfg = _cfg()
        servers = await run_cm_server(cfg, modern, None)
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
    # accepted), but still answered with a valid protobuf 751.
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


def test_handshake_with_machine_auth_end_to_end():
    """Successful logon: gateway pushes a sentry (5537), we confirm (5538),
    then it offers a login key (5463) which we accept (5464)."""
    res = _run_scenario(modern=_FakeModern())
    assert res.channel_result == 1
    assert res.logon_eresult == 1
    assert res.session_token is not None
    # The MachineAuth exchange must have happened.
    assert res.sentry_sha != b""
    assert res.sentry_job_id is not None
    assert res.sentry_filename.startswith("ssfn")
    assert res.login_key_unique_id is not None

    names = [f.name for f in res.frames]
    for expected in ("ClientUpdateMachineAuth", "ClientUpdateMachineAuthResponse",
                     "ClientNewLoginKey", "ClientNewLoginKeyAccepted",
                     "ClientLogOnResponse", "ClientSessionToken",
                     "ClientAccountInfo", "ClientCMList"):
        assert expected in names, f"{expected} missing from {names}"
    # Ordering: sentry push comes before login key offer.
    assert names.index("ClientUpdateMachineAuth") < names.index("ClientNewLoginKey")


def test_capture_render_contains_frames():
    res = _run_scenario()
    text = res.render_capture()
    assert "ChannelEncryptRequest" in text
    assert "ChannelEncryptResult" in text
    assert "00000000" in text  # hexdump rows present

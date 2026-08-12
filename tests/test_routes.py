from gateway import routes

ORIGIN_PORT = 18081


def test_forward_hosts():
    r = routes.route_for("api.steampowered.com", ORIGIN_PORT)
    assert r.kind == "forward"
    assert r.host == "api.steampowered.com"
    assert r.tls is True


def test_content_hosts_route_local():
    for host in ("steampipe.akamaized.net", "edgecast.steamcontent.com"):
        r = routes.route_for(host, ORIGIN_PORT)
        assert r.kind == "local"
        assert r.port == ORIGIN_PORT


def test_legacy_cache_hosts_route_local():
    for host in ("cache1.steampowered.com", "cache10.steampowered.com"):
        r = routes.route_for(host, ORIGIN_PORT)
        assert r.kind == "local", host


def test_passthrough_for_unknown():
    r = routes.route_for("some-other.steampowered.com", ORIGIN_PORT)
    assert r.kind == "forward"
    assert r.host == "some-other.steampowered.com"


def test_drop_for_empty():
    assert routes.route_for("", ORIGIN_PORT).kind == "drop"
    assert routes.route_for(None, ORIGIN_PORT).kind == "drop"


def test_trailing_dot_and_case():
    r = routes.route_for("API.STEAMPOWERED.COM.", ORIGIN_PORT)
    assert r.kind == "forward"

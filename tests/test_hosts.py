from gateway import hosts


def test_render_contains_core_domains():
    block = hosts.render("10.0.0.5")
    assert "10.0.0.5\tapi.steampowered.com" in block
    assert "10.0.0.5\tstore.steampowered.com" in block
    assert "10.0.0.5\tcm0.steampowered.com" in block
    assert "10.0.0.5\tcache1.steampowered.com" in block
    assert "steam-legacy-gateway" in block


def test_strip_removes_only_block():
    original = "127.0.0.1 localhost\n" + hosts.render("10.0.0.5")
    stripped = hosts.strip_block(original)
    assert "10.0.0.5" not in stripped
    assert "127.0.0.1 localhost" in stripped
    # Stripping twice is idempotent.
    assert hosts.strip_block(stripped) == stripped


def test_strip_without_block_is_identity():
    text = "127.0.0.1 localhost\n"
    assert hosts.strip_block(text) == text

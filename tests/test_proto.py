from gateway.cm import proto


def test_varint_roundtrip():
    for value in (0, 1, 127, 128, 300, 2**32, 2**63):
        data = proto.varint(value)
        assert data[0] & 0x80 or len(data) == 1  # well-formed
        decoded, off = proto._read_varint(data, 0)
        assert decoded == value
        assert off == len(data)


def test_parse_fields_roundtrip():
    msg = (
        proto.string_field(1, "myaccount")
        + proto.bytes_field(2, b"\x01\x02\x03")
        + proto.varint_field(3, 65542)
        + proto.fixed64_field(1, 0x123456789)
    )
    fields = list(proto.parse_fields(msg))
    numbers = sorted(f.number for f in fields)
    assert numbers == [1, 1, 2, 3]
    assert proto.field_text(1, msg) == "myaccount"
    assert proto.field_bytes(2, msg) == b"\x01\x02\x03"
    assert proto.field_varint(3, msg) == 65542


def test_field_missing():
    assert proto.field_text(9, b"") is None
    assert proto.field_bytes(9, b"") is None
    assert proto.field_varint(9, b"") == 0


def test_logon_shaped_message():
    # Mimic CMsgClientLogon: account_name=50, password=51 (RSA blob).
    logon = proto.string_field(50, "vincenzosco") + proto.bytes_field(51, b"\x00" * 128)
    assert proto.field_text(50, logon) == "vincenzosco"
    assert len(proto.field_bytes(51, logon)) == 128


def test_field_fixed64():
    import struct

    msg = proto.fixed64_field(11, 0x1234)
    assert proto.field_fixed64(11, msg) == 0x1234
    assert proto.field_fixed64(10, msg) == 0  # absent
    packed = struct.pack("<Q", 0xFFFFFFFFFFFFFFFF)
    msg2 = proto.fixed64_field(10, 0xFFFFFFFFFFFFFFFF)
    assert proto.field_fixed64(10, msg2) == 0xFFFFFFFFFFFFFFFF

import hashlib

from gateway.cm import machineauth, proto


def test_update_machine_auth_roundtrip():
    data = b"\x01\x02\x03" * 80
    body = machineauth.build_update_machine_auth("ssfn123", 0, data)
    parsed = machineauth.parse_update_machine_auth(body)
    assert parsed.filename == "ssfn123"
    assert parsed.offset == 0
    assert parsed.cubtowrite == len(data)
    assert parsed.bytes_ == data


def test_update_machine_auth_response_roundtrip():
    sha = hashlib.sha1(b"data").digest()
    body = machineauth.build_update_machine_auth_response(
        "ssfn123", eresult=1, filesize=1024, sha_file=sha, offset=0,
        cubwrote=1024)
    parsed = machineauth.parse_update_machine_auth_response(body)
    assert parsed.filename == "ssfn123"
    assert parsed.eresult == 1
    assert parsed.filesize == 1024
    assert parsed.sha_file == sha
    assert parsed.cubwrote == 1024


def test_read_machine_auth_roundtrip():
    req = machineauth.build_read_machine_auth("ssfn123", 0, 128)
    parsed = machineauth.parse_read_machine_auth(req)
    assert parsed.filename == "ssfn123"
    assert parsed.cubtoread == 128

    data = b"\xAA" * 128
    resp = machineauth.build_read_machine_auth_response(
        "ssfn123", eresult=1, filesize=256,
        sha_file=hashlib.sha1(data).digest(), offset=0, bytes_read=data)
    parsed = machineauth.parse_read_machine_auth_response(resp)
    assert parsed.filesize == 256
    assert parsed.bytes_read == data


def test_request_machine_auth_roundtrip():
    sha = hashlib.sha1(b"sentry").digest()
    body = machineauth.build_request_machine_auth_response(1)
    assert proto.field_varint(1, body) == 1


def test_new_login_key_pair():
    body = machineauth.build_new_login_key(42, "deadbeef")
    key = machineauth.parse_new_login_key(body)
    assert key.unique_id == 42
    assert key.login_key == "deadbeef"

    accepted = machineauth.build_new_login_key_accepted(42)
    assert proto.field_varint(1, accepted) == 42


def test_header_job_ids():
    hdr = machineauth.header(jobid_source=7, jobid_target=0)
    assert machineauth.jobid_source(hdr) == 7
    assert machineauth.jobid_target(hdr) == machineauth.JOB_NONE

    hdr2 = machineauth.header(jobid_source=7, jobid_target=9)
    assert machineauth.jobid_target(hdr2) == 9


def test_header_steamid_sessionid():
    hdr = machineauth.header(steamid=76561197960265728, client_sessionid=3)
    assert machineauth.steamid_of(hdr) == 76561197960265728
    assert proto.field_varint(2, hdr) == 3


def test_sentry_filename_deterministic():
    a = machineauth.sentry_filename("alice")
    b = machineauth.sentry_filename("alice")
    c = machineauth.sentry_filename("bob")
    assert a == b
    assert a != c
    assert a.startswith("ssfn")


def test_sentinel_store_roundtrip(tmp_path):
    store = machineauth.SentinelStore(tmp_path / "sentries.json")
    sha = hashlib.sha1(b"sentry-data").digest()
    store.put("alice", machineauth.SentryEntry(
        filename="ssfnAAA", filesize=11, sha_file=sha, data=b"sentry-data"))

    reloaded = machineauth.SentinelStore(tmp_path / "sentries.json")
    entry = reloaded.get("alice", "ssfnAAA")
    assert entry is not None
    assert entry.sha_file == sha
    assert entry.data == b"sentry-data"
    assert reloaded.sha_for("alice") == sha
    assert reloaded.sha_for("nobody") is None


def test_sentinel_store_delete(tmp_path):
    store = machineauth.SentinelStore(tmp_path / "s.json")
    store.put("alice", machineauth.SentryEntry(
        filename="ssfnAAA", filesize=1, sha_file=b"x", data=b"x"))
    store.delete("alice", "ssfnAAA")
    assert store.get("alice", "ssfnAAA") is None

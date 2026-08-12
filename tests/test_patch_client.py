"""Tests for scripts/patch_client.py — in-place CM endpoint patching."""
import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
_SRC = _SCRIPTS / "patch_client.py"

spec = importlib.util.spec_from_file_location("patch_client", _SRC)
patch_client = importlib.util.module_from_spec(spec)
sys.modules["patch_client"] = patch_client
spec.loader.exec_module(patch_client)


def _fake_dylib(tmp_path: Path, addrs: list[str]) -> Path:
    d = tmp_path / "steamclient.dylib"
    table = b"".join(f"{a}\0".encode() for a in addrs) + b"\0" * 64
    d.write_bytes(table)
    return d


def test_scan_finds_cm_slots(tmp_path):
    dylib = _fake_dylib(tmp_path, ["208.64.200.201:27017", "208.64.200.201:27018"])
    data = dylib.read_bytes()
    slots = patch_client._scan(data)
    assert len(slots) == 2
    assert all(p == 27017 or p == 27018 for _, _, _, p in slots)


def test_scan_ignores_local_service_ports(tmp_path):
    dylib = _fake_dylib(tmp_path, ["127.0.0.1:57343", "127.0.0.1:57344"])
    assert patch_client._scan(dylib.read_bytes()) == []


def test_patch_rewrites_all_slots(tmp_path):
    dylib = _fake_dylib(tmp_path, ["208.64.200.201:27017", "172.16.3.84:27018"])
    rc = patch_client.patch(dylib, "203.0.113.7", dry_run=False)
    assert rc == 0
    slots = patch_client._scan(dylib.read_bytes())
    assert {ip for _, _, ip, _ in slots} == {"203.0.113.7"}
    # backup was written once
    assert dylib.with_name(dylib.name + ".orig").is_file()


def test_patch_dry_run_does_not_modify(tmp_path):
    dylib = _fake_dylib(tmp_path, ["208.64.200.201:27017"])
    before = dylib.read_bytes()
    rc = patch_client.patch(dylib, "203.0.113.7", dry_run=True)
    assert rc == 0
    assert dylib.read_bytes() == before


def test_patch_skips_too_long_replacement(tmp_path, capsys):
    # original IP 172.16.3.84 (11 chars); a 15-char IP would overflow the slot
    # length for that entry; our target must fit. Use a max-length IPv4 to show
    # the skip path: original slot "172.16.3.84:27018" is 18 bytes; a 15-char IP
    # gives 21 bytes -> skipped.
    dylib = _fake_dylib(tmp_path, ["172.16.3.84:27018"])
    rc = patch_client.patch(dylib, "255.255.255.255", dry_run=False)
    assert rc == 0
    captured = capsys.readouterr().out
    assert "too long" in captured
    # nothing was overwritten
    assert dylib.read_bytes() == b"172.16.3.84:27018\0" + b"\0" * 64


def test_invalid_ip_rejected(tmp_path):
    dylib = _fake_dylib(tmp_path, ["208.64.200.201:27017"])
    rc = patch_client.patch(dylib, "not-an-ip", dry_run=False)
    assert rc == 2


def test_restore(tmp_path):
    dylib = _fake_dylib(tmp_path, ["208.64.200.201:27017"])
    patch_client.patch(dylib, "203.0.113.7", dry_run=False)
    assert patch_client._scan(dylib.read_bytes())[0][2] == "203.0.113.7"
    assert patch_client.restore(dylib) == 0
    assert patch_client._scan(dylib.read_bytes())[0][2] == "208.64.200.201"


def test_verify_single_ip(tmp_path, capsys):
    dylib = _fake_dylib(tmp_path, ["203.0.113.7:27017", "203.0.113.7:27018"])
    assert patch_client.verify(dylib) == 0
    assert "all 2 CM entries point at 203.0.113.7" in capsys.readouterr().out


def test_verify_mixed_returns_nonzero(tmp_path, capsys):
    # pristine / partially patched -> WARN + exit 1, so CI treats it as a gate
    dylib = _fake_dylib(tmp_path, ["208.64.200.201:27017", "203.0.113.7:27018"])
    assert patch_client.verify(dylib) == 1
    assert "WARN" in capsys.readouterr().out


def test_verify_expect_ok(tmp_path, capsys):
    dylib = _fake_dylib(tmp_path, ["203.0.113.7:27017", "203.0.113.7:27018"])
    assert patch_client.verify(dylib, expect="203.0.113.7") == 0
    assert "all 2 CM slots point at 203.0.113.7" in capsys.readouterr().out


def test_verify_expect_partial(tmp_path, capsys):
    dylib = _fake_dylib(tmp_path, ["203.0.113.7:27017", "208.64.200.201:27018"])
    assert patch_client.verify(dylib, expect="203.0.113.7") == 1
    assert "only 1/2 slots point at 203.0.113.7" in capsys.readouterr().out


def test_verify_expect_missing(tmp_path, capsys):
    dylib = _fake_dylib(tmp_path, ["208.64.200.201:27017"])
    assert patch_client.verify(dylib, expect="203.0.113.7") == 1
    assert "FAIL" in capsys.readouterr().out


def test_placeholder_endpoint_hint(tmp_path, capsys):
    # deploy/endpoint.txt placeholder must fail loudly through the CLI path,
    # not silently patch 0.0.0.0
    dylib = _fake_dylib(tmp_path, ["208.64.200.201:27017"])
    f = tmp_path / "endpoint.txt"
    f.write_text("NOT_DEPLOYED\n")
    rc = patch_client.main(["--dylib", str(dylib), "--endpoint-file", str(f)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "NOT_DEPLOYED" in err and "not be deployed" in err
    # file untouched
    assert dylib.read_bytes() == b"208.64.200.201:27017\0" + b"\0" * 64


def test_invalid_ip_via_flag_has_no_placeholder_hint(tmp_path, capsys):
    # a genuinely bad --ip must NOT blame deploy/endpoint.txt
    dylib = _fake_dylib(tmp_path, ["208.64.200.201:27017"])
    rc = patch_client.patch(dylib, "300.1.1.1", dry_run=False)
    assert rc == 2
    assert "placeholder" not in capsys.readouterr().err


def test_read_endpoint_file(tmp_path):
    f = tmp_path / "endpoint.txt"
    f.write_text("203.0.113.7\n")
    assert patch_client.read_endpoint_file(f) == "203.0.113.7"

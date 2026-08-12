#!/usr/bin/env python3
"""Dump the complete EMsg name->value table from the client binaries.

Walks {u32 value, u32 name_ptr} entry windows in both osx32/steam and
steamclient.dylib, resolves each pointer to a k_EMsg* name, and writes a
sorted value->name listing to a file (default emsg_table.txt).
"""
import struct
import sys


def cstr(data, off):
    end = data.find(b"\x00", off)
    if end < 0:
        return ""
    try:
        return data[off:end].decode("latin1")
    except Exception:
        return ""


def find_tables(data, start, end):
    """Yield {value: set(names)} for every plausible {u32,u32} pair."""
    results = {}
    for off in range(start, end - 8, 4):
        v, p = struct.unpack_from("<II", data, off)
        if p < 0x100000 or p > len(data) - 4:
            continue
        name = cstr(data, p)
        if name.startswith("k_EMsg") and len(name) < 80:
            results.setdefault(v, set()).add(name)
    return results


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "/tmp/emsg_table.txt"
    paths = {
        "osx32/steam": [(0x1A0000, 0x1C8000)],
        # steamclient.dylib has a second copy of the table around 0x26bxxxx
        "steamclient.dylib": [(0xBD0000, 0xC20000), (0x26A0000, 0x26E0000)],
    }
    base = "client/Steam.app/Contents/MacOS/"
    merged = {}
    for rel, windows in paths.items():
        try:
            data = open(base + rel, "rb").read()
        except OSError:
            print(f"MISSING {rel}")
            continue
        for (s, e) in windows:
            t = find_tables(data, s, e)
            for v, names in t.items():
                merged.setdefault(v, set()).update(names)
    with open(out, "w") as fh:
        for v in sorted(merged):
            fh.write(f"{v:6d} -> {sorted(merged[v])}\n")
    print(f"wrote {len(merged)} entries to {out}")
    for v in sorted(merged):
        print(f"{v:6d} -> {sorted(merged[v])}")


if __name__ == "__main__":
    main()

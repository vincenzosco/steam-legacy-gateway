#!/usr/bin/env python3
"""Extract protobuf field numbers from SteamKit's generated C#.

Each field carries an attribute line like:

    [global::ProtoBuf.ProtoMember(1, IsRequired = false, Name=@"protocol_version", ...)]

We locate each CMsg class body and list field_number -> proto_name for the
classes we care about.
"""
import re
import sys

CLASSES = [
    "CMsgClientLogon",
    "CMsgClientLogonResponse",
    "CMsgClientSessionToken",
    "CMsgClientAccountInfo",
    "CMsgClientHeartBeat",
    "CMsgClientNewLoginKey",
    "CMsgClientNewLoginKeyAccepted",
    "CMsgClientUpdateMachineAuth",
    "CMsgClientUpdateMachineAuthResponse",
    "CMsgClientReadMachineAuth",
    "CMsgClientReadMachineAuthResponse",
    "CMsgClientRequestMachineAuth",
    "CMsgClientRequestMachineAuthResponse",
    "CMsgClientLoggedOff",
    "CMsgClientCMList",
    "CMsgProtoBufHeader",
    "CMsgMulti",
]

attr_re = re.compile(
    r"ProtoMember\((\d+),\s*IsRequired = \w+,\s*Name=@\"([^\"]+)\""
)
class_re = re.compile(r"public partial class (CMsg\w+)\s*:\s*global::ProtoBuf\.IExtensible")


def parse_file(path):
    src = open(path, "r", encoding="utf-8", errors="replace").read()
    out = {}
    for m in class_re.finditer(src):
        name = m.group(1)
        if name not in CLASSES:
            continue
        body = src[m.end():]
        depth = 0
        for i, ch in enumerate(body):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    body = body[:i]
                    break
        fields = {}
        for am in attr_re.finditer(body):
            fields[int(am.group(1))] = am.group(2)
        out[name] = fields
    return out


def main():
    files = sys.argv[1:] or ["/tmp/msgcs.cs", "/tmp/msgcs2.cs"]
    merged = {}
    for f in files:
        try:
            parsed = parse_file(f)
        except OSError:
            continue
        for name, fields in parsed.items():
            merged.setdefault(name, {}).update(fields)
    for name in CLASSES:
        if name in merged:
            print(f"== {name}")
            for num in sorted(merged[name]):
                print(f"    {num}: {merged[name][num]}")


if __name__ == "__main__":
    main()

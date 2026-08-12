#!/usr/bin/env python3
# client_sim.py — act as the Lion-era Steam client against the gateway.
#
# Usage (with the gateway running on the same machine):
#   python3 -m gateway run --cm-only            # terminal 1: the gateway (no root needed)
#   python3 scripts/client_sim.py --out captures/handshake.txt   # terminal 2: the client
#
# The simulator speaks the same protocol as the Oct-2015 client
# (server-initiated channel encrypt + protobuf logon) and dumps every byte.
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gateway.cm.sim_client import main as sim_main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(sim_main())

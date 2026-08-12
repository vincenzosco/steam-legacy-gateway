"""CLI entrypoint.

    python -m gateway                       run all services
    python -m gateway gen-certs             create the local CA + leaf bundle
    python -m gateway hosts [--ip X]        print the /etc/hosts block for Lion
    python -m gateway hosts --apply --ip X --file /etc/hosts
                                            install the block (run as root)
    python -m gateway hosts --remove --file /etc/hosts
                                            remove the block
    python -m gateway routes                print the routing table
    python -m gateway smoke-tls             run only the TLS forwarder (for tests)
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
from pathlib import Path

from gateway import config as confmod
from gateway import hosts as hosts_mod
from gateway import routes as routes_mod

log = logging.getLogger("gateway.main")


def _logging_setup(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )


async def _run_services(cfg: dict, *, run_cm: bool, run_content: bool) -> None:
    from gateway.cm.server import run_cm_server
    from gateway.content.bridge import ContentBridge
    from gateway.content.cache import ChunkCache
    from gateway.content.fetcher import Fetcher
    from gateway.minihttp import serve as serve_http
    from gateway.tls_proxy import run_tls_proxy

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass

    cache = ChunkCache(cfg["content"]["cache_dir"])
    fetcher = Fetcher(cfg, cache)
    bridge = ContentBridge(cfg, cache, fetcher)

    servers: list = []
    if run_content:
        servers.append(await serve_http("127.0.0.1", cfg["content"]["listen_port"], bridge.handle))
        asyncio.create_task(bridge.warm_preload())
        log.info("content origin on 127.0.0.1:%s", cfg["content"]["listen_port"])

    # Modern session first: the CM translator needs it.
    from gateway.auth.bridge import credentials_from_config
    from gateway.cm.modern import ModernSession

    creds = credentials_from_config(cfg)
    modern = None
    if creds is not None:
        modern = ModernSession(creds, cfg["cm"].get("modern_cm_host", ""))
        try:
            await modern.start()
        except Exception as exc:
            log.error("modern session failed to start: %s", exc)
            modern = None
    else:
        log.warning("No account configured — CM translator will refuse logons. "
                    "Set account.* in config/gateway.local.yaml")

    servers.extend(await run_tls_proxy(cfg, stop))
    if run_cm:
        if modern is None:
            log.warning("--no-modern (no account) but CM listener requested; "
                        "starting it anyway (logons will fail).")
        servers.extend(await run_cm_server(cfg, modern, stop) if modern else [])

    log.info("gateway ready. Point the Lion machine's hosts file at %s",
             cfg.get("gateway_ip", "?"))

    await stop.wait()
    log.info("shutting down ...")
    for server in servers:
        server.close()
    await asyncio.gather(*(s.wait_closed() for s in servers), return_exceptions=True)
    if modern:
        await modern.stop()


def _cmd_hosts(args: argparse.Namespace) -> int:
    cfg = confmod.load_config()
    ip = args.ip or cfg.get("gateway_ip", "")
    if args.apply:
        path = Path(args.file)
        if not ip:
            print("--apply requires --ip (or gateway_ip in config)", file=sys.stderr)
            return 2
        orig = path.read_text(encoding="utf-8") if path.is_file() else ""
        stripped = hosts_mod.strip_block(orig)
        path.write_text(stripped.rstrip() + "\n" + hosts_mod.render(ip), encoding="utf-8")
        print(f"hosts block installed into {path} (make a backup first if needed)")
        return 0
    if args.remove:
        path = Path(args.file)
        if not path.is_file():
            print(f"no such file: {path}", file=sys.stderr)
            return 2
        path.write_text(hosts_mod.strip_block(path.read_text(encoding="utf-8")),
                        encoding="utf-8")
        print(f"hosts block removed from {path}")
        return 0
    print(hosts_mod.render(ip))
    return 0


def _cmd_routes() -> int:
    for host in sorted(routes_mod.FORWARD_HOSTS):
        print(f"forward  {host} -> {routes_mod.FORWARD_HOSTS[host]}")
    for host in sorted(routes_mod.LOCAL_ORIGIN_HOSTS):
        print(f"local    {host} -> content origin")
    for host in routes_mod.CM_HOSTNAMES:
        print(f"cm       {host} -> CM listener (TCP 27017-27020)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="gateway", description=__doc__)
    parser.add_argument("--config", help="path to a YAML config file")
    sub = parser.add_subparsers(dest="command")

    p_run = sub.add_parser("run")
    p_run.add_argument("--no-cm", action="store_true", help="skip CM listener")
    p_run.add_argument("--no-content", action="store_true", help="skip content origin")

    sub.add_parser("gen-certs")

    p_hosts = sub.add_parser("hosts", help="render/install the /etc/hosts block")
    p_hosts.add_argument("--ip", help="gateway IP to route to")
    p_hosts.add_argument("--apply", action="store_true", help="install into a hosts file")
    p_hosts.add_argument("--remove", action="store_true", help="remove from a hosts file")
    p_hosts.add_argument("--file", default="/etc/hosts", help="hosts file to edit")

    sub.add_parser("routes", help="print the routing table")

    p_smoke = sub.add_parser("smoke-tls", help="run only the TLS forwarder (for testing)")
    p_smoke.add_argument("--port", type=int, default=8443)
    p_smoke.add_argument("--plain-port", type=int, default=8080)

    args = parser.parse_args(argv)
    cmd = args.command or "run"
    cfg = confmod.env_override(confmod.load_config(args.config))
    _logging_setup(cfg.get("log_level", "INFO"))

    if cmd == "gen-certs":
        from gateway.certs import ensure_bundle_cert, ensure_ca

        cert_dir = Path(cfg["tls"]["cert_dir"])
        ca_cert, _ = ensure_ca(cert_dir)
        leaf, _ = ensure_bundle_cert(cert_dir)
        print(f"CA cert:    {ca_cert}   <- install & trust this on the Lion machine")
        print(f"Leaf cert:  {leaf}")
        return 0

    if cmd == "hosts":
        return _cmd_hosts(args)

    if cmd == "routes":
        return _cmd_routes()

    if cmd == "smoke-tls":
        cfg["tls"]["listen_port"] = args.port
        cfg["tls"]["plain_port"] = args.plain_port

        async def _smoke() -> None:
            from gateway.content.bridge import ContentBridge
            from gateway.content.cache import ChunkCache
            from gateway.content.fetcher import Fetcher
            from gateway.minihttp import serve as serve_http
            from gateway.tls_proxy import run_tls_proxy

            stop = asyncio.Event()
            cache = ChunkCache(cfg["content"]["cache_dir"])
            bridge = ContentBridge(cfg, cache, Fetcher(cfg, cache))
            origin = await serve_http(
                "127.0.0.1", cfg["content"]["listen_port"], bridge.handle
            )
            servers = await run_tls_proxy(cfg, stop)
            await stop.wait()
            origin.close()
            await origin.wait_closed()

        return asyncio.run(_smoke())

    return asyncio.run(_run_services(cfg, run_cm=not args.no_cm,
                                     run_content=not args.no_content))


if __name__ == "__main__":
    raise SystemExit(main())

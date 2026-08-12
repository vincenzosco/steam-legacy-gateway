"""Modern back-end: one modern Steam session owned by the gateway.

ValvePython/steam is built on gevent, so it cannot live inside the asyncio
event loop. We run it in a dedicated thread and bridge events back over an
asyncio queue using `call_soon_threadsafe`. If the `steam` package is missing,
the session fails fast with a clear message (the rest of the gateway still runs).
"""
from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any

from gateway.auth.bridge import Credentials, resolve_guard_code

log = logging.getLogger("gateway.cm.modern")


class ModernSession:
    """Represents one authenticated modern session with Valve's CM network."""

    def __init__(self, credentials: Credentials, modern_cm_host: str = ""):
        self.credentials = resolve_guard_code(credentials)
        self.modern_cm_host = modern_cm_host
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._ready: asyncio.Future | None = None
        self._events: asyncio.Queue | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._client = None  # SteamClient instance (gevent thread)

    # -- public async API ------------------------------------------------------

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._ready = self._loop.create_future()
        self._events = asyncio.Queue()
        self._thread = threading.Thread(target=self._run, name="modern-steam", daemon=True)
        self._thread.start()
        await self._ready
        log.info("modern session ready (%s)", self.credentials.username)

    async def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    async def events(self):
        assert self._events is not None
        return await self._events.get()

    def client(self):
        """The raw SteamClient (only callable from the gevent thread context)."""
        return self._client

    def is_ready(self) -> bool:
        """True when the modern login completed successfully (not failed)."""
        return bool(self._ready) and self._ready.done() and self._ready.exception() is None

    # -- gevent-thread internals -----------------------------------------------

    def _emit(self, event: dict[str, Any]) -> None:
        loop, q = self._loop, self._events
        if loop and q:
            loop.call_soon_threadsafe(q.put_nowait, event)

    def _resolve_ready(self) -> None:
        loop, fut = self._loop, self._ready
        if loop and fut and not fut.done():
            loop.call_soon_threadsafe(fut.set_result, True)

    def _fail(self, message: str) -> None:
        log.error("modern session failed: %s", message)
        self._emit({"type": "error", "error": message})
        loop, fut = self._loop, self._ready
        if loop and fut and not fut.done():
            loop.call_soon_threadsafe(fut.set_exception, RuntimeError(message))

    def _run(self) -> None:
        try:
            from steam import SteamClient
        except ImportError as exc:
            self._fail(f"ValvePython 'steam' package not installed "
                       f"(pip install steam): {exc}")
            return

        client = SteamClient()
        self._client = client

        client.on("logged_on", self._on_logged_on)
        client.on("error", self._on_error)
        client.on("disconnect", self._on_disconnect)
        if self.modern_cm_host:
            client.set_server_list([(self.modern_cm_host, 27017)])

        try:
            log.info("modern login as %s ...", self.credentials.username)
            client.login(
                self.credentials.username,
                self.credentials.password,
                two_factor_code=self.credentials.two_factor_code,
            )
        except Exception as exc:  # gevent greenlet may raise inside login
            self._fail(f"login raised: {exc}")

        # Keep the thread alive so greenlets keep running until told to stop.
        import time

        while not self._stop.wait(0.25):
            time.sleep(0.25)

        try:
            client.disconnect()
        except Exception:
            pass

    def _on_logged_on(self) -> None:
        log.info("modern logged_on")
        self._emit({"type": "logged_on"})
        self._resolve_ready()

    def _on_error(self, error: Exception) -> None:
        self._emit({"type": "error", "error": str(error)})

    def _on_disconnect(self, reason: str) -> None:
        self._emit({"type": "disconnect", "reason": str(reason)})

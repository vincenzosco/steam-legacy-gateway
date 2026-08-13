"""Modern back-end: modern Steam sessions owned by the gateway.

One ModernSession per account (see ModernFactory): each runs ValvePython/steam
in its own dedicated thread, so several different users on several Lion
machines can share one bridge. Events are bridged back over an asyncio queue
using `call_soon_threadsafe`. If the `steam` package is missing, a session
fails fast with a clear message (the rest of the gateway still runs).
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
        self._thread = threading.Thread(
            target=self._run,
            name=f"modern-steam-{self.credentials.username}",
            daemon=True,
        )
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

    def steam_id(self) -> int:
        """The modern session's SteamID as a 64-bit int, or 0 if unknown.

        Safe to call from any thread (plain attribute read of the SteamClient
        set by the gevent thread).
        """
        client = self._client
        if client is None:
            return 0
        sid = getattr(client, "steam_id", None)
        if sid is None:
            return 0
        try:
            return int(sid)  # SteamID has __int__ / as_64
        except (TypeError, ValueError):
            return 0

    async def wait_ready(self, timeout: float = 90.0) -> bool:
        """Wait for the modern login to complete (success or failure)."""
        fut = self._ready
        if fut is None:
            return False
        try:
            await asyncio.wait_for(asyncio.shield(fut), timeout=timeout)
            return True
        except (asyncio.TimeoutError, RuntimeError):
            return False

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
        log.info("modern logged_on (%s)", self.credentials.username)
        self._emit({"type": "logged_on"})
        self._resolve_ready()


class ModernFactory:
    """Builds modern sessions lazily, from legacy client credentials.

    This is the 'credentials from the client's login screen' path: a legacy
    ClientLogon reaches the bridge with a username/password (decrypted via the
    swapped CM key) and the modern session for that account logs in with
    exactly those — no credentials in config/gateway.local.yaml.

    One session per distinct account: the first logon for a username creates
    (and logs in) that account's session; later logons for the same username
    reuse it. Different usernames get different sessions, each in its own
    thread — so several users can share one bridge. A failed login is never
    cached, so the next attempt retries.

    If the operator configured account.* (or env vars) at boot, `preset` is
    that pre-started session and every connection rides on it (single-account
    mode — the translator refuses logons for any other account).
    """

    def __init__(self, cfg: dict, modern_cm_host: str = "",
                 preset: ModernSession | None = None):
        self.cfg = cfg
        self.modern_cm_host = modern_cm_host
        self.preset = preset
        self._sessions: dict[str, ModernSession] = {}
        self._lock = asyncio.Lock()

    async def get(self, credentials: Credentials) -> ModernSession | None:
        """Return the modern session for these credentials, logging in on first use.

        Sessions are keyed by username: the same account always gets the same
        session (so two machines on one account share a single modern login);
        different accounts get independent sessions.
        """
        if self.preset is not None:
            return self.preset
        async with self._lock:
            session = self._sessions.get(credentials.username)
            if session is not None:
                return session
            session = ModernSession(credentials, self.modern_cm_host)
            try:
                await session.start()
            except Exception as exc:
                log.error("modern login failed for %r: %s",
                          credentials.username, exc)
                return None
            self._sessions[credentials.username] = session
            return session

    async def close(self) -> None:
        """Stop the preset and every pooled modern session."""
        sessions: list[ModernSession] = []
        if self.preset is not None:
            sessions.append(self.preset)
        async with self._lock:
            sessions.extend(self._sessions.values())
        for session in sessions:
            try:
                await session.stop()
            except Exception as exc:
                log.warning("error stopping modern session: %s", exc)

    def _on_error(self, error: Exception) -> None:
        self._emit({"type": "error", "error": str(error)})

    def _on_disconnect(self, reason: str) -> None:
        self._emit({"type": "disconnect", "reason": str(reason)})

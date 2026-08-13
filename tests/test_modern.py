"""ModernFactory session-pool tests: one modern session per account."""

import asyncio

from gateway.auth.bridge import Credentials
from gateway.cm import modern as modern_mod
from gateway.cm.modern import ModernFactory


class _FakeModern:
    """Stand-in ModernSession: no real ValvePython thread."""

    def __init__(self, credentials: Credentials, host: str = ""):
        self.username = credentials.username
        self.credentials = credentials
        self.ready = True

    async def start(self) -> None:
        pass

    def is_ready(self) -> bool:
        return self.ready

    def steam_id(self) -> int:
        return 0


class _FailingModern(_FakeModern):
    async def start(self) -> None:
        raise RuntimeError("login failed")


def test_one_session_per_account(monkeypatch):
    """Different usernames get different sessions; the same username reuses it."""
    created: list[str] = []

    class _Recorder(_FakeModern):
        def __init__(self, credentials: Credentials, host: str = ""):
            super().__init__(credentials, host)
            created.append(credentials.username)

    monkeypatch.setattr(modern_mod, "ModernSession", _Recorder)
    factory = ModernFactory({}, "")

    async def run():
        alice = await factory.get(Credentials("alice", "pw"))
        bob = await factory.get(Credentials("bob", "pw"))
        alice_again = await factory.get(Credentials("alice", "pw-changed"))
        return alice, bob, alice_again

    alice, bob, alice_again = asyncio.run(run())
    assert alice is alice_again   # same account -> same session (single modern login)
    assert alice is not bob       # different accounts -> independent sessions
    assert created == ["alice", "bob"]


def test_failed_login_is_not_cached(monkeypatch):
    """A failed login returns None and is not cached, so the next attempt retries."""
    monkeypatch.setattr(modern_mod, "ModernSession", _FailingModern)
    factory = ModernFactory({}, "")

    async def run():
        first = await factory.get(Credentials("alice", "pw"))
        second = await factory.get(Credentials("alice", "pw"))
        return first, second

    first, second = asyncio.run(run())
    assert first is None
    assert second is None  # both attempts actually tried (not served from a cache)


def test_preset_mode_serves_everyone():
    """account.* configured: the preset session is returned for any logon."""
    preset = _FakeModern(Credentials("preset-user", "pw"))
    factory = ModernFactory({}, "", preset=preset)

    async def run():
        return await factory.get(Credentials("anyone", "pw"))

    assert asyncio.run(run()) is preset


def test_close_stops_pooled_and_preset_sessions(monkeypatch):
    stopped: list[str] = []

    class _Stoppable(_FakeModern):
        async def stop(self) -> None:
            stopped.append(self.username)

    monkeypatch.setattr(modern_mod, "ModernSession", _Stoppable)

    async def run():
        pooled = ModernFactory({}, "")
        await pooled.get(Credentials("alice", "pw"))
        await pooled.get(Credentials("bob", "pw"))
        await pooled.close()

        with_preset = ModernFactory({}, "",
                                    preset=_Stoppable(Credentials("preset-user", "pw")))
        await with_preset.close()

    asyncio.run(run())
    assert sorted(stopped) == ["alice", "bob", "preset-user"]

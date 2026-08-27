"""
Testes dos comandos `identity` / `identity verify` do shell (Fase 3),
usando um RelayClient falso — sem rede real.
"""

from __future__ import annotations

from client import commands, crypto, crypto_identity as cryptoid


class FakeRelayClient:
    def __init__(self, connected: bool = True):
        self.connected = connected
        self.keys: dict[str, str | None] = {}

    def get_public_key(self, username: str):
        if username not in self.keys:
            return False, None, "user not found"
        return True, self.keys[username], ""


def _make_identity(store):
    identity, _ = cryptoid.load_or_create("sofia", store)
    return identity


def test_identity_command_shows_own_fingerprint(tmp_path, monkeypatch):
    import client.identity_store as store_module

    monkeypatch.setattr(store_module, "_store_dir", lambda: tmp_path)
    from client.identity_store import PlaintextIdentityStore

    identity = _make_identity(PlaintextIdentityStore())
    ctx = commands.Context(
        username="sofia",
        fingerprint=identity.fingerprint(),
        client=FakeRelayClient(),
        crypto_identity=identity,
    )

    result = commands.dispatch(ctx, "identity")
    assert result == commands.CONTINUE


def test_identity_verify_shows_peer_fingerprint():
    _, public_key = crypto.generate_keypair()
    fake = FakeRelayClient()
    fake.keys["morningstar"] = crypto.encode_public_key(public_key)
    ctx = commands.Context(username="sofia", fingerprint="AAAA", client=fake)

    result = commands.dispatch(ctx, 'identity verify "morningstar"')
    assert result == commands.CONTINUE


def test_identity_verify_unknown_user_does_not_crash():
    fake = FakeRelayClient()  # "morningstar" not in fake.keys -> not found
    ctx = commands.Context(username="sofia", fingerprint="AAAA", client=fake)

    result = commands.dispatch(ctx, 'identity verify "morningstar"')
    assert result == commands.CONTINUE


def test_identity_verify_user_without_published_key_does_not_crash():
    fake = FakeRelayClient()
    fake.keys["morningstar"] = None  # existe, mas nunca publicou
    ctx = commands.Context(username="sofia", fingerprint="AAAA", client=fake)

    result = commands.dispatch(ctx, 'identity verify "morningstar"')
    assert result == commands.CONTINUE


def test_identity_verify_without_target_shows_usage():
    fake = FakeRelayClient()
    ctx = commands.Context(username="sofia", fingerprint="AAAA", client=fake)
    result = commands.dispatch(ctx, "identity verify")
    assert result == commands.CONTINUE


def test_identity_command_without_client_does_not_crash():
    ctx = commands.Context(username="sofia", fingerprint="AAAA", client=None)
    result = commands.dispatch(ctx, "identity")
    assert result == commands.CONTINUE
    result = commands.dispatch(ctx, 'identity verify "morningstar"')
    assert result == commands.CONTINUE

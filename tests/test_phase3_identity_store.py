"""
Testes de client/identity_store.py — o armazenamento local da chave
privada. Roda o backend Windows real quando disponível (esta suíte é
desenvolvida e executada em Windows) e sempre roda o fallback
multiplataforma.
"""

from __future__ import annotations

import sys

import pytest

from client.identity_store import (
    PlaintextIdentityStore,
    WindowsIdentityStore,
    get_default_store,
)


@pytest.fixture()
def plaintext_store(tmp_path, monkeypatch):
    import client.identity_store as store_module

    monkeypatch.setattr(store_module, "_store_dir", lambda: tmp_path)
    return PlaintextIdentityStore()


def test_plaintext_store_round_trip(plaintext_store):
    secret = b"\x01" * 32
    plaintext_store.save("morningstar", secret)
    assert plaintext_store.exists("morningstar") is True
    assert plaintext_store.load("morningstar") == secret


def test_plaintext_store_missing_identity_returns_none(plaintext_store):
    assert plaintext_store.load("nobody") is None
    assert plaintext_store.exists("nobody") is False


def test_plaintext_store_isolates_by_username(plaintext_store):
    plaintext_store.save("morningstar", b"\x01" * 32)
    plaintext_store.save("sofia", b"\x02" * 32)
    assert plaintext_store.load("morningstar") != plaintext_store.load("sofia")


def test_default_store_picks_a_backend():
    store = get_default_store()
    assert store.backend_name in ("windows-dpapi", "plaintext-file")


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI só existe no Windows")
def test_windows_dpapi_round_trip(tmp_path, monkeypatch):
    import client.identity_store as store_module

    monkeypatch.setattr(store_module, "_store_dir", lambda: tmp_path)
    win_store = WindowsIdentityStore()

    secret = b"\x42" * 32
    win_store.save("morningstar", secret)
    assert win_store.load("morningstar") == secret


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI só existe no Windows")
def test_windows_dpapi_blob_on_disk_is_not_plaintext(tmp_path, monkeypatch):
    """A chave privada em disco não pode ser os bytes crus — precisa estar
    protegida pelo DPAPI."""
    import client.identity_store as store_module

    monkeypatch.setattr(store_module, "_store_dir", lambda: tmp_path)
    win_store = WindowsIdentityStore()

    secret = b"\x99" * 32
    win_store.save("morningstar", secret)

    raw_on_disk = (tmp_path / "ed25519_morningstar.key").read_bytes()
    assert raw_on_disk != secret
    assert secret not in raw_on_disk

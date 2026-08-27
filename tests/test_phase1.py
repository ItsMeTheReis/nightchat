"""
Testes da Fase 1 — rodam sem terminal interativo e sem dependências externas.
    python -m pytest tests/         (se pytest instalado)
    python tests/test_phase1.py     (runner embutido, sem pytest)
"""

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client import identity, commands, presence  # noqa: E402


def _isolate_store(tmp: Path):
    """Redireciona o store de credenciais para um diretório temporário."""
    identity._store_dir = lambda: tmp  # type: ignore
    identity._store_file = lambda: tmp / "credentials.json"  # type: ignore


def test_account_create_and_verify():
    with tempfile.TemporaryDirectory() as d:
        _isolate_store(Path(d))
        assert identity.store_exists() is False
        ident = identity.create_account("morningstar", "s3nh4-forte")
        assert ident.username == "morningstar"
        assert identity.store_exists() is True
        # senha correta -> retorna identity
        ok = identity.verify_password("s3nh4-forte")
        assert ok is not None and ok.username == "morningstar"
        # senha errada -> None
        assert identity.verify_password("errada") is None


def test_password_not_stored_plaintext():
    with tempfile.TemporaryDirectory() as d:
        _isolate_store(Path(d))
        identity.create_account("morningstar", "supersecreta123")
        raw = (Path(d) / "credentials.json").read_text()
        assert "supersecreta123" not in raw
        assert "verifier" in raw and "salt" in raw


def test_fingerprint_stable_and_formatted():
    ident = identity.Identity("morningstar", "a" * 32)
    fp1 = ident.fingerprint()
    fp2 = ident.fingerprint()
    assert fp1 == fp2                      # determinístico
    assert " " in fp1                      # formatado em blocos
    assert all(len(b) == 4 for b in fp1.split())


def test_connect_target_parsing():
    p = commands._parse_connect_target
    assert p('connect to user "sofia"') == "sofia"
    assert p('/connect to user sofia') == "sofia"
    assert p('/connect sofia') == "sofia"
    assert p('connect to user "elliot_1"') == "elliot_1"
    assert p('garbage') is None


def test_dispatch_known_and_unknown(capsys=None):
    ctx = commands.Context(username="morningstar", fingerprint="AAAA BBBB")
    assert commands.dispatch(ctx, "/help") == commands.CONTINUE
    assert commands.dispatch(ctx, "/status") == commands.CONTINUE
    assert commands.dispatch(ctx, "/users") == commands.CONTINUE
    assert commands.dispatch(ctx, "/fingerprint") == commands.CONTINUE
    assert commands.dispatch(ctx, "comando_inexistente") == commands.CONTINUE
    assert commands.dispatch(ctx, "/exit") == commands.EXIT
    assert commands.dispatch(ctx, "") == commands.CONTINUE


def test_presence_without_relay_is_empty():
    # A partir da Fase 2, presence.py consulta o relay de verdade; sem um
    # RelayClient conectado (presence.set_client não foi chamado), a lista
    # é vazia — não há mais dados mockados (ver tests/test_phase2_client.py).
    presence._client = None
    assert presence.online_users(exclude="sofia") == []
    assert presence.is_mock() is True


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_")]
    passed = 0
    for fn in fns:
        fn()
        print(f"  [ok] {fn.__name__}")
        passed += 1
    print(f"\n{passed}/{len(fns)} testes passaram.")


if __name__ == "__main__":
    _run_all()

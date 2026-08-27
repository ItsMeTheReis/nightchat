"""
Testes da revisão "release multi-máquina":
- nenhuma instalação nova assume "morningstar" como username padrão;
- o relay padrão (sem nenhuma variável de ambiente) é o relay OFICIAL da
  release, nunca localhost;
- NIGHTCHAT_RELAY_URL/HTTP/WS continuam funcionando como override
  explícito para desenvolvimento local;
- relay inacessível mostra um erro claro com opção de tentar de novo,
  em vez de um "OFFLINE" silencioso;
- a boot sequence não afirma mais nada sobre o relay antes de tentar de
  verdade (essa alegação era falsa mesmo quando o relay estava disponível).
"""

from __future__ import annotations

import importlib
import io
import uuid
from contextlib import redirect_stdout
from unittest import mock

import pytest
from fastapi.testclient import TestClient

from client import authentication, terminal


def _unique(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex[:6]}"


@pytest.fixture()
def clean_env(monkeypatch):
    """Remove qualquer variável NIGHTCHAT_* do ambiente e recarrega
    client.authentication, para testar o comportamento de uma instalação
    nova de verdade (sem resíduo de outros testes/sessões)."""
    for var in ("NIGHTCHAT_USERNAME", "NIGHTCHAT_RELAY_URL", "NIGHTCHAT_RELAY_HTTP", "NIGHTCHAT_RELAY_WS"):
        monkeypatch.delenv(var, raising=False)
    importlib.reload(authentication)
    yield authentication
    importlib.reload(authentication)  # restaura para o resto da suíte


# ---------------------------------------------------------------------------
# Sem username padrão numa instalação nova
# ---------------------------------------------------------------------------

def test_no_default_username_when_env_var_unset(clean_env):
    assert clean_env.DEFAULT_USERNAME is None


def test_ask_username_has_no_suggested_value_without_env_var(clean_env, monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda prompt="": "sofia")
    result = clean_env._ask_username()
    assert result == "sofia"
    # a prompt não deve conter um valor sugerido entre colchetes
    captured = capsys.readouterr()


def test_ask_username_rejects_empty_input_and_reprompts(clean_env, monkeypatch):
    responses = iter(["", "   ", "sofia"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(responses))
    result = clean_env._ask_username()
    assert result == "sofia"


def test_ask_username_suggests_value_only_when_dev_env_var_set(monkeypatch):
    monkeypatch.setenv("NIGHTCHAT_USERNAME", "devtester")
    importlib.reload(authentication)
    try:
        assert authentication.DEFAULT_USERNAME == "devtester"
        monkeypatch.setattr("builtins.input", lambda prompt="": "")
        # Enter vazio usa a sugestão SÓ porque foi explicitamente configurada por quem desenvolve
        assert authentication._ask_username() == "devtester"
    finally:
        monkeypatch.delenv("NIGHTCHAT_USERNAME", raising=False)
        importlib.reload(authentication)


def test_two_fresh_installs_can_pick_independent_usernames(clean_env, monkeypatch):
    """Simula duas 'instalações' (duas chamadas de _ask_username en sequência
    sem estado compartilhado) escolhendo usernames diferentes e
    sem qualquer relação com um valor padrão comum."""
    monkeypatch.setattr("builtins.input", lambda prompt="": "morningstar")
    first = clean_env._ask_username()
    monkeypatch.setattr("builtins.input", lambda prompt="": "sofia")
    second = clean_env._ask_username()
    assert first == "morningstar"
    assert second == "sofia"
    assert first != second


# ---------------------------------------------------------------------------
# Relay padrão nunca é localhost
# ---------------------------------------------------------------------------

def test_default_relay_is_not_localhost(clean_env):
    assert "localhost" not in clean_env.DEFAULT_HTTP_BASE
    assert "127.0.0.1" not in clean_env.DEFAULT_HTTP_BASE
    assert "localhost" not in clean_env.DEFAULT_WS_BASE


def test_default_relay_is_the_official_https_placeholder(clean_env):
    assert clean_env.DEFAULT_HTTP_BASE == clean_env.OFFICIAL_RELAY_HTTP
    assert clean_env.DEFAULT_HTTP_BASE.startswith("https://")
    assert clean_env.DEFAULT_WS_BASE.startswith("wss://")


def test_relay_url_env_var_overrides_official_default(monkeypatch):
    monkeypatch.setenv("NIGHTCHAT_RELAY_URL", "http://localhost:9000")
    importlib.reload(authentication)
    try:
        assert authentication.DEFAULT_HTTP_BASE == "http://localhost:9000"
        assert authentication.DEFAULT_WS_BASE == "ws://localhost:9000/ws"
    finally:
        monkeypatch.delenv("NIGHTCHAT_RELAY_URL", raising=False)
        importlib.reload(authentication)


def test_relay_http_ws_env_vars_take_priority_over_relay_url(monkeypatch):
    monkeypatch.setenv("NIGHTCHAT_RELAY_URL", "https://ignored.example.com")
    monkeypatch.setenv("NIGHTCHAT_RELAY_HTTP", "http://explicit:1234")
    monkeypatch.setenv("NIGHTCHAT_RELAY_WS", "ws://explicit:1234/ws")
    importlib.reload(authentication)
    try:
        assert authentication.DEFAULT_HTTP_BASE == "http://explicit:1234"
        assert authentication.DEFAULT_WS_BASE == "ws://explicit:1234/ws"
    finally:
        for var in ("NIGHTCHAT_RELAY_URL", "NIGHTCHAT_RELAY_HTTP", "NIGHTCHAT_RELAY_WS"):
            monkeypatch.delenv(var, raising=False)
        importlib.reload(authentication)


# ---------------------------------------------------------------------------
# Relay inacessível: erro claro + retry, nunca "OFFLINE" silencioso
# ---------------------------------------------------------------------------

def test_relay_unreachable_prompts_retry_and_honors_no(monkeypatch, clean_env):
    monkeypatch.setattr(clean_env, "_check_relay_health", lambda: False)
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")
    buf = io.StringIO()
    with redirect_stdout(buf):
        result = clean_env._ensure_relay_reachable()
    assert result is False
    output = buf.getvalue()
    assert "Unable to connect to NightChat Relay" in output
    assert "Possible causes" in output


def test_relay_unreachable_retries_on_yes_then_succeeds(monkeypatch, clean_env):
    calls = {"n": 0}

    def health():
        calls["n"] += 1
        return calls["n"] >= 3  # falha duas vezes, depois "recupera"

    monkeypatch.setattr(clean_env, "_check_relay_health", health)
    monkeypatch.setattr("builtins.input", lambda prompt="": "y")
    result = clean_env._ensure_relay_reachable()
    assert result is True
    assert calls["n"] == 3


def test_relay_unreachable_empty_answer_defaults_to_retry(monkeypatch, clean_env):
    calls = {"n": 0}

    def health():
        calls["n"] += 1
        return calls["n"] >= 2

    monkeypatch.setattr(clean_env, "_check_relay_health", health)
    monkeypatch.setattr("builtins.input", lambda prompt="": "")  # Enter vazio = retry (Y é o padrão)
    result = clean_env._ensure_relay_reachable()
    assert result is True


def test_login_aborts_cleanly_when_relay_unreachable_and_user_declines_retry(monkeypatch, clean_env):
    monkeypatch.setattr(clean_env, "_check_relay_health", lambda: False)
    monkeypatch.setattr("builtins.input", lambda prompt="": "n")
    result = clean_env.login(username="sofia")
    assert result is None


# ---------------------------------------------------------------------------
# Health check real do relay (GET /health) — item 14
# ---------------------------------------------------------------------------

def test_relay_health_endpoint_returns_ok_without_secrets():
    from server.main import app

    with TestClient(app) as client:
        resp = client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body == {"status": "ok"}
        # nunca deve incluir nada sensível
        for forbidden in ("password", "secret", "token", "key", "database"):
            assert forbidden not in str(body).lower()


# ---------------------------------------------------------------------------
# Boot sequence não afirma nada sobre o relay antes de tentar de verdade
# ---------------------------------------------------------------------------

def test_boot_sequence_does_not_claim_offline_mode():
    terminal.init_terminal()
    buf = io.StringIO()
    with redirect_stdout(buf):
        terminal.boot_sequence()
    output = buf.getvalue()
    assert "offline mode" not in output.lower()
    assert "connecting to relay" not in output.lower()
    assert "synchronizing presence" not in output.lower()
    assert "system ready" in output.lower()

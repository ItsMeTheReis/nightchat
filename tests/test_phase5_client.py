"""
Testes do lado cliente da Fase 5: comando `chat`, invalidação de sessão
na reconexão, e que o callback de mensagem cifrada nunca derruba nada
mesmo diante de erro (sessão desconhecida, replay, adulteração).
"""

from __future__ import annotations

from unittest import mock

from client import active_sessions, chat_state, commands
from client.session import SessionState


class FakeRelayClient:
    def __init__(self, connected: bool = True):
        self.connected = connected
        self.sent_messages: list[tuple[str, str, str]] = []

    def send_encrypted_message(self, target, session_id, payload_b64):
        self.sent_messages.append((target, session_id, payload_b64))
        return self.connected


def setup_function(_fn):
    active_sessions.reset()
    chat_state.reset()


def _session(peer="sofia", session_id="session-abc"):
    return SessionState(session_id=session_id, peer_username=peer, k_send=b"\x01" * 32, k_recv=b"\x02" * 32)


def test_chat_without_established_session_shows_error_and_does_not_crash():
    fake = FakeRelayClient()
    ctx = commands.Context(username="morningstar", fingerprint="AAAA", client=fake)
    result = commands.dispatch(ctx, 'chat "sofia"')
    assert result == commands.CONTINUE
    assert chat_state.current() is None  # nunca entrou no modo chat


def test_chat_with_self_is_rejected():
    active_sessions.store(_session(peer="morningstar"))
    fake = FakeRelayClient()
    ctx = commands.Context(username="morningstar", fingerprint="AAAA", client=fake)
    result = commands.dispatch(ctx, 'chat "morningstar"')
    assert result == commands.CONTINUE


def test_chat_sends_encrypted_message_and_leaves_on_back(monkeypatch):
    session = _session()
    active_sessions.store(session)
    fake = FakeRelayClient()
    ctx = commands.Context(username="morningstar", fingerprint="AAAA", client=fake)

    # simula o usuário digitando uma mensagem e depois saindo do chat
    inputs = iter(["hello sofia", "/back"])
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: next(inputs))

    result = commands.dispatch(ctx, 'chat "sofia"')

    assert result == commands.CONTINUE
    assert chat_state.current() is None  # saiu do modo chat corretamente
    assert len(fake.sent_messages) == 1
    target, session_id, payload_b64 = fake.sent_messages[0]
    assert target == "sofia"
    assert session_id == session.session_id
    assert session.send_counter == 1  # a mensagem foi realmente cifrada (contador avançou)


def test_chat_sets_and_clears_chat_state_even_on_eof(monkeypatch):
    active_sessions.store(_session())
    fake = FakeRelayClient()
    ctx = commands.Context(username="morningstar", fingerprint="AAAA", client=fake)

    def _raise_eof(*_a, **_k):
        raise EOFError

    monkeypatch.setattr("builtins.input", _raise_eof)

    commands.dispatch(ctx, 'chat "sofia"')
    assert chat_state.current() is None  # limpo mesmo saindo por EOF


def test_chat_stops_when_relay_disconnects_mid_session(monkeypatch):
    session = _session()
    active_sessions.store(session)
    fake = FakeRelayClient(connected=False)  # já desconectado antes de entrar
    ctx = commands.Context(username="morningstar", fingerprint="AAAA", client=fake)

    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "hello")

    result = commands.dispatch(ctx, 'chat "sofia"')
    assert result == commands.CONTINUE
    assert chat_state.current() is None
    assert fake.sent_messages == []  # nunca chegou a tentar enviar


# ---------------------------------------------------------------------------
# main.py: reconexão invalida sessões; callback de mensagem nunca crasha
# ---------------------------------------------------------------------------

def test_reconnect_invalidates_active_sessions():
    import client.main as main_module

    active_sessions.store(_session(peer="sofia"))
    active_sessions.store(_session(peer="elliot", session_id="session-xyz"))
    assert set(active_sessions.list_peers()) == {"sofia", "elliot"}

    main_module._on_reconnected()

    assert active_sessions.list_peers() == []


def test_encrypted_message_callback_handles_unknown_session_gracefully():
    import client.main as main_module

    # nenhuma sessão ativa com "ghost" -> não deve levantar
    main_module._on_encrypted_message("ghost", "some-session", "aGVsbG8=")


def test_encrypted_message_callback_handles_tampered_payload_gracefully():
    import client.main as main_module

    session = _session(peer="sofia")
    active_sessions.store(session)
    # payload que não decodifica em nada válido
    main_module._on_encrypted_message("sofia", session.session_id, "not-a-valid-payload!!")


def test_encrypted_message_callback_handles_replay_gracefully():
    import client.main as main_module
    from client import chat

    session_a = _session(peer="sofia")
    session_b = SessionState(session_id=session_a.session_id, peer_username="morningstar", k_send=session_a.k_recv, k_recv=session_a.k_send)
    active_sessions.store(session_b)

    payload = chat.encrypt_outgoing(session_a, "morningstar", "hi")
    main_module._on_encrypted_message("morningstar", session_a.session_id, payload)
    assert session_b.recv_counter == 1

    # reentrega a mesma mensagem — não pode levantar, nem duplicar o estado
    main_module._on_encrypted_message("morningstar", session_a.session_id, payload)
    assert session_b.recv_counter == 1

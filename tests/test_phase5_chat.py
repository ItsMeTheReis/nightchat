"""
Testes de client/chat.py — mensagens de chat cifradas usando uma
SessionState já estabelecida (Fase 4). Cobre o caminho feliz e todos os
ataques exigidos: replay, duplicata, adulteração de ciphertext, de
contador, de session_id, mensagem de outro peer e chave incorreta.
"""

from __future__ import annotations

import base64
import json

import pytest

from client import aead, chat
from client.session import SessionState


def _make_pair(session_id: str = "session-1"):
    """Duas SessionState 'espelhadas', como o handshake da Fase 4
    produziria: o k_send de um é o k_recv do outro."""
    k_a_to_b = b"\x01" * 32
    k_b_to_a = b"\x02" * 32
    session_a = SessionState(session_id=session_id, peer_username="sofia", k_send=k_a_to_b, k_recv=k_b_to_a)
    session_b = SessionState(session_id=session_id, peer_username="morningstar", k_send=k_b_to_a, k_recv=k_a_to_b)
    return session_a, session_b


def test_round_trip_message():
    session_a, session_b = _make_pair()
    payload = chat.encrypt_outgoing(session_a, "morningstar", "hello sofia")
    plaintext = chat.decrypt_incoming(session_b, session_a.session_id, "morningstar", payload)
    assert plaintext == "hello sofia"
    assert session_a.send_counter == 1
    assert session_b.recv_counter == 1


def test_multiple_messages_increment_counters_in_order():
    session_a, session_b = _make_pair()
    for i, text in enumerate(["one", "two", "three"], start=1):
        payload = chat.encrypt_outgoing(session_a, "morningstar", text)
        plaintext = chat.decrypt_incoming(session_b, session_a.session_id, "morningstar", payload)
        assert plaintext == text
        assert session_a.send_counter == i
        assert session_b.recv_counter == i


def test_payload_never_contains_plaintext():
    session_a, _ = _make_pair()
    payload = chat.encrypt_outgoing(session_a, "morningstar", "a very secret message")
    raw = base64.b64decode(payload)
    assert b"a very secret message" not in raw


# ---------------------------------------------------------------------------
# Replay / duplicata / fora de ordem
# ---------------------------------------------------------------------------

def test_replaying_the_same_message_is_rejected():
    session_a, session_b = _make_pair()
    payload = chat.encrypt_outgoing(session_a, "morningstar", "hello")
    chat.decrypt_incoming(session_b, session_a.session_id, "morningstar", payload)

    with pytest.raises(chat.ReplayError):
        chat.decrypt_incoming(session_b, session_a.session_id, "morningstar", payload)


def test_duplicate_delivery_of_same_counter_is_rejected():
    """Mesmo contador entregue duas vezes (ex.: retransmissão de rede) —
    a segunda cópia não pode ser aceita de novo."""
    session_a, session_b = _make_pair()
    payload1 = chat.encrypt_outgoing(session_a, "morningstar", "first")
    chat.decrypt_incoming(session_b, session_a.session_id, "morningstar", payload1)

    # reentrega o MESMO payload (mesmo counter=1) de novo
    with pytest.raises(chat.ReplayError):
        chat.decrypt_incoming(session_b, session_a.session_id, "morningstar", payload1)


def test_out_of_order_lower_counter_after_higher_is_rejected():
    session_a, session_b = _make_pair()
    payload1 = chat.encrypt_outgoing(session_a, "morningstar", "first")
    payload2 = chat.encrypt_outgoing(session_a, "morningstar", "second")

    chat.decrypt_incoming(session_b, session_a.session_id, "morningstar", payload2)  # processa o 2 primeiro
    with pytest.raises(chat.ReplayError):
        chat.decrypt_incoming(session_b, session_a.session_id, "morningstar", payload1)  # 1 chega depois — rejeitado


def test_failed_replay_attempt_does_not_advance_counter_state():
    session_a, session_b = _make_pair()
    payload = chat.encrypt_outgoing(session_a, "morningstar", "hello")
    chat.decrypt_incoming(session_b, session_a.session_id, "morningstar", payload)
    assert session_b.recv_counter == 1

    try:
        chat.decrypt_incoming(session_b, session_a.session_id, "morningstar", payload)
    except chat.ReplayError:
        pass
    assert session_b.recv_counter == 1  # não regrediu nem duplicou


# ---------------------------------------------------------------------------
# Adulteração
# ---------------------------------------------------------------------------

def test_tampered_ciphertext_is_rejected():
    session_a, session_b = _make_pair()
    payload = chat.encrypt_outgoing(session_a, "morningstar", "hello")
    frame = json.loads(base64.b64decode(payload))
    ciphertext = bytearray(base64.b64decode(frame["ciphertext"]))
    ciphertext[0] ^= 0xFF
    frame["ciphertext"] = base64.b64encode(bytes(ciphertext)).decode("ascii")
    tampered_payload = base64.b64encode(json.dumps(frame).encode("utf-8")).decode("ascii")

    with pytest.raises(aead.DecryptionError):
        chat.decrypt_incoming(session_b, session_a.session_id, "morningstar", tampered_payload)


def test_tampered_counter_is_rejected():
    """Mudar o campo 'counter' (autenticado como parte do AAD) sem
    recifrar invalida a mensagem — mesmo que o ciphertext em si não
    tenha sido tocado."""
    session_a, session_b = _make_pair()
    payload = chat.encrypt_outgoing(session_a, "morningstar", "hello")
    frame = json.loads(base64.b64decode(payload))
    frame["counter"] = frame["counter"] + 5
    tampered_payload = base64.b64encode(json.dumps(frame).encode("utf-8")).decode("ascii")

    with pytest.raises(aead.DecryptionError):
        chat.decrypt_incoming(session_b, session_a.session_id, "morningstar", tampered_payload)


def test_tampered_session_id_is_rejected():
    session_a, session_b = _make_pair()
    payload = chat.encrypt_outgoing(session_a, "morningstar", "hello")

    with pytest.raises(chat.WrongSessionError):
        chat.decrypt_incoming(session_b, "some-other-session-id", "morningstar", payload)


def test_message_claiming_wrong_sender_is_rejected():
    """A SessionState é específica de um peer — uma mensagem que chega
    dizendo vir de outra pessoa não pode ser aceita nela."""
    session_a, session_b = _make_pair()
    payload = chat.encrypt_outgoing(session_a, "morningstar", "hello")

    with pytest.raises(chat.WrongSessionError):
        chat.decrypt_incoming(session_b, session_a.session_id, "someone_else", payload)


def test_message_decrypted_with_wrong_session_key_is_rejected():
    """Simula 'chave incorreta': uma SessionState com o mesmo session_id
    e peer, mas chaves diferentes (ex.: um handshake diferente/corrompido)."""
    session_a, session_b = _make_pair()
    payload = chat.encrypt_outgoing(session_a, "morningstar", "hello")

    wrong_key_session = SessionState(
        session_id=session_a.session_id, peer_username="morningstar", k_send=b"\x09" * 32, k_recv=b"\x08" * 32
    )
    with pytest.raises(aead.DecryptionError):
        chat.decrypt_incoming(wrong_key_session, session_a.session_id, "morningstar", payload)


def test_message_from_a_different_established_session_is_rejected():
    """Uma mensagem cifrada para a sessão com 'elliot' não pode ser
    aceita na sessão com 'sofia', mesmo compartilhando o mesmo destinatário
    local — sessões diferentes têm session_id e chaves diferentes."""
    session_with_sofia, _ = _make_pair(session_id="session-with-sofia")
    session_with_elliot_a, session_with_elliot_b = _make_pair(session_id="session-with-elliot")

    payload = chat.encrypt_outgoing(session_with_elliot_a, "morningstar", "message for elliot's session")

    with pytest.raises(chat.WrongSessionError):
        chat.decrypt_incoming(session_with_sofia, session_with_elliot_a.session_id, "morningstar", payload)


def test_malformed_payload_is_rejected_gracefully():
    _, session_b = _make_pair()
    with pytest.raises(aead.DecryptionError):
        chat.decrypt_incoming(session_b, session_b.session_id, "morningstar", "not-valid-base64-json!!")


def test_payload_missing_required_fields_is_rejected():
    _, session_b = _make_pair()
    bad_frame = base64.b64encode(json.dumps({"counter": 1}).encode("utf-8")).decode("ascii")  # falta 'ciphertext'
    with pytest.raises(aead.DecryptionError):
        chat.decrypt_incoming(session_b, session_b.session_id, "morningstar", bad_frame)

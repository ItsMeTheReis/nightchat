"""
Testes do roteamento de TYPE_ENCRYPTED_MESSAGE no relay (Fase 5):
- roteamento autorizado por session_id (mesma regra do handshake, Fase 4);
- rejeição de sessão desconhecida/de outro par;
- o relay nunca decifra, nunca loga, nunca guarda o conteúdo;
- integração completa: handshake real + troca de mensagem cifrada real
  de ponta a ponta pelo relay de verdade (TestClient), confirmando que o
  ciphertext que atravessa o relay não é o plaintext.
"""

from __future__ import annotations

import base64
import json
import uuid

import pytest
from fastapi.testclient import TestClient

from client import chat
from client import crypto as client_crypto
from client.crypto_identity import load_or_create
from client.handshake import HandshakeManager
from client.identity_store import PlaintextIdentityStore
from server import sessions
from server.main import app, _login_limiter, _register_limiter, _exists_limiter
from server.presence import manager
from server.relay import _connect_request_limiter, _ws_message_limiter
from shared import identity as shared_identity
from shared import protocol as proto


@pytest.fixture(autouse=True)
def _clean_relay_state():
    manager.active.clear()
    sessions._pending.clear()
    sessions._handshake_sessions.clear()
    _login_limiter.reset()
    _register_limiter.reset()
    _exists_limiter.reset()
    _connect_request_limiter.reset()
    _ws_message_limiter.reset()
    yield
    manager.active.clear()
    sessions._pending.clear()
    sessions._handshake_sessions.clear()
    _login_limiter.reset()
    _register_limiter.reset()
    _exists_limiter.reset()
    _connect_request_limiter.reset()
    _ws_message_limiter.reset()


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def isolated_store(tmp_path, monkeypatch):
    import client.identity_store as store_module

    monkeypatch.setattr(store_module, "_store_dir", lambda: tmp_path)
    return PlaintextIdentityStore()


def _unique(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex[:6]}"


def _register(client: TestClient, username: str, password: str) -> str:
    resp = client.post("/auth/register", json={"username": username, "password": password})
    assert resp.status_code == 201, resp.text
    return resp.json()["token"]


def _publish_key(client: TestClient, token: str, username: str, identity) -> None:
    public_key_b64 = identity.public_key_b64()
    message = shared_identity.key_binding_message(username, public_key_b64)
    signature_b64 = base64.b64encode(identity.sign(message)).decode("ascii")
    resp = client.put(
        "/users/me/public-key",
        json={"public_key": public_key_b64, "signature": signature_b64},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text


def _authed_ws(client: TestClient, token: str):
    ctx = client.websocket_connect("/ws")

    class _Ctx:
        def __enter__(self):
            raw = ctx.__enter__()
            raw.send_json({"type": proto.TYPE_AUTH, "token": token})
            result = raw.receive_json()
            assert result["ok"] is True, result
            return raw

        def __exit__(self, *exc):
            return ctx.__exit__(*exc)

    return _Ctx()


def _accept_and_get_session(wa, wb, a: str, b: str) -> str:
    wa.send_json({"type": "connect_request", "from": a, "to": b})
    wb.receive_json()
    wb.send_json({"type": "connect_response", "from": b, "to": a, "payload": "accept"})
    resp = wa.receive_json()
    assert resp["type"] == "connect_response" and resp["payload"] == "accept"
    return resp["session"]


# ---------------------------------------------------------------------------
# Autorização de roteamento
# ---------------------------------------------------------------------------

def test_encrypted_message_routes_between_authorized_participants(client: TestClient):
    a, b = _unique("morningstar"), _unique("sofia")
    ta = _register(client, a, "s3nh4-forte")
    tb = _register(client, b, "s3nh4-forte")

    with _authed_ws(client, ta) as wa:
        wa.receive_json()
        with _authed_ws(client, tb) as wb:
            wb.receive_json()
            wa.receive_json()
            session_id = _accept_and_get_session(wa, wb, a, b)

            wa.send_json({"type": "encrypted_message", "from": a, "to": b, "session": session_id, "payload": "ZmFrZS1jaXBoZXJ0ZXh0"})
            msg = wb.receive_json()
            assert msg["type"] == "encrypted_message"
            assert msg["from"] == a
            assert msg["session"] == session_id
            assert msg["payload"] == "ZmFrZS1jaXBoZXJ0ZXh0"


def test_encrypted_message_rejects_unknown_session(client: TestClient):
    a = _unique("lonely")
    ta = _register(client, a, "s3nh4-forte")
    with _authed_ws(client, ta) as wa:
        wa.receive_json()
        wa.send_json({"type": "encrypted_message", "from": a, "to": "ninguem", "session": "nao-existe", "payload": "aGVsbG8="})
        err = wa.receive_json()
        assert err["reason"] == "unknown_session"


def test_outsider_cannot_inject_encrypted_message_into_someone_elses_session(client: TestClient):
    a, b, c = _unique("aa"), _unique("bb"), _unique("cc")
    ta = _register(client, a, "s3nh4-forte")
    tb = _register(client, b, "s3nh4-forte")
    tc = _register(client, c, "s3nh4-forte")

    with _authed_ws(client, ta) as wa:
        wa.receive_json()
        with _authed_ws(client, tb) as wb:
            wb.receive_json()
            wa.receive_json()
            session_id = _accept_and_get_session(wa, wb, a, b)

            with _authed_ws(client, tc) as wc:
                wc.receive_json()
                wa.receive_json()
                wb.receive_json()

                wc.send_json({"type": "encrypted_message", "from": c, "to": b, "session": session_id, "payload": "aGVsbG8="})
                err = wc.receive_json()
                assert err["reason"] == "unknown_session"


def test_encrypted_message_to_offline_peer_returns_error(client: TestClient):
    a, b = _unique("morningstar"), _unique("sofia")
    ta = _register(client, a, "s3nh4-forte")
    tb = _register(client, b, "s3nh4-forte")

    with _authed_ws(client, ta) as wa:
        wa.receive_json()
        with _authed_ws(client, tb) as wb:
            wb.receive_json()
            wa.receive_json()
            session_id = _accept_and_get_session(wa, wb, a, b)
        # b desconectou — a recebe um session_end e um presence offline (Fase 2/4)
        end_msg = wa.receive_json()
        assert end_msg["type"] == "session_end"
        presence_msg = wa.receive_json()
        assert presence_msg["type"] == "presence"

        wa.send_json({"type": "encrypted_message", "from": a, "to": b, "session": session_id, "payload": "aGVsbG8="})
        err = wa.receive_json()
        assert err["reason"] == "unknown_session"  # a sessão já foi limpa quando b desconectou


# ---------------------------------------------------------------------------
# O relay nunca decifra / nunca vê plaintext
# ---------------------------------------------------------------------------

def test_relay_never_stores_or_modifies_ciphertext_payload(client: TestClient):
    """O byte a byte que sai é EXATAMENTE o que entrou — nenhuma
    "compreensão" do conteúdo pelo relay."""
    a, b = _unique("morningstar"), _unique("sofia")
    ta = _register(client, a, "s3nh4-forte")
    tb = _register(client, b, "s3nh4-forte")

    with _authed_ws(client, ta) as wa:
        wa.receive_json()
        with _authed_ws(client, tb) as wb:
            wb.receive_json()
            wa.receive_json()
            session_id = _accept_and_get_session(wa, wb, a, b)

            opaque_payload = base64.b64encode(b"\x00\x01\xffnot-really-json-just-bytes").decode("ascii")
            wa.send_json({"type": "encrypted_message", "from": a, "to": b, "session": session_id, "payload": opaque_payload})
            msg = wb.receive_json()
            assert msg["payload"] == opaque_payload  # bit-a-bit idêntico


def test_relay_has_no_users_table_column_capable_of_decrypting(client: TestClient):
    """Verificação estrutural: a tabela users não tem NENHUMA coluna que
    pudesse guardar uma chave de sessão/segredo compartilhado — só
    username e password_hash (Fase 2/3)."""
    from server.models import User

    column_names = {c.name for c in User.__table__.columns}
    assert column_names == {"username", "password_hash", "public_key"}
    for forbidden in ("session_key", "shared_secret", "k_send", "k_recv", "private_key"):
        assert forbidden not in column_names


def test_relay_logging_never_includes_payload_content(client: TestClient, caplog):
    """Nenhuma chamada de log do relay inclui o conteúdo de `payload` —
    só metadados operacionais (username, session_id, tipo)."""
    import logging

    a, b = _unique("morningstar"), _unique("sofia")
    ta = _register(client, a, "s3nh4-forte")
    tb = _register(client, b, "s3nh4-forte")

    secret_marker = "TOTALLY_SECRET_PLAINTEXT_MARKER_XYZ"
    opaque_payload = base64.b64encode(secret_marker.encode()).decode("ascii")

    with caplog.at_level(logging.DEBUG, logger="nightchat.relay"):
        with _authed_ws(client, ta) as wa:
            wa.receive_json()
            with _authed_ws(client, tb) as wb:
                wb.receive_json()
                wa.receive_json()
                session_id = _accept_and_get_session(wa, wb, a, b)
                wa.send_json(
                    {"type": "encrypted_message", "from": a, "to": b, "session": session_id, "payload": opaque_payload}
                )
                wb.receive_json()

    for record in caplog.records:
        assert secret_marker not in record.getMessage()
        assert opaque_payload not in record.getMessage()


# ---------------------------------------------------------------------------
# Integração completa: handshake real + chat E2EE real de ponta a ponta
# ---------------------------------------------------------------------------

def test_full_e2ee_chat_end_to_end_over_real_relay(client: TestClient, isolated_store):
    morningstar, sofia = _unique("morningstar"), _unique("sofia")
    t_m = _register(client, morningstar, "s3nh4-forte")
    t_s = _register(client, sofia, "s3nh4-sofia")

    id_m, _ = load_or_create(morningstar, isolated_store)
    id_s, _ = load_or_create(sofia, isolated_store)
    _publish_key(client, t_m, morningstar, id_m)
    _publish_key(client, t_s, sofia, id_s)

    def fetch_public_key(username: str):
        resp = client.get(f"/users/{username}/public-key")
        if resp.status_code != 200:
            return None
        b64 = resp.json().get("public_key")
        return client_crypto.decode_public_key(b64) if b64 else None

    with _authed_ws(client, t_m) as wm:
        wm.receive_json()
        with _authed_ws(client, t_s) as ws:
            ws.receive_json()
            wm.receive_json()
            session_id = _accept_and_get_session(wm, ws, morningstar, sofia)

            def send_via(ws_socket, msg_type, target, sid, payload):
                ws_socket.send_json({"type": msg_type, "to": target, "session": sid, "payload": payload})
                return True

            def send_handshake_via(ws_socket):
                return lambda t, s, p: send_via(
                    ws_socket, "relay", t, s, base64.b64encode(json.dumps(p).encode("utf-8")).decode("ascii")
                )

            established = {}
            hm_m = HandshakeManager(identity=id_m, send_relay=send_handshake_via(wm), fetch_public_key=fetch_public_key)
            hm_s = HandshakeManager(identity=id_s, send_relay=send_handshake_via(ws), fetch_public_key=fetch_public_key)
            hm_m.on_established = lambda st: established.setdefault("morningstar", st)
            hm_s.on_established = lambda st: established.setdefault("sofia", st)

            hm_m.initiate(sofia, session_id)

            msg1 = ws.receive_json()
            hm_s.handle_message(msg1["from"], msg1["session"], json.loads(base64.b64decode(msg1["payload"])))
            msg2 = wm.receive_json()
            hm_m.handle_message(msg2["from"], msg2["session"], json.loads(base64.b64decode(msg2["payload"])))
            msg3 = ws.receive_json()
            hm_s.handle_message(msg3["from"], msg3["session"], json.loads(base64.b64decode(msg3["payload"])))

            assert "morningstar" in established and "sofia" in established
            session_m = established["morningstar"]
            session_s = established["sofia"]

            # --- agora o CHAT de verdade, usando as chaves recém-derivadas ---
            plaintext_sent = "hello sofia, this is a secret"
            chat_payload = chat.encrypt_outgoing(session_m, morningstar, plaintext_sent)

            send_via(wm, "encrypted_message", sofia, session_id, chat_payload)
            chat_msg = ws.receive_json()
            assert chat_msg["type"] == "encrypted_message"

            # o que atravessou o relay NÃO é o plaintext
            raw_on_wire = base64.b64decode(chat_msg["payload"])
            assert plaintext_sent.encode("utf-8") not in raw_on_wire

            received_plaintext = chat.decrypt_incoming(session_s, chat_msg["session"], chat_msg["from"], chat_msg["payload"])
            assert received_plaintext == plaintext_sent

            # --- e a resposta, na direção oposta ---
            reply_sent = "hello morningstar, secret received"
            reply_payload = chat.encrypt_outgoing(session_s, sofia, reply_sent)
            send_via(ws, "encrypted_message", morningstar, session_id, reply_payload)
            reply_msg = wm.receive_json()
            received_reply = chat.decrypt_incoming(session_m, reply_msg["session"], reply_msg["from"], reply_msg["payload"])
            assert received_reply == reply_sent

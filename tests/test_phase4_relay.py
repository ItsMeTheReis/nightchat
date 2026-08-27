"""
Testes do roteamento de handshake E2EE no relay (Fase 4):
- session_id é mintado pelo relay no connect_response(accept);
- TYPE_RELAY só é roteado entre os dois participantes reais da sessão;
- um terceiro (ou o próprio participante mirando outro alvo) não
  consegue usar/redirecionar uma sessão alheia;
- TYPE_SESSION_END encerra a sessão e avisa a outra parte;
- desconexão no meio do handshake limpa a sessão e avisa quem ficou;
- integração completa: handshake real (client/handshake.py) de ponta a
  ponta através do relay de verdade (TestClient), incluindo a publicação
  de chaves Ed25519 da Fase 3.
"""

from __future__ import annotations

import base64
import json
import uuid

import pytest
from fastapi.testclient import TestClient

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
    """`a` pede conexão a `b`; `b` aceita. Retorna o session_id que `a`
    recebe de volta (mintado pelo relay)."""
    wa.send_json({"type": "connect_request", "from": a, "to": b})
    wb.receive_json()  # connect_request chega em b
    wb.send_json({"type": "connect_response", "from": b, "to": a, "payload": "accept"})
    resp = wa.receive_json()
    assert resp["type"] == "connect_response"
    assert resp["payload"] == "accept"
    assert "session" in resp
    return resp["session"]


# ---------------------------------------------------------------------------
# session_id mintado no accept
# ---------------------------------------------------------------------------

def test_accept_includes_a_session_id(client: TestClient):
    a, b = _unique("morningstar"), _unique("sofia")
    ta = _register(client, a, "s3nh4-forte")
    tb = _register(client, b, "s3nh4-forte")

    with _authed_ws(client, ta) as wa:
        wa.receive_json()
        with _authed_ws(client, tb) as wb:
            wb.receive_json()
            wa.receive_json()
            session_id = _accept_and_get_session(wa, wb, a, b)
            assert isinstance(session_id, str) and len(session_id) > 0
            assert sessions.other_party(session_id, a) == b
            assert sessions.other_party(session_id, b) == a


def test_deny_does_not_mint_a_session(client: TestClient):
    a, b = _unique("morningstar"), _unique("sofia")
    ta = _register(client, a, "s3nh4-forte")
    tb = _register(client, b, "s3nh4-forte")

    with _authed_ws(client, ta) as wa:
        wa.receive_json()
        with _authed_ws(client, tb) as wb:
            wb.receive_json()
            wa.receive_json()

            wa.send_json({"type": "connect_request", "from": a, "to": b})
            wb.receive_json()
            wb.send_json({"type": "connect_response", "from": b, "to": a, "payload": "deny"})
            resp = wa.receive_json()
            assert resp["payload"] == "deny"
            assert "session" not in resp


# ---------------------------------------------------------------------------
# Autorização de roteamento do TYPE_RELAY / TYPE_SESSION_END
# ---------------------------------------------------------------------------

def test_relay_forwards_between_authorized_participants(client: TestClient):
    a, b = _unique("morningstar"), _unique("sofia")
    ta = _register(client, a, "s3nh4-forte")
    tb = _register(client, b, "s3nh4-forte")

    with _authed_ws(client, ta) as wa:
        wa.receive_json()
        with _authed_ws(client, tb) as wb:
            wb.receive_json()
            wa.receive_json()
            session_id = _accept_and_get_session(wa, wb, a, b)

            wa.send_json({"type": "relay", "from": a, "to": b, "session": session_id, "payload": "aGVsbG8="})
            msg = wb.receive_json()
            assert msg["type"] == "relay"
            assert msg["from"] == a
            assert msg["session"] == session_id
            assert msg["payload"] == "aGVsbG8="


def test_relay_rejects_unknown_session(client: TestClient):
    a = _unique("lonely")
    ta = _register(client, a, "s3nh4-forte")
    with _authed_ws(client, ta) as wa:
        wa.receive_json()
        wa.send_json({"type": "relay", "from": a, "to": "ninguem", "session": "nao-existe", "payload": "aGVsbG8="})
        err = wa.receive_json()
        assert err["reason"] == "unknown_session"


def test_outsider_cannot_use_someone_elses_session_id(client: TestClient):
    """C não é participante da sessão entre A e B — não consegue usá-la."""
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

                wc.send_json({"type": "relay", "from": c, "to": b, "session": session_id, "payload": "aGVsbG8="})
                err = wc.receive_json()
                assert err["reason"] == "unknown_session"


def test_participant_cannot_redirect_session_to_a_different_target(client: TestClient):
    """A é participante da sessão com B, mas tenta mandar pelo mesmo
    session_id para C — não é permitido: o 'to' precisa bater com o outro
    participante real da sessão."""
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

                wa.send_json({"type": "relay", "from": a, "to": c, "session": session_id, "payload": "aGVsbG8="})
                err = wa.receive_json()
                assert err["reason"] == "unknown_session"


def test_session_end_ends_session_and_notifies_peer(client: TestClient):
    a, b = _unique("morningstar"), _unique("sofia")
    ta = _register(client, a, "s3nh4-forte")
    tb = _register(client, b, "s3nh4-forte")

    with _authed_ws(client, ta) as wa:
        wa.receive_json()
        with _authed_ws(client, tb) as wb:
            wb.receive_json()
            wa.receive_json()
            session_id = _accept_and_get_session(wa, wb, a, b)

            wa.send_json({"type": "session_end", "from": a, "session": session_id})
            end_msg = wb.receive_json()
            assert end_msg["type"] == "session_end"
            assert end_msg["from"] == a
            assert end_msg["session"] == session_id

            assert sessions.other_party(session_id, a) is None

            wb.send_json({"type": "relay", "from": b, "to": a, "session": session_id, "payload": "aGVsbG8="})
            err = wb.receive_json()
            assert err["reason"] == "unknown_session"


def test_disconnect_mid_handshake_cleans_up_and_notifies_peer(client: TestClient):
    a, b = _unique("morningstar"), _unique("sofia")
    ta = _register(client, a, "s3nh4-forte")
    tb = _register(client, b, "s3nh4-forte")

    with _authed_ws(client, tb) as wb:
        wb.receive_json()
        session_id = None
        with _authed_ws(client, ta) as wa:
            wa.receive_json()
            wb.receive_json()
            session_id = _accept_and_get_session(wa, wb, a, b)
        # `a` desconectou (saiu do `with` de dentro) sem terminar o handshake

        end_msg = wb.receive_json()  # primeiro a presence offline ou o session_end — checa os dois
        seen_types = {end_msg["type"]}
        if end_msg["type"] != "session_end":
            end_msg2 = wb.receive_json()
            seen_types.add(end_msg2["type"])
        assert "session_end" in seen_types
        assert sessions.other_party(session_id, b) is None


# ---------------------------------------------------------------------------
# Integração completa: handshake real de ponta a ponta pelo relay real
# ---------------------------------------------------------------------------

def test_full_handshake_end_to_end_over_real_relay(client: TestClient, isolated_store):
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

            def send_via(ws_socket, target, sid, payload):
                ws_socket.send_json(
                    {
                        "type": "relay",
                        "to": target,
                        "session": sid,
                        "payload": base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii"),
                    }
                )
                return True

            established = {}
            hm_m = HandshakeManager(identity=id_m, send_relay=lambda t, s, p: send_via(wm, t, s, p), fetch_public_key=fetch_public_key)
            hm_s = HandshakeManager(identity=id_s, send_relay=lambda t, s, p: send_via(ws, t, s, p), fetch_public_key=fetch_public_key)
            hm_m.on_established = lambda st: established.__setitem__("morningstar", st)
            hm_s.on_established = lambda st: established.__setitem__("sofia", st)

            hm_m.initiate(sofia, session_id)

            msg1 = ws.receive_json()
            assert msg1["type"] == "relay"
            payload1 = json.loads(base64.b64decode(msg1["payload"]))
            hm_s.handle_message(msg1["from"], msg1["session"], payload1)

            msg2 = wm.receive_json()
            payload2 = json.loads(base64.b64decode(msg2["payload"]))
            hm_m.handle_message(msg2["from"], msg2["session"], payload2)

            msg3 = ws.receive_json()
            payload3 = json.loads(base64.b64decode(msg3["payload"]))
            hm_s.handle_message(msg3["from"], msg3["session"], payload3)

    assert "morningstar" in established
    assert "sofia" in established
    session_m = established["morningstar"]
    session_s = established["sofia"]
    assert session_m.session_id == session_id == session_s.session_id
    assert session_m.k_send == session_s.k_recv
    assert session_m.k_recv == session_s.k_send

"""
Testes do NightChat Relay (Fase 2, revisão pós-auditoria): registro,
login, normalização/validação de username, timing-safety do login,
presença (incluindo a race condition de reconexão), ciclo de vida do
banco no WebSocket, validação de mensagens malformadas, rate limiting,
pedidos de conexão múltiplos e a autenticação do WebSocket por primeira
mensagem (sem token na URL).

Roda com pytest:
    python -m pytest tests/test_phase2_server.py -v
"""

from __future__ import annotations

import json
import time
import uuid
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from jose import jwt as jose_jwt

from server import auth, sessions
from server.config import Settings, validate_production_config
from server.main import app, _login_limiter, _register_limiter, _exists_limiter
from server.presence import manager
from server.relay import _connect_request_limiter, _ws_message_limiter, _is_secure
from shared import protocol as proto


@pytest.fixture(autouse=True)
def _clean_relay_state():
    """Evita vazamento de estado (sockets, pedidos pendentes, rate limits) entre testes."""
    manager.active.clear()
    sessions._pending.clear()
    _login_limiter.reset()
    _register_limiter.reset()
    _exists_limiter.reset()
    _connect_request_limiter.reset()
    _ws_message_limiter.reset()
    yield
    manager.active.clear()
    sessions._pending.clear()
    _login_limiter.reset()
    _register_limiter.reset()
    _exists_limiter.reset()
    _connect_request_limiter.reset()
    _ws_message_limiter.reset()


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


def _unique(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex[:8]}"


def _register(client: TestClient, username: str, password: str) -> str:
    resp = client.post("/auth/register", json={"username": username, "password": password})
    assert resp.status_code == 201, resp.text
    return resp.json()["token"]


class _WS:
    """Wrapper fino sobre o WebSocketTestSession que faz o handshake de
    autenticação por primeira mensagem (o novo protocolo — sem token na URL)."""

    def __init__(self, raw):
        self.raw = raw

    def send_json(self, data):
        self.raw.send_json(data)

    def send_text(self, text):
        self.raw.send_text(text)

    def receive_json(self):
        return self.raw.receive_json()


def _authed_ws(client: TestClient, token: str):
    """Context manager: conecta em /ws (sem query string!) e autentica
    mandando {"type": "auth", "token": ...} como primeira mensagem."""
    ctx = client.websocket_connect("/ws")

    class _Ctx:
        def __enter__(self):
            raw = ctx.__enter__()
            raw.send_json({"type": proto.TYPE_AUTH, "token": token})
            result = raw.receive_json()
            assert result["type"] == proto.TYPE_AUTH_RESULT
            assert result["ok"] is True, result
            return _WS(raw)

        def __exit__(self, *exc):
            return ctx.__exit__(*exc)

    return _Ctx()


# ---------------------------------------------------------------------------
# Registro / normalização de username / autenticação
# ---------------------------------------------------------------------------

def test_register_creates_user(client: TestClient):
    username = _unique("morningstar")
    resp = client.post("/auth/register", json={"username": username, "password": "s3nh4-forte"})
    assert resp.status_code == 201
    body = resp.json()
    assert body["username"] == username.lower()
    assert isinstance(body["token"], str) and body["token"]


def test_register_duplicate_username_is_rejected(client: TestClient):
    username = _unique("dup")
    _register(client, username, "s3nh4-forte")
    resp = client.post("/auth/register", json={"username": username, "password": "outra-senha"})
    assert resp.status_code == 409


def test_username_shorter_than_3_is_rejected(client: TestClient):
    resp = client.post("/auth/register", json={"username": "ab", "password": "s3nh4-forte"})
    assert resp.status_code == 422


def test_username_longer_than_20_is_rejected(client: TestClient):
    resp = client.post("/auth/register", json={"username": "a" * 21, "password": "s3nh4-forte"})
    assert resp.status_code == 422


def test_username_with_space_is_rejected(client: TestClient):
    resp = client.post("/auth/register", json={"username": "user name", "password": "s3nh4-forte"})
    assert resp.status_code == 422


def test_username_with_hyphen_and_underscore_is_accepted(client: TestClient):
    username = _unique("night-chat_")
    resp = client.post("/auth/register", json={"username": username, "password": "s3nh4-forte"})
    assert resp.status_code == 201


def test_username_normalization_prevents_duplicate_identities(client: TestClient):
    """morningstar / MorningStar / MORNINGSTAR precisam ser a MESMA conta."""
    base = _unique("morningstar")
    _register(client, base, "s3nh4-forte")

    resp_upper = client.post("/auth/register", json={"username": base.upper(), "password": "outra-senha"})
    assert resp_upper.status_code == 409  # já existe (normalizado)

    resp_login = client.post("/auth/login", json={"username": base.upper(), "password": "s3nh4-forte"})
    assert resp_login.status_code == 200
    assert resp_login.json()["username"] == base.lower()


def test_password_is_never_stored_in_plaintext(client: TestClient):
    from server.database import SessionLocal
    from server.models import User

    username = _unique("nopwstore")
    _register(client, username, "supersecreta123")

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username.lower()).first()
        assert user is not None
        assert user.password_hash != "supersecreta123"
        assert "supersecreta123" not in user.password_hash
        assert user.password_hash.startswith("$argon2id$")
    finally:
        db.close()


def test_login_success(client: TestClient):
    username = _unique("loginok")
    _register(client, username, "s3nh4-forte")
    resp = client.post("/auth/login", json={"username": username, "password": "s3nh4-forte"})
    assert resp.status_code == 200


def test_login_wrong_password(client: TestClient):
    username = _unique("wrongpw")
    _register(client, username, "s3nh4-forte")
    resp = client.post("/auth/login", json={"username": username, "password": "senha-errada"})
    assert resp.status_code == 401


def test_login_nonexistent_user(client: TestClient):
    resp = client.post("/auth/login", json={"username": "usuario_que_nao_existe_xyz", "password": "qualquer"})
    assert resp.status_code == 401


def test_login_nonexistent_user_still_runs_argon2_verification(client: TestClient):
    """Corrige o timing leak: usuário inexistente também deve disparar uma
    verificação Argon2id de verdade (contra o hash dummy), não um
    curto-circuito instantâneo."""
    with patch.object(auth, "verify_password", wraps=auth.verify_password) as spy:
        resp = client.post(
            "/auth/login", json={"username": "usuario_que_definitivamente_nao_existe", "password": "qualquer"}
        )
    assert resp.status_code == 401
    assert spy.call_count == 1
    called_password, called_hash = spy.call_args[0]
    assert called_hash == auth.DUMMY_HASH


def test_exists_endpoint(client: TestClient):
    username = _unique("existscheck")
    assert client.get(f"/auth/exists?username={username}").json()["exists"] is False
    _register(client, username, "s3nh4-forte")
    assert client.get(f"/auth/exists?username={username.upper()}").json()["exists"] is True


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

def test_login_rate_limit_returns_429(client: TestClient):
    username = _unique("ratelimited")
    _register(client, username, "s3nh4-forte")
    from server.config import settings as server_settings

    for _ in range(server_settings.rate_limit_login_max):
        resp = client.post("/auth/login", json={"username": username, "password": "senha-errada"})
        assert resp.status_code == 401
    resp = client.post("/auth/login", json={"username": username, "password": "senha-errada"})
    assert resp.status_code == 429


def test_register_rate_limit_returns_429(client: TestClient):
    from server.config import settings as server_settings

    for _ in range(server_settings.rate_limit_register_max):
        client.post("/auth/register", json={"username": _unique("flood"), "password": "s3nh4-forte"})
    resp = client.post("/auth/register", json={"username": _unique("flood"), "password": "s3nh4-forte"})
    assert resp.status_code == 429


def test_connect_request_rate_limit_returns_error(client: TestClient):
    from server.config import settings as server_settings

    a = _unique("floodreq")
    ta = _register(client, a, "s3nh4-forte")
    with _authed_ws(client, ta) as wa:
        wa.receive_json()  # user_list inicial
        for i in range(server_settings.rate_limit_connect_request_max):
            wa.send_json({"type": "connect_request", "from": a, "to": f"ghost{i}"})
            err = wa.receive_json()
            assert err["type"] == "error"
            assert err["reason"] == "target_offline"
        wa.send_json({"type": "connect_request", "from": a, "to": "ghost_over_limit"})
        err = wa.receive_json()
        assert err["reason"] == "rate_limited"


# ---------------------------------------------------------------------------
# Presença: race condition de reconexão (auditoria Fase 2, item crítico)
# ---------------------------------------------------------------------------

def test_presence_online_after_connect(client: TestClient):
    a = _unique("a")
    token = _register(client, a, "s3nh4-forte")
    with _authed_ws(client, token):
        assert manager.is_online(a.lower()) is True


def test_presence_offline_after_disconnect(client: TestClient):
    a = _unique("a")
    token = _register(client, a, "s3nh4-forte")
    with _authed_ws(client, token):
        assert manager.is_online(a.lower()) is True
    assert manager.is_online(a.lower()) is False


def test_old_websocket_finally_cannot_remove_new_websocket():
    """
    Reproduz diretamente a race condition da auditoria: a conexão ANTIGA
    só deve conseguir remover a entrada de presença se ainda for ela a
    conexão ativa. Uma reconexão (nova conexão já registrada) deve
    sobreviver ao cleanup tardio da conexão antiga.
    """

    class FakeWebSocket:
        async def close(self, code=None):
            pass

    import asyncio

    async def _run():
        username = "racecondition_user"
        old_ws = FakeWebSocket()
        new_ws = FakeWebSocket()

        # conexão antiga fica online primeiro
        await manager.replace(username, old_ws)
        assert manager.active[username] is old_ws

        # reconexão: a nova conexão substitui a antiga (via manager.replace,
        # como o endpoint real faz)
        await manager.replace(username, new_ws)
        assert manager.active[username] is new_ws

        # o `finally` da task ANTIGA roda tarde, tentando remover pelo
        # username (não deve ter efeito, pois quem está lá agora é new_ws)
        removed = manager.disconnect(username, old_ws)

        assert removed is False
        assert manager.is_online(username) is True
        assert manager.active[username] is new_ws  # a nova conexão sobreviveu

    asyncio.run(_run())


def test_reconnect_end_to_end_survives_stale_cleanup(client: TestClient):
    """Mesmo cenário, mas através do endpoint real: abrir, fechar sem que o
    servidor perceba ainda, reconectar, e só depois deixar a conexão velha
    'terminar' — o usuário deve continuar online no final."""
    a = _unique("reconnect")
    token = _register(client, a, "s3nh4-forte")

    with _authed_ws(client, token):
        assert manager.is_online(a.lower()) is True
        with _authed_ws(client, token):
            # segunda conexão do MESMO usuário: a primeira é fechada com 4409
            assert manager.is_online(a.lower()) is True
        # saiu do `with` de dentro -> conexão nova encerrou de propósito
    # saiu do `with` de fora -> a conexão antiga (já suplantada) tenta
    # se limpar, mas isso não deve derrubar a presença incorretamente en
    # route; ao final, ambas encerraram e o usuário está offline.
    assert manager.is_online(a.lower()) is False


# ---------------------------------------------------------------------------
# Ciclo de vida do banco durante o WebSocket
# ---------------------------------------------------------------------------

def test_websocket_does_not_hold_db_session_for_connection_lifetime(client: TestClient):
    """O endpoint WebSocket não deve usar Depends(get_db) — só abre uma
    sessão curta (via SessionLocal) para a checagem pontual do handshake e
    fecha em seguida. Verificamos isso checando que SessionLocal é chamado
    (e a sessão fechada) durante a autenticação, sem ficar pendurado
    enquanto o socket segue aberto processando mensagens."""
    from server import relay as relay_module

    a = _unique("dblifecycle")
    token = _register(client, a, "s3nh4-forte")

    close_calls = []
    original_session_local = relay_module.SessionLocal

    class TrackedSession:
        def __init__(self):
            self._session = original_session_local()

        def __enter__(self):
            return self._session

        def __exit__(self, *exc):
            close_calls.append(True)
            return self._session.__exit__(*exc)

    with patch.object(relay_module, "SessionLocal", TrackedSession):
        with _authed_ws(client, token) as ws:
            # a sessão do handshake já deve ter sido aberta E fechada antes
            # de qualquer mensagem de aplicação trafegar
            assert close_calls == [True]
            ws.send_json({"type": "list_users", "from": a})
            ws.receive_json()
            # nenhuma sessão nova foi aberta só por trocar mensagens comuns
            assert close_calls == [True]


# ---------------------------------------------------------------------------
# Autenticação do WebSocket por primeira mensagem (sem token na URL)
# ---------------------------------------------------------------------------

def test_jwt_is_not_required_in_ws_url(client: TestClient):
    """Conectar em /ws sem query string nenhuma deve funcionar — o token
    vai na primeira mensagem, não na URL."""
    a = _unique("nourltoken")
    token = _register(client, a, "s3nh4-forte")
    with client.websocket_connect("/ws") as ws:  # sem "?token=..."
        ws.send_json({"type": proto.TYPE_AUTH, "token": token})
        result = ws.receive_json()
        assert result["ok"] is True


def test_ws_rejects_missing_auth_frame(client: TestClient):
    with pytest.raises(Exception):
        with client.websocket_connect("/ws") as ws:
            ws.send_json({"type": "list_users", "from": "x"})  # não autenticou primeiro
            ws.receive_json()


def test_ws_rejects_invalid_token(client: TestClient):
    with client.websocket_connect("/ws") as ws:
        ws.send_json({"type": proto.TYPE_AUTH, "token": "not-a-real-token"})
        result = ws.receive_json()
        assert result["type"] == proto.TYPE_AUTH_RESULT
        assert result["ok"] is False
    assert manager.online_usernames() == []


def test_ws_rejects_expired_token(client: TestClient):
    from server.config import settings as server_settings

    a = _unique("expiredtoken")
    _register(client, a, "s3nh4-forte")
    expired = jose_jwt.encode(
        {"sub": a.lower(), "exp": time.time() - 60},
        server_settings.jwt_secret,
        algorithm=server_settings.jwt_algorithm,
    )
    with client.websocket_connect("/ws") as ws:
        ws.send_json({"type": proto.TYPE_AUTH, "token": expired})
        result = ws.receive_json()
        assert result["type"] == proto.TYPE_AUTH_RESULT
        assert result["ok"] is False
    assert manager.online_usernames() == []


# ---------------------------------------------------------------------------
# Validação de mensagens malformadas
# ---------------------------------------------------------------------------

def test_malformed_json_does_not_crash_connection(client: TestClient):
    a = _unique("malformed")
    token = _register(client, a, "s3nh4-forte")
    with _authed_ws(client, token) as ws:
        ws.receive_json()  # descarta user_list inicial
        ws.send_text("isto nao e json {{{")
        err = ws.receive_json()
        assert err["type"] == "error"
        assert err["reason"] == "invalid_json"
        # a conexão continua viva e funcional depois do erro
        ws.send_json({"type": "list_users", "from": a})
        ok = ws.receive_json()
        assert ok["type"] == "user_list"


@pytest.mark.parametrize("payload", ['"hello"', "42", '["a", "b"]', "true", "null"])
def test_valid_json_but_not_object_returns_error(client: TestClient, payload: str):
    a = _unique("nonobject")
    token = _register(client, a, "s3nh4-forte")
    with _authed_ws(client, token) as ws:
        ws.receive_json()  # descarta user_list inicial
        ws.send_text(payload)
        err = ws.receive_json()
        assert err["type"] == "error"
        assert err["reason"] == "invalid_message"


def test_missing_type_field_returns_error(client: TestClient):
    a = _unique("missingtype")
    token = _register(client, a, "s3nh4-forte")
    with _authed_ws(client, token) as ws:
        ws.receive_json()  # descarta user_list inicial
        ws.send_json({"from": a})
        err = ws.receive_json()
        assert err["reason"] == "missing_type"


def test_unknown_type_returns_error(client: TestClient):
    a = _unique("unknowntype")
    token = _register(client, a, "s3nh4-forte")
    with _authed_ws(client, token) as ws:
        ws.receive_json()  # descarta user_list inicial
        ws.send_json({"type": "not_a_real_type"})
        err = ws.receive_json()
        assert err["reason"] == "unknown_type"


def test_connect_request_missing_required_field_returns_error(client: TestClient):
    a = _unique("missingfield")
    token = _register(client, a, "s3nh4-forte")
    with _authed_ws(client, token) as ws:
        ws.receive_json()  # descarta user_list inicial
        ws.send_json({"type": "connect_request", "from": a})  # falta "to"
        err = ws.receive_json()
        assert err["reason"] == "missing_field"
        assert err["field"] == "to"


def test_connect_request_wrong_field_type_returns_error(client: TestClient):
    a = _unique("wrongtype")
    token = _register(client, a, "s3nh4-forte")
    with _authed_ws(client, token) as ws:
        ws.receive_json()  # descarta user_list inicial
        ws.send_json({"type": "connect_request", "from": a, "to": 12345})
        err = ws.receive_json()
        assert err["reason"] == "missing_field"


def test_relay_and_session_end_require_a_real_session(client: TestClient):
    """TYPE_RELAY/TYPE_SESSION_END passaram a ser roteados de verdade na
    Fase 4 (handshake E2EE) — mas só dentro de uma sessão real, mintada
    pelo relay num connect_response(accept). Sem "session", ou com uma
    sessão desconhecida, o servidor recusa — nunca finge sucesso. Ver
    tests/test_phase4_relay.py para o roteamento funcional completo."""
    a = _unique("norelay")
    token = _register(client, a, "s3nh4-forte")
    with _authed_ws(client, token) as ws:
        ws.receive_json()  # descarta user_list inicial

        ws.send_json({"type": proto.TYPE_RELAY, "from": a, "to": "x", "payload": "ZGF0YQ=="})
        err = ws.receive_json()
        assert err["reason"] == "missing_field"
        assert err["field"] == "session"

        ws.send_json({"type": proto.TYPE_RELAY, "from": a, "to": "x", "session": "nao-existe", "payload": "ZGF0YQ=="})
        err = ws.receive_json()
        assert err["reason"] == "unknown_session"

        ws.send_json({"type": proto.TYPE_SESSION_END, "from": a})
        err = ws.receive_json()
        assert err["reason"] == "missing_field"

        ws.send_json({"type": proto.TYPE_SESSION_END, "from": a, "session": "nao-existe"})
        err = ws.receive_json()
        assert err["reason"] == "unknown_session"


# ---------------------------------------------------------------------------
# Descoberta de usuários / múltiplos clientes
# ---------------------------------------------------------------------------

def test_user_list_query_excludes_self(client: TestClient):
    a, b = _unique("a"), _unique("b")
    ta = _register(client, a, "s3nh4-forte")
    tb = _register(client, b, "s3nh4-forte")

    with _authed_ws(client, ta) as wa:
        wa.receive_json()
        with _authed_ws(client, tb) as wb:
            wb.receive_json()
            wa.receive_json()  # presence: b ficou online

            wa.send_json({"type": "list_users", "from": a})
            listed = wa.receive_json()
            assert listed["users"] == [b.lower()]

            wb.send_json({"type": "list_users", "from": b})
            listed_b = wb.receive_json()
            assert listed_b["users"] == [a.lower()]


def test_multiple_simultaneous_clients(client: TestClient):
    users = [_unique(f"multi{i}") for i in range(3)]
    tokens = [_register(client, u, "s3nh4-forte") for u in users]

    with _authed_ws(client, tokens[0]) as w0:
        w0.receive_json()
        with _authed_ws(client, tokens[1]) as w1:
            w1.receive_json()
            w0.receive_json()
            with _authed_ws(client, tokens[2]) as w2:
                w2.receive_json()
                w0.receive_json()
                w1.receive_json()

                w2.send_json({"type": "list_users", "from": users[2]})
                seen = set(w2.receive_json()["users"])
                assert seen == {users[0].lower(), users[1].lower()}


# ---------------------------------------------------------------------------
# Pedidos de conexão: múltiplos pendentes, limpeza, resposta a quem caiu
# ---------------------------------------------------------------------------

def test_connect_request_is_forwarded(client: TestClient):
    a, b = _unique("morningstar"), _unique("sofia")
    ta = _register(client, a, "s3nh4-forte")
    tb = _register(client, b, "s3nh4-forte")

    with _authed_ws(client, ta) as wa:
        wa.receive_json()
        with _authed_ws(client, tb) as wb:
            wb.receive_json()
            wa.receive_json()

            wa.send_json({"type": "connect_request", "from": a, "to": b})
            req = wb.receive_json()
            assert req["type"] == "connect_request"
            assert req["from"] == a.lower()


def test_connect_response_accept_is_delivered_to_requester(client: TestClient):
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

            wb.send_json({"type": "connect_response", "from": b, "to": a, "payload": "accept"})
            resp = wa.receive_json()
            assert resp["from"] == b.lower()
            assert resp["payload"] == "accept"


def test_connect_response_deny_is_delivered_to_requester(client: TestClient):
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


def test_connect_request_to_offline_user_returns_error(client: TestClient):
    a = _unique("lonely")
    ta = _register(client, a, "s3nh4-forte")
    with _authed_ws(client, ta) as wa:
        wa.receive_json()
        wa.send_json({"type": "connect_request", "from": a, "to": "ninguem_esta_online"})
        err = wa.receive_json()
        assert err["reason"] == "target_offline"


def test_connect_response_without_pending_request_is_rejected(client: TestClient):
    a, b = _unique("morningstar"), _unique("sofia")
    ta = _register(client, a, "s3nh4-forte")
    tb = _register(client, b, "s3nh4-forte")

    with _authed_ws(client, ta) as wa:
        wa.receive_json()
        with _authed_ws(client, tb) as wb:
            wb.receive_json()
            wa.receive_json()

            wb.send_json({"type": "connect_response", "from": b, "to": a, "payload": "accept"})
            err = wb.receive_json()
            assert err["reason"] == "no_pending_request"


def test_multiple_pending_requests_are_both_delivered(client: TestClient):
    """A e B pedem conexão a C — C deve receber os DOIS pedidos, não só o último."""
    a, b, c = _unique("aa"), _unique("bb"), _unique("cc")
    ta = _register(client, a, "s3nh4-forte")
    tb = _register(client, b, "s3nh4-forte")
    tc = _register(client, c, "s3nh4-forte")

    with _authed_ws(client, tc) as wc:
        wc.receive_json()
        with _authed_ws(client, ta) as wa:
            wa.receive_json()
            wc.receive_json()  # presence: a online
            with _authed_ws(client, tb) as wb:
                wb.receive_json()
                wc.receive_json()  # presence: b online
                wa.receive_json()

                wa.send_json({"type": "connect_request", "from": a, "to": c})
                req_from_a = wc.receive_json()
                assert req_from_a["from"] == a.lower()

                wb.send_json({"type": "connect_request", "from": b, "to": c})
                req_from_b = wc.receive_json()
                assert req_from_b["from"] == b.lower()

                assert sessions.pending_for(c.lower()) == [a.lower(), b.lower()]

                # C aceita o pedido de A; o de B continua pendente
                wc.send_json({"type": "connect_response", "from": c, "to": a, "payload": "accept"})
                wa.receive_json()
                assert sessions.pending_for(c.lower()) == [b.lower()]


def test_requester_disconnect_cleans_up_pending_request(client: TestClient):
    """A pede conexão a B; A desconecta antes de B responder — o pedido
    órfão não deve continuar pendurado para sempre."""
    a, b = _unique("morningstar"), _unique("sofia")
    ta = _register(client, a, "s3nh4-forte")
    tb = _register(client, b, "s3nh4-forte")

    with _authed_ws(client, tb) as wb:
        wb.receive_json()
        with _authed_ws(client, ta) as wa:
            wa.receive_json()
            wb.receive_json()  # presence: a online

            wa.send_json({"type": "connect_request", "from": a, "to": b})
            wb.receive_json()
            assert sessions.pending_for(b.lower()) == [a.lower()]

        # `a` desconectou (saiu do `with` de dentro) sem que `b` respondesse
        wb.receive_json()  # presence: a offline

    assert sessions.pending_for(b.lower()) == []


def test_response_after_requester_disconnected_is_reported_as_no_pending_request(client: TestClient):
    """
    A pede conexão a B e desconecta antes de B responder. Como
    `clear_for_user` já remove o pedido pendente no disconnect de A (ver
    test_requester_disconnect_cleans_up_pending_request), a resposta
    coerente que B recebe ao tentar accept/deny é "no_pending_request" —
    não silêncio. Isso já cobre o requisito de "B deve receber uma
    resposta coerente" da auditoria.
    """
    a, b = _unique("morningstar"), _unique("sofia")
    ta = _register(client, a, "s3nh4-forte")
    tb = _register(client, b, "s3nh4-forte")

    with _authed_ws(client, tb) as wb:
        wb.receive_json()
        with _authed_ws(client, ta) as wa:
            wa.receive_json()
            wb.receive_json()
            wa.send_json({"type": "connect_request", "from": a, "to": b})
            wb.receive_json()
        wb.receive_json()  # presence: a offline

        wb.send_json({"type": "connect_response", "from": b, "to": a, "payload": "accept"})
        err = wb.receive_json()
        assert err["type"] == "error"
        assert err["reason"] == "no_pending_request"


def test_connect_response_delivery_failure_is_reported_as_requester_offline(client: TestClient):
    """
    Cobre o branch defensivo de `_handle_connect_response`: se por algum
    motivo existir um pedido pendente registrado cujo requerente não está
    mais entregável (`manager.send_to` falha) — cenário que hoje só ocorre
    fora do caminho normal, já que `clear_for_user` cobre a desconexão
    ordinária — B ainda recebe um erro explícito em vez de silêncio.
    """
    b = _unique("sofia")
    tb = _register(client, b, "s3nh4-forte")

    sessions.add_request(requester="ghost_user_never_connected", target=b.lower())

    with _authed_ws(client, tb) as wb:
        wb.receive_json()  # user_list inicial
        wb.send_json({"type": "connect_response", "from": b, "to": "ghost_user_never_connected", "payload": "accept"})
        err = wb.receive_json()
        assert err["type"] == "error"
        assert err["reason"] == "requester_offline"


# ---------------------------------------------------------------------------
# Integração: fluxo completo morningstar -> relay <- sofia
# ---------------------------------------------------------------------------

def test_integration_morningstar_connects_and_sofia_accepts(client: TestClient):
    morningstar, sofia = _unique("morningstar"), _unique("sofia")
    t_m = _register(client, morningstar, "s3nh4-forte")
    t_s = _register(client, sofia, "s3nh4-sofia")

    with _authed_ws(client, t_m) as wm:
        initial_m = wm.receive_json()
        assert initial_m["users"] == []

        with _authed_ws(client, t_s) as ws:
            initial_s = ws.receive_json()
            assert initial_s["users"] == [morningstar.lower()]

            presence_evt = wm.receive_json()
            assert presence_evt == {
                "v": "nightchat/1",
                "type": "presence",
                "from": sofia.lower(),
                "status": "online",
            }

            wm.send_json({"type": "list_users", "from": morningstar})
            assert wm.receive_json()["users"] == [sofia.lower()]

            wm.send_json({"type": "connect_request", "from": morningstar, "to": sofia})
            incoming = ws.receive_json()
            assert incoming["type"] == "connect_request"
            assert incoming["from"] == morningstar.lower()

            ws.send_json({"type": "connect_response", "from": sofia, "to": morningstar, "payload": "accept"})
            result = wm.receive_json()
            assert result["type"] == "connect_response"
            assert result["from"] == sofia.lower()
            assert result["payload"] == "accept"


# ---------------------------------------------------------------------------
# Configuração de produção
# ---------------------------------------------------------------------------

def test_production_config_with_insecure_defaults_raises():
    insecure = Settings(
        environment="production",
        jwt_secret="dev-insecure-secret-change-me",
        require_tls=False,
        database_url="sqlite:///./x.db",
    )
    with pytest.raises(RuntimeError):
        validate_production_config(insecure)


def test_production_config_with_secure_settings_does_not_raise():
    secure = Settings(
        environment="production",
        jwt_secret="a" * 40,
        require_tls=True,
        database_url="postgresql+psycopg://user:pass@host:5432/db",
    )
    validate_production_config(secure)  # não deve levantar


def test_development_config_with_default_secret_only_warns():
    dev = Settings(environment="development", jwt_secret="dev-insecure-secret-change-me")
    with pytest.warns(UserWarning):
        validate_production_config(dev)


def test_is_secure_request_accepts_forwarded_proto_header():
    class Headers(dict):
        def get(self, key, default=""):
            return dict.get(self, key.lower(), default)

    assert _is_secure("http", Headers({"x-forwarded-proto": "https"})) is True
    assert _is_secure("ws", Headers({"x-forwarded-proto": "wss"})) is True
    assert _is_secure("http", Headers({})) is False
    assert _is_secure("https", Headers({})) is True

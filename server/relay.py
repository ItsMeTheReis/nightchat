"""
relay.py — Endpoint WebSocket: autenticação, presença, descoberta de
usuários, encaminhamento de pedidos de conexão e roteamento do handshake
E2EE (Fase 4) e de mensagens de chat cifradas (Fase 5).

O relay só entende o envelope L1 (ver docs/ARCHITECTURE.md, seção 4).

HONESTIDADE DE ESCOPO (Fase 5): TYPE_RELAY (handshake) e
TYPE_ENCRYPTED_MESSAGE (chat) são roteados pela MESMA função
(`_route_opaque`), com a MESMA autorização por session_id. O relay nunca
decifra, nunca loga e nunca armazena `payload` em nenhum dos dois casos —
não existe, e nunca vai existir aqui, uma chave capaz de abrir o
ciphertext de uma mensagem. Isso é verificado explicitamente em
tests/test_phase5_relay_e2ee.py.

Autenticação do WebSocket (mudou nesta revisão): o JWT NÃO vai mais na
query string da URL (`?token=...`), porque query strings acabam em logs
de acesso (uvicorn, proxies, load balancers). O cliente conecta em
`/ws` sem parâmetros e manda o token como PRIMEIRA MENSAGEM:

    cliente -> {"type": "auth", "token": "<jwt>"}
    servidor -> {"type": "auth_result", "ok": true}   (ou ok:false + reason)

Ciclo de vida do banco: NÃO usamos `Depends(get_db)` aqui. Abrimos uma
sessão curta só para a checagem pontual do usuário no handshake e a
fechamos imediatamente — o WebSocket pode ficar aberto por horas, mas não
prende uma conexão do pool SQL por todo esse tempo.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from . import auth, sessions
from .database import SessionLocal
from .logging_conf import logger
from .models import User
from .presence import manager
from .ratelimit import FixedWindowLimiter
from .config import settings
from .validation import normalize_username

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared import protocol as proto

router = APIRouter()

AUTH_TIMEOUT_SECONDS = 10.0

# Rate limiting de operações de WebSocket já autenticadas (chave = username).
_connect_request_limiter = FixedWindowLimiter(
    settings.rate_limit_connect_request_max, settings.rate_limit_connect_request_window
)
_ws_message_limiter = FixedWindowLimiter(
    settings.rate_limit_ws_message_max, settings.rate_limit_ws_message_window
)


def _msg(msg_type: str, extra: dict | None = None) -> dict:
    d = {"v": proto.PROTOCOL_VERSION, "type": msg_type}
    if extra:
        d.update(extra)
    return d


def _is_secure(scheme: str, headers) -> bool:
    """Aceita conexão direta em TLS (wss/https) ou um proxy reverso
    confiável na frente que declara X-Forwarded-Proto. Ver server/config.py
    (require_tls) para a documentação completa desse trade-off."""
    if scheme in ("https", "wss"):
        return True
    forwarded = headers.get("x-forwarded-proto", "")
    return forwarded.split(",")[0].strip().lower() in ("https", "wss")


async def _authenticate(websocket: WebSocket) -> tuple[str, dict] | None:
    """Lê o frame de autenticação inicial. Retorna (username, claims) ou
    None (e já fecha o socket com um código apropriado) se falhar."""
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=AUTH_TIMEOUT_SECONDS)
    except (asyncio.TimeoutError, WebSocketDisconnect):
        await websocket.close(code=4401)
        return None

    try:
        first = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        await websocket.close(code=4401)
        return None

    if not isinstance(first, dict) or first.get("type") != proto.TYPE_AUTH:
        await websocket.close(code=4401)
        return None

    token = first.get("token")
    if not isinstance(token, str) or not token:
        await websocket.send_json(_msg(proto.TYPE_AUTH_RESULT, {"ok": False, "reason": "missing_token"}))
        await websocket.close(code=4401)
        return None

    claims = auth.decode_token_claims(token)
    if claims is None:
        logger.warning("ws auth failed reason=invalid_or_expired_token")
        await websocket.send_json(_msg(proto.TYPE_AUTH_RESULT, {"ok": False, "reason": "invalid_or_expired_token"}))
        await websocket.close(code=4401)
        return None

    username = claims.get("sub")
    if not isinstance(username, str) or not username:
        await websocket.close(code=4401)
        return None

    with SessionLocal() as db:
        user_exists = db.query(User).filter(User.username == username).first() is not None
    if not user_exists:
        logger.warning("ws auth failed reason=user_not_found")
        await websocket.send_json(_msg(proto.TYPE_AUTH_RESULT, {"ok": False, "reason": "user_not_found"}))
        await websocket.close(code=4401)
        return None

    await websocket.send_json(_msg(proto.TYPE_AUTH_RESULT, {"ok": True}))
    logger.info("authentication success user=%s channel=websocket", username)
    return username, claims


async def _expire_at(websocket: WebSocket, expires_at: float) -> None:
    """Fecha a conexão no instante em que o JWT expira, para que uma
    conexão longa não continue "autenticada para sempre" com um token
    vencido (ver docs no topo de server/auth.py)."""
    delay = max(0.0, expires_at - time.time())
    await asyncio.sleep(delay)
    try:
        await websocket.close(code=4401)
    except Exception:
        pass


@router.websocket("/ws")
async def ws_endpoint(websocket: WebSocket) -> None:
    if settings.require_tls and not _is_secure(websocket.url.scheme, websocket.headers):
        await websocket.close(code=4400)
        return

    await websocket.accept()

    result = await _authenticate(websocket)
    if result is None:
        return
    username, claims = result

    await manager.replace(username, websocket)

    others = [u for u in manager.online_usernames() if u != username]
    await websocket.send_json(_msg(proto.TYPE_USER_LIST, {"users": others}))
    await manager.broadcast(_msg(proto.TYPE_PRESENCE, {"from": username, "status": "online"}), exclude=username)

    expire_task = None
    exp = claims.get("exp")
    if isinstance(exp, (int, float)):
        expire_task = asyncio.create_task(_expire_at(websocket, float(exp)))

    try:
        while True:
            try:
                raw_text = await websocket.receive_text()
            except WebSocketDisconnect:
                break

            if not _ws_message_limiter.allow(username):
                logger.warning("rate limit triggered op=ws_message key=%s", username)
                await manager.send_to(username, _msg(proto.TYPE_ERROR, {"reason": "rate_limited"}))
                continue

            try:
                data = json.loads(raw_text)
            except (json.JSONDecodeError, ValueError):
                await manager.send_to(username, _msg(proto.TYPE_ERROR, {"reason": "invalid_json"}))
                continue

            try:
                await _handle_message(username, data)
            except Exception:  # nunca deixar uma mensagem derrubar a conexão
                logger.exception("unexpected error handling ws message from user=%s", username)
                await manager.send_to(username, _msg(proto.TYPE_ERROR, {"reason": "internal_error"}))
    finally:
        if expire_task is not None:
            expire_task.cancel()
        removed = manager.disconnect(username, websocket)
        if removed:
            sessions.clear_for_user(username)
            ended_sessions = sessions.clear_handshake_sessions_for_user(username)
            for session_id, other in ended_sessions:
                await manager.send_to(
                    other, _msg(proto.TYPE_SESSION_END, {"from": username, "session": session_id, "reason": "peer_disconnected"})
                )
            await manager.broadcast(_msg(proto.TYPE_PRESENCE, {"from": username, "status": "offline"}))
            logger.info("ws disconnected user=%s", username)


async def _handle_message(username: str, data: object) -> None:
    if not isinstance(data, dict):
        await manager.send_to(username, _msg(proto.TYPE_ERROR, {"reason": "invalid_message"}))
        return

    msg_type = data.get("type")
    if not isinstance(msg_type, str):
        await manager.send_to(username, _msg(proto.TYPE_ERROR, {"reason": "missing_type"}))
        return

    if msg_type == proto.TYPE_LIST_USERS:
        others = [u for u in manager.online_usernames() if u != username]
        await manager.send_to(username, _msg(proto.TYPE_USER_LIST, {"users": others}))
        return

    if msg_type == proto.TYPE_CONNECT_REQUEST:
        await _handle_connect_request(username, data)
        return

    if msg_type == proto.TYPE_CONNECT_RESPONSE:
        await _handle_connect_response(username, data)
        return

    if msg_type == proto.TYPE_RELAY:
        await _route_opaque(username, data, proto.TYPE_RELAY)
        return

    if msg_type == proto.TYPE_ENCRYPTED_MESSAGE:
        await _route_opaque(username, data, proto.TYPE_ENCRYPTED_MESSAGE)
        return

    if msg_type == proto.TYPE_SESSION_END:
        await _handle_session_end(username, data)
        return

    await manager.send_to(username, _msg(proto.TYPE_ERROR, {"reason": "unknown_type", "type": msg_type}))


async def _handle_connect_request(username: str, data: dict) -> None:
    target = data.get("to")
    if not isinstance(target, str) or not target:
        await manager.send_to(username, _msg(proto.TYPE_ERROR, {"reason": "missing_field", "field": "to"}))
        return

    target = normalize_username(target)
    if target == username:
        await manager.send_to(username, _msg(proto.TYPE_ERROR, {"reason": "invalid_target"}))
        return

    if not _connect_request_limiter.allow(username):
        logger.warning("rate limit triggered op=connect_request key=%s", username)
        await manager.send_to(username, _msg(proto.TYPE_ERROR, {"reason": "rate_limited"}))
        return

    if not sessions.add_request(requester=username, target=target):
        await manager.send_to(username, _msg(proto.TYPE_ERROR, {"reason": "too_many_pending_requests", "to": target}))
        return

    delivered = await manager.send_to(target, _msg(proto.TYPE_CONNECT_REQUEST, {"from": username}))
    if not delivered:
        sessions.pop_pending(target=target, expected_requester=username)
        await manager.send_to(username, _msg(proto.TYPE_ERROR, {"reason": "target_offline", "to": target}))


async def _handle_connect_response(username: str, data: dict) -> None:
    target = data.get("to")
    decision = data.get("payload")
    if not isinstance(target, str) or not target:
        await manager.send_to(username, _msg(proto.TYPE_ERROR, {"reason": "missing_field", "field": "to"}))
        return
    if decision not in (proto.CONNECT_ACCEPT, proto.CONNECT_DENY):
        await manager.send_to(username, _msg(proto.TYPE_ERROR, {"reason": "invalid_field", "field": "payload"}))
        return

    target = normalize_username(target)
    if not sessions.pop_pending(target=username, expected_requester=target):
        await manager.send_to(username, _msg(proto.TYPE_ERROR, {"reason": "no_pending_request"}))
        return

    extra = {"from": username, "payload": decision}
    session_id = None
    if decision == proto.CONNECT_ACCEPT:
        # Minta o session_id do handshake E2EE (Fase 4) aqui: só neste
        # ponto o relay sabe que os dois lados concordaram em conversar.
        # `target` é sempre o INICIADOR original (quem mandou o
        # connect_request); `username` é o RESPONDENTE (quem aceitou).
        session_id = sessions.create_handshake_session(initiator=target, responder=username)
        extra["session"] = session_id

    delivered = await manager.send_to(target, _msg(proto.TYPE_CONNECT_RESPONSE, extra))
    if not delivered:
        # O requerente desconectou entre o pedido e a resposta. B (quem
        # respondeu) precisa de um retorno coerente em vez de silêncio.
        if session_id is not None:
            sessions.end_handshake_session(session_id)
        await manager.send_to(username, _msg(proto.TYPE_ERROR, {"reason": "requester_offline", "to": target}))


async def _route_opaque(username: str, data: dict, msg_type: str) -> None:
    """
    Encaminha um payload OPACO — handshake (TYPE_RELAY, Fase 4) ou
    mensagem de chat cifrada (TYPE_ENCRYPTED_MESSAGE, Fase 5) — entre as
    duas partes de uma sessão já autorizada. Estruturalmente idêntico
    para os dois tipos: o relay nunca entende `payload` (nunca é
    decodificado, nunca é logado), só confere que `session_id` é uma
    sessão real e que `username` é de fato um dos dois participantes
    dela antes de rotear para o outro. Ver docs/ARCHITECTURE.md.
    """
    target = data.get("to")
    session_id = data.get("session")
    payload = data.get("payload")
    if not isinstance(target, str) or not target:
        await manager.send_to(username, _msg(proto.TYPE_ERROR, {"reason": "missing_field", "field": "to"}))
        return
    if not isinstance(session_id, str) or not session_id:
        await manager.send_to(username, _msg(proto.TYPE_ERROR, {"reason": "missing_field", "field": "session"}))
        return
    if not isinstance(payload, str) or not payload:
        await manager.send_to(username, _msg(proto.TYPE_ERROR, {"reason": "missing_field", "field": "payload"}))
        return

    target = normalize_username(target)
    expected_peer = sessions.other_party(session_id, username)
    if expected_peer is None or expected_peer != target:
        await manager.send_to(username, _msg(proto.TYPE_ERROR, {"reason": "unknown_session"}))
        return

    delivered = await manager.send_to(target, _msg(msg_type, {"from": username, "session": session_id, "payload": payload}))
    if not delivered:
        await manager.send_to(username, _msg(proto.TYPE_ERROR, {"reason": "target_offline", "to": target}))


async def _handle_session_end(username: str, data: dict) -> None:
    session_id = data.get("session")
    if not isinstance(session_id, str) or not session_id:
        await manager.send_to(username, _msg(proto.TYPE_ERROR, {"reason": "missing_field", "field": "session"}))
        return

    other = sessions.other_party(session_id, username)
    if other is None:
        await manager.send_to(username, _msg(proto.TYPE_ERROR, {"reason": "unknown_session"}))
        return

    sessions.end_handshake_session(session_id)
    await manager.send_to(other, _msg(proto.TYPE_SESSION_END, {"from": username, "session": session_id}))

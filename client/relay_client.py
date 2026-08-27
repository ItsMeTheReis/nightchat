"""
relay_client.py — Cliente de rede do NightChat (Fase 2).

Duas partes:
1. REST (síncrono, stdlib `urllib`): registro/login contra o relay.
2. WebSocket (assíncrono, `websockets`): conexão persistente que roda
   numa thread própria com seu próprio event loop, para que o shell do
   terminal (síncrono, baseado em `input()`) possa continuar bloqueando
   normalmente enquanto eventos do servidor (presença, pedidos de
   conexão) chegam em segundo plano via callbacks.

Autenticação do WebSocket (auditoria Fase 2): o JWT NÃO vai na URL. Depois
de conectar, o cliente manda `{"type": "auth", "token": "<jwt>"}` como
primeira mensagem e espera `{"type": "auth_result", "ok": true/false}`.

Resiliência a queda de conexão (auditoria Fase 2): se o relay cair depois
de uma conexão bem-sucedida, o cliente NÃO propaga a exceção para quem
chamou `send_connect_request`/`request_users`/etc. — `_send()` devolve
False e os métodos públicos degradam graciosamente (lista vazia, no-op).
Um callback `on_disconnected` avisa a UI. Uma rotina de reconexão com
backoff exponencial tenta um número limitado de vezes antes de desistir
(nunca cria threads/tarefas sem limite).

Este módulo NÃO sabe nada de criptografia E2EE — só transporta o
envelope L1 (ver docs/ARCHITECTURE.md, seção 4). `TYPE_RELAY` ainda não é
uma operação funcional (ver shared/protocol.py) — não implementado aqui.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

import websockets

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from shared import protocol as proto
else:
    from shared import protocol as proto

RECONNECT_BASE_DELAY = 1.0
RECONNECT_MAX_DELAY = 20.0
DEFAULT_RECONNECT_MAX_ATTEMPTS = 5


def _http_post(url: str, payload: dict) -> tuple[int, dict]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8"))
        except Exception:
            body = {"detail": str(e)}
        return e.code, body
    except urllib.error.URLError as e:
        return 0, {"detail": str(e.reason)}


def _http_get(url: str) -> tuple[int, dict]:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8"))
        except Exception:
            body = {}
        return e.code, body
    except urllib.error.URLError as e:
        return 0, {"detail": str(e.reason)}


def _http_put(url: str, payload: dict, token: str) -> tuple[int, dict]:
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
    req = urllib.request.Request(url, data=data, headers=headers, method="PUT")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8"))
        except Exception:
            body = {"detail": str(e)}
        return e.code, body
    except urllib.error.URLError as e:
        return 0, {"detail": str(e.reason)}


@dataclass
class RelayClient:
    http_base: str
    ws_base: str
    username: str
    token: str | None = None

    reconnect_max_attempts: int = DEFAULT_RECONNECT_MAX_ATTEMPTS
    reconnect_base_delay: float = RECONNECT_BASE_DELAY
    reconnect_max_delay: float = RECONNECT_MAX_DELAY

    on_incoming_request: Callable[[str], None] | None = None
    on_connect_result: Callable[[str, str, str | None], None] | None = None
    on_presence_update: Callable[[list[str]], None] | None = None
    on_error: Callable[[dict], None] | None = None
    on_disconnected: Callable[[str], None] | None = None
    on_reconnected: Callable[[], None] | None = None
    on_relay_message: Callable[[str, str, dict], None] | None = None  # (from, session_id, payload) — Fase 4
    on_session_end: Callable[[str, str], None] | None = None  # (from, session_id) — Fase 4
    on_encrypted_message: Callable[[str, str, str], None] | None = None  # (from, session_id, payload_b64) — Fase 5

    connected: bool = field(default=False, init=False)

    _ws: "websockets.WebSocketClientProtocol | None" = field(default=None, init=False, repr=False)
    _loop: asyncio.AbstractEventLoop | None = field(default=None, init=False, repr=False)
    _thread: threading.Thread | None = field(default=None, init=False, repr=False)
    _stop: threading.Event = field(default_factory=threading.Event, init=False, repr=False)
    _connected_evt: threading.Event = field(default_factory=threading.Event, init=False, repr=False)
    _connect_error: str | None = field(default=None, init=False, repr=False)
    _user_list_evt: threading.Event = field(default_factory=threading.Event, init=False, repr=False)
    _online_users: list[str] = field(default_factory=list, init=False, repr=False)

    # -- REST: registro/login -------------------------------------------------

    def exists(self, username: str) -> bool:
        status, body = _http_get(f"{self.http_base}/auth/exists?username={username}")
        return bool(body.get("exists")) if status == 200 else False

    def register(self, username: str, password: str) -> tuple[bool, str]:
        status, body = _http_post(f"{self.http_base}/auth/register", {"username": username, "password": password})
        if status == 201:
            self.token = body["token"]
            return True, ""
        return False, body.get("detail", f"HTTP {status}")

    def login(self, username: str, password: str) -> tuple[bool, str]:
        status, body = _http_post(f"{self.http_base}/auth/login", {"username": username, "password": password})
        if status == 200:
            self.token = body["token"]
            return True, ""
        return False, body.get("detail", f"HTTP {status}")

    # -- REST: identidade criptográfica (Fase 3) ------------------------------

    def publish_public_key(self, public_key_b64: str, signature_b64: str) -> tuple[bool, str]:
        """Requer estar autenticado (self.token). O servidor deriva o dono
        da chave do próprio JWT — não existe campo 'username' no corpo."""
        if not self.token:
            return False, "not authenticated (no token)"
        status, body = _http_put(
            f"{self.http_base}/users/me/public-key",
            {"public_key": public_key_b64, "signature": signature_b64},
            self.token,
        )
        if status == 200:
            return True, ""
        return False, body.get("detail", f"HTTP {status}")

    def get_public_key(self, username: str) -> tuple[bool, str | None, str]:
        """Retorna (ok, public_key_b64_ou_None, erro). public_key None com
        ok=True significa 'usuário existe mas nunca publicou uma chave'."""
        status, body = _http_get(f"{self.http_base}/users/{username}/public-key")
        if status == 200:
            return True, body.get("public_key"), ""
        if status == 404:
            return False, None, "user not found"
        return False, None, body.get("detail", f"HTTP {status}")

    # -- WebSocket: conexão persistente ---------------------------------------

    def connect_ws(self, timeout: float = 10.0) -> tuple[bool, str]:
        """Faz a PRIMEIRA tentativa de conexão (sem retry — erros aqui são
        reportados de volta ao fluxo de login). Se bem-sucedida, a thread
        de fundo continua rodando e passa a tentar reconectar sozinha caso
        a conexão caia depois."""
        if not self.token:
            return False, "not authenticated (no token)"
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        if not self._connected_evt.wait(timeout=timeout):
            return False, "timeout connecting to relay"
        if not self.connected:
            return False, self._connect_error or "failed to connect"
        return True, ""

    def _run_loop(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._main())
        finally:
            self._loop.close()

    async def _main(self) -> None:
        if not await self._connect_and_auth():
            self._connected_evt.set()
            return
        self.connected = True
        self._connected_evt.set()

        while not self._stop.is_set():
            await self._pump_until_closed()
            if self._stop.is_set():
                break
            self.connected = False
            self._notify_disconnected("connection lost")
            if not await self._reconnect_with_backoff():
                self._notify_disconnected("relay unavailable — giving up after retries")
                break

    async def _pump_until_closed(self) -> None:
        try:
            async for raw in self._ws:
                self._dispatch(json.loads(raw))
        except Exception:
            pass

    async def _reconnect_with_backoff(self) -> bool:
        for attempt in range(1, self.reconnect_max_attempts + 1):
            if self._stop.is_set():
                return False
            delay = min(self.reconnect_base_delay * (2 ** (attempt - 1)), self.reconnect_max_delay)
            await asyncio.sleep(delay)
            if self._stop.is_set():
                return False
            if await self._connect_and_auth():
                self.connected = True
                if self.on_reconnected:
                    self.on_reconnected()
                return True
        return False

    async def _connect_and_auth(self) -> bool:
        try:
            self._ws = await websockets.connect(self.ws_base, open_timeout=10)
        except Exception as e:  # noqa: BLE001 - reportado ao chamador via string
            self._connect_error = str(e)
            return False
        try:
            await self._ws.send(json.dumps({"v": proto.PROTOCOL_VERSION, "type": proto.TYPE_AUTH, "token": self.token}))
            raw = await asyncio.wait_for(self._ws.recv(), timeout=10)
            resp = json.loads(raw)
        except Exception as e:
            self._connect_error = f"auth handshake failed: {e}"
            await self._safe_close_ws()
            return False
        if not isinstance(resp, dict) or resp.get("type") != proto.TYPE_AUTH_RESULT or not resp.get("ok"):
            self._connect_error = resp.get("reason", "authentication rejected") if isinstance(resp, dict) else "bad auth response"
            await self._safe_close_ws()
            return False
        return True

    async def _safe_close_ws(self) -> None:
        try:
            if self._ws is not None:
                await self._ws.close()
        except Exception:
            pass

    def _notify_disconnected(self, reason: str) -> None:
        if self.on_disconnected:
            self.on_disconnected(reason)

    def _dispatch(self, data: dict) -> None:
        msg_type = data.get("type")
        if msg_type == proto.TYPE_USER_LIST:
            self._online_users = list(data.get("users", []))
            self._user_list_evt.set()
            if self.on_presence_update:
                self.on_presence_update(self._online_users)
        elif msg_type == proto.TYPE_PRESENCE:
            if self.on_presence_update:
                self.on_presence_update(self._online_users)
        elif msg_type == proto.TYPE_CONNECT_REQUEST:
            if self.on_incoming_request:
                self.on_incoming_request(data.get("from", "?"))
        elif msg_type == proto.TYPE_CONNECT_RESPONSE:
            if self.on_connect_result:
                self.on_connect_result(data.get("from", "?"), data.get("payload", ""), data.get("session"))
        elif msg_type == proto.TYPE_RELAY:
            if self.on_relay_message:
                from_user = data.get("from", "?")
                session_id = data.get("session", "")
                payload_b64 = data.get("payload", "")
                try:
                    payload = json.loads(base64.b64decode(payload_b64.encode("ascii")).decode("utf-8"))
                except Exception:
                    return
                if isinstance(payload, dict):
                    self.on_relay_message(from_user, session_id, payload)
        elif msg_type == proto.TYPE_SESSION_END:
            if self.on_session_end:
                self.on_session_end(data.get("from", "?"), data.get("session", ""))
        elif msg_type == proto.TYPE_ENCRYPTED_MESSAGE:
            if self.on_encrypted_message:
                # Ao contrário do handshake (JSON de controle), aqui o
                # payload é ciphertext de verdade — não decodificamos nada
                # aqui, só repassamos o base64 cru para a camada de chat
                # (client/chat.py) decidir se autentica ou rejeita.
                self.on_encrypted_message(data.get("from", "?"), data.get("session", ""), data.get("payload", ""))
        elif msg_type == proto.TYPE_ERROR:
            if self.on_error:
                self.on_error(data)

    def _send(self, obj: dict) -> bool:
        """Nunca propaga exceção — devolve False se não for possível
        entregar (desconectado, socket fechado, timeout etc.).

        Cuidado de concorrência (Fase 4): isto pode ser chamado de duas
        situações bem diferentes —
        1. da thread principal (shell/UI) reagindo a um comando do
           usuário — aí SIM precisamos atravessar para a thread do event
           loop com `run_coroutine_threadsafe` e esperar o resultado;
        2. de DENTRO da própria thread do event loop, reagindo
           SINCRONAMENTE a uma mensagem recebida (ex.: o handshake
           respondendo a um `handshake_init` assim que ele chega, dentro
           de `_dispatch`/`on_relay_message`). Nesse caso, `.result()`
           bloquearia o loop esperando por uma tarefa que só ele mesmo
           pode rodar — um autodeadlock que só se resolve pelo timeout de
           5s, sem exceção visível e sem o chamador nunca saber que a
           entrega falhou. Por isso detectamos esse caso (comparando o
           event loop "correndo agora" com o nosso) e, se for o mesmo,
           apenas AGENDAMOS o envio (`create_task`) em vez de esperar por
           ele — o loop processa assim que a chamada síncrona atual
           devolver o controle.
        """
        if not self.connected or not self._ws or not self._loop:
            return False
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None

        try:
            if running_loop is self._loop:
                self._loop.create_task(self._ws.send(json.dumps(obj)))
                return True
            fut = asyncio.run_coroutine_threadsafe(self._ws.send(json.dumps(obj)), self._loop)
            fut.result(timeout=5)
            return True
        except Exception:
            return False

    def request_users(self) -> list[str]:
        if not self.connected:
            return []
        self._user_list_evt.clear()
        if not self._send({"v": proto.PROTOCOL_VERSION, "type": proto.TYPE_LIST_USERS, "from": self.username}):
            return []
        self._user_list_evt.wait(timeout=5)
        return list(self._online_users)

    def send_connect_request(self, target: str) -> bool:
        return self._send(
            {"v": proto.PROTOCOL_VERSION, "type": proto.TYPE_CONNECT_REQUEST, "from": self.username, "to": target}
        )

    def send_connect_response(self, target: str, decision: str) -> bool:
        return self._send(
            {
                "v": proto.PROTOCOL_VERSION,
                "type": proto.TYPE_CONNECT_RESPONSE,
                "from": self.username,
                "to": target,
                "payload": decision,
            }
        )

    def send_relay(self, target: str, session_id: str, payload: dict) -> bool:
        """
        Transporte opaco do handshake (Fase 4): `payload` é um dict de
        controle do handshake (client/handshake.py), nunca interpretado
        pelo servidor — só serializado em JSON e depois em base64 antes
        de ir para o campo `payload` do envelope TYPE_RELAY.
        """
        payload_b64 = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
        return self._send(
            {
                "v": proto.PROTOCOL_VERSION,
                "type": proto.TYPE_RELAY,
                "from": self.username,
                "to": target,
                "session": session_id,
                "payload": payload_b64,
            }
        )

    def send_session_end(self, session_id: str) -> bool:
        """Não leva 'to': o relay determina a outra parte pelo próprio
        registro da sessão (server/sessions.py) — não confia num alvo
        declarado pelo cliente."""
        return self._send(
            {"v": proto.PROTOCOL_VERSION, "type": proto.TYPE_SESSION_END, "from": self.username, "session": session_id}
        )

    def send_encrypted_message(self, target: str, session_id: str, payload_b64: str) -> bool:
        """
        Transporte opaco de uma mensagem de chat cifrada (Fase 5).
        `payload_b64` já vem pronto de client/chat.py:encrypt_outgoing —
        este método NUNCA vê plaintext, só um blob base64 que ele copia
        para o envelope TYPE_ENCRYPTED_MESSAGE.
        """
        return self._send(
            {
                "v": proto.PROTOCOL_VERSION,
                "type": proto.TYPE_ENCRYPTED_MESSAGE,
                "from": self.username,
                "to": target,
                "session": session_id,
                "payload": payload_b64,
            }
        )

    def close(self) -> None:
        self._stop.set()
        if self._ws and self._loop and not self._loop.is_closed():
            try:
                asyncio.run_coroutine_threadsafe(self._ws.close(), self._loop).result(timeout=5)
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        self.connected = False

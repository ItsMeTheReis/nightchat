"""
Testes de resiliência de conexão do RelayClient (auditoria Fase 2, item 8):
- o cliente não deve crashar quando o relay cai;
- deve reportar um estado de desconexão via callback;
- deve tentar reconectar com backoff, um número LIMITADO de vezes;
- `_send()`/`request_users()` devem degradar graciosamente (não levantar)
  quando desconectado.

Usa um servidor WebSocket "de mentira" (biblioteca `websockets`, já uma
dependência do projeto) que fala só o suficiente do protocolo de
autenticação (`auth` -> `auth_result`) para exercitar o RelayClient de
verdade, sem precisar subir o FastAPI/uvicorn inteiro.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time

import pytest
import websockets

from client.relay_client import RelayClient
from shared import protocol as proto


class FakeRelayServer:
    """Servidor WS mínimo: aceita, autentica sempre com sucesso, e depois
    pode ser instruído a fechar a conexão para simular a queda do relay."""

    def __init__(self) -> None:
        self.port: int | None = None
        self._server = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self.drop_after_auth = False
        self.refuse_new_connections = False

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=5)

    def _run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._serve())

    async def _serve(self) -> None:
        self._server = await websockets.serve(self._handler, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        self._ready.set()
        await self._server.wait_closed()

    async def _handler(self, ws) -> None:
        if self.refuse_new_connections:
            await ws.close()
            return
        try:
            raw = await ws.recv()
            data = json.loads(raw)
            assert data["type"] == proto.TYPE_AUTH
            await ws.send(json.dumps({"v": proto.PROTOCOL_VERSION, "type": proto.TYPE_AUTH_RESULT, "ok": True}))
            if self.drop_after_auth:
                await ws.close()
                return
            async for _ in ws:
                pass
        except websockets.exceptions.ConnectionClosed:
            pass

    def stop(self) -> None:
        if self._loop and self._server:
            self._loop.call_soon_threadsafe(self._server.close)
        if self._thread:
            self._thread.join(timeout=5)


@pytest.fixture()
def fake_server():
    server = FakeRelayServer()
    server.start()
    yield server
    server.stop()


def _fast_client(ws_base: str) -> RelayClient:
    return RelayClient(
        http_base="http://unused.invalid",
        ws_base=ws_base,
        username="morningstar",
        token="fake-token",
        reconnect_max_attempts=2,
        reconnect_base_delay=0.05,
        reconnect_max_delay=0.1,
    )


def test_connect_ws_succeeds_against_fake_server(fake_server: FakeRelayServer):
    client = _fast_client(f"ws://127.0.0.1:{fake_server.port}")
    try:
        ok, err = client.connect_ws(timeout=5)
        assert ok is True, err
        assert client.connected is True
    finally:
        client.close()


def test_client_does_not_crash_when_relay_drops_connection(fake_server: FakeRelayServer):
    """Depois que o relay derruba a conexão, chamar os métodos públicos não
    deve levantar exceção — devem degradar graciosamente."""
    client = _fast_client(f"ws://127.0.0.1:{fake_server.port}")
    try:
        ok, _ = client.connect_ws(timeout=5)
        assert ok is True

        # impede reconexão automática para observar o estado "desconectado"
        # de forma determinística (sem correr contra o backoff)
        fake_server.refuse_new_connections = True
        assert client._ws is not None
        asyncio.run_coroutine_threadsafe(client._ws.close(), client._loop).result(timeout=5)

        # dá tempo do loop de fundo perceber a queda
        time.sleep(0.3)

        # nada aqui deve levantar exceção, mesmo desconectado
        assert client.send_connect_request("sofia") is False
        assert client.send_connect_response("sofia", "accept") is False
        assert client.request_users() == []
    finally:
        client.close()


def test_disconnected_callback_fires_on_connection_loss(fake_server: FakeRelayServer):
    events: list[str] = []
    client = _fast_client(f"ws://127.0.0.1:{fake_server.port}")
    client.on_disconnected = lambda reason: events.append(reason)
    try:
        ok, _ = client.connect_ws(timeout=5)
        assert ok is True

        assert client._ws is not None
        asyncio.run_coroutine_threadsafe(client._ws.close(), client._loop).result(timeout=5)

        deadline = time.monotonic() + 3
        while not events and time.monotonic() < deadline:
            time.sleep(0.05)

        assert events, "on_disconnected nunca foi chamado"
    finally:
        client.close()


def test_reconnect_gives_up_after_bounded_attempts_and_notifies(fake_server: FakeRelayServer):
    """Se o relay cai e NUNCA mais volta, o cliente tenta reconectar um
    número limitado de vezes e desiste — nunca fica tentando pra sempre,
    nunca cria threads sem limite (só a thread original é usada)."""
    events: list[str] = []
    client = _fast_client(f"ws://127.0.0.1:{fake_server.port}")
    client.on_disconnected = lambda reason: events.append(reason)
    try:
        ok, _ = client.connect_ws(timeout=5)
        assert ok is True

        thread_at_connect = client._thread
        fake_server.refuse_new_connections = True  # próximas tentativas de reconexão falham
        assert client._ws is not None
        asyncio.run_coroutine_threadsafe(client._ws.close(), client._loop).result(timeout=5)

        # espera o ciclo completo: perde conexão -> tenta reconectar N vezes -> desiste
        deadline = time.monotonic() + 5
        while len(events) < 2 and time.monotonic() < deadline:
            time.sleep(0.05)

        assert len(events) == 2, f"esperava 2 notificações (perdeu + desistiu), veio {events}"
        assert client.connected is False
        # a MESMA thread original é quem fez tudo — nenhuma thread nova por tentativa
        assert client._thread is thread_at_connect
        assert not client._thread.is_alive()  # a thread termina, não fica pendurada
    finally:
        client.close()


def test_first_connection_attempt_does_not_retry_on_failure():
    """A primeira tentativa (usada no fluxo de login) falha imediatamente
    se não houver servidor nenhum — sem ficar tentando de novo sozinha
    (retry só existe DEPOIS de uma conexão bem-sucedida cair)."""
    client = RelayClient(
        http_base="http://unused.invalid",
        ws_base="ws://127.0.0.1:1",  # porta que ninguém escuta
        username="morningstar",
        token="fake-token",
        reconnect_max_attempts=2,
        reconnect_base_delay=0.05,
    )
    try:
        start = time.monotonic()
        ok, err = client.connect_ws(timeout=5)
        elapsed = time.monotonic() - start
        assert ok is False
        assert err
        assert elapsed < 4  # não esperou por nenhum backoff de retry
        assert client.connected is False
    finally:
        client.close()


def test_send_methods_return_false_before_any_connection():
    """Chamar os métodos de envio antes de qualquer connect_ws() não deve
    levantar exceção."""
    client = RelayClient(http_base="http://unused.invalid", ws_base="ws://127.0.0.1:1", username="morningstar")
    assert client.send_connect_request("sofia") is False
    assert client.send_connect_response("sofia", "accept") is False
    assert client.request_users() == []

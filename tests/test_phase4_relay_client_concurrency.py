"""
Regressão de concorrência (Fase 4): reagir a uma mensagem recebida
enviando outra mensagem, DE DENTRO do callback de despacho do
RelayClient, não pode travar.

Isso é exatamente o que client/handshake.py faz o tempo todo: ao receber
um `handshake_init`, o respondente monta e ENVIA um `handshake_response`
de volta, tudo dentro do callback `on_relay_message` — que roda na
mesma thread do event loop de fundo do RelayClient (ver `_dispatch` em
client/relay_client.py). Uma implementação ingênua de `_send()` (sempre
`run_coroutine_threadsafe(...).result()`) faz o loop tentar agendar uma
tarefa nele mesmo enquanto está bloqueado esperando por ela — um
autodeadlock que só "resolve" via timeout de 5s, devolvendo False sem
nenhum erro visível. Este teste teria pego esse bug antes de ele só
aparecer num teste end-to-end contra um servidor de verdade.

Usa um servidor WebSocket "de mentira" mínimo (só autentica e encaminha
por 'to'), com DOIS RelayClient de verdade (threads/event loops reais) —
diferente de tests/test_phase4_handshake.py (rede em memória, sem
asyncio) e tests/test_phase4_relay.py (TestClient síncrono, sem o
RelayClient real).
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


class FakeForwardingServer:
    """Autentica qualquer token como o próprio texto do token (username =
    token, só para este teste) e encaminha TYPE_RELAY por 'to'."""

    def __init__(self) -> None:
        self.port: int | None = None
        self._server = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._clients: dict[str, "websockets.WebSocketServerProtocol"] = {}

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
        username: str | None = None
        try:
            raw = await ws.recv()
            data = json.loads(raw)
            assert data["type"] == proto.TYPE_AUTH
            username = data["token"]
            self._clients[username] = ws
            await ws.send(json.dumps({"v": proto.PROTOCOL_VERSION, "type": proto.TYPE_AUTH_RESULT, "ok": True}))

            async for raw_msg in ws:
                msg = json.loads(raw_msg)
                if msg.get("type") == proto.TYPE_RELAY:
                    target = msg.get("to")
                    target_ws = self._clients.get(target)
                    if target_ws is not None:
                        await target_ws.send(
                            json.dumps(
                                {
                                    "v": proto.PROTOCOL_VERSION,
                                    "type": proto.TYPE_RELAY,
                                    "from": username,
                                    "session": msg.get("session"),
                                    "payload": msg.get("payload"),
                                }
                            )
                        )
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            if username is not None:
                self._clients.pop(username, None)

    def stop(self) -> None:
        if self._loop and self._server:
            self._loop.call_soon_threadsafe(self._server.close)
        if self._thread:
            self._thread.join(timeout=5)


@pytest.fixture()
def fake_server():
    server = FakeForwardingServer()
    server.start()
    yield server
    server.stop()


def _client(fake_server, username: str) -> RelayClient:
    c = RelayClient(http_base="http://unused.invalid", ws_base=f"ws://127.0.0.1:{fake_server.port}", username=username, token=username)
    ok, err = c.connect_ws(timeout=5)
    assert ok, err
    return c


def test_reactive_send_from_within_dispatch_callback_does_not_deadlock(fake_server):
    """B recebe um TYPE_RELAY de A e, DENTRO do próprio callback de
    recebimento, manda outro TYPE_RELAY de volta para A — isso não pode
    travar nem falhar silenciosamente."""
    a = _client(fake_server, "morningstar")
    b = _client(fake_server, "sofia")
    try:
        received_by_a = []
        received_by_b = []

        def on_b_receives(frm, session_id, payload):
            received_by_b.append(payload)
            # reage IMEDIATAMENTE, de dentro do callback (mesma thread do
            # event loop de b) — é exatamente isso que trava sem o fix.
            ok = b.send_relay("morningstar", session_id, {"reply": True})
            assert ok is True

        a.on_relay_message = lambda frm, sid, payload: received_by_a.append(payload)
        b.on_relay_message = on_b_receives

        sent = a.send_relay("sofia", "session-1", {"hello": True})
        assert sent is True

        deadline = time.monotonic() + 3
        while not received_by_a and time.monotonic() < deadline:
            time.sleep(0.05)

        assert received_by_b == [{"hello": True}]
        assert received_by_a == [{"reply": True}], "resposta reativa nunca chegou — provável autodeadlock em _send()"
    finally:
        a.close()
        b.close()


def test_reactive_send_completes_quickly_not_via_5s_timeout(fake_server):
    """Além de eventualmente chegar, a resposta reativa precisa ser
    RÁPIDA — se estiver caindo no autodeadlock, o retorno de send_relay()
    ainda seria True (o bug é silencioso), mas só depois de ~5s de
    bloqueio interno. Medimos que o round-trip todo é bem mais rápido
    que isso."""
    a = _client(fake_server, "morningstar2")
    b = _client(fake_server, "sofia2")
    try:
        arrived = threading.Event()

        def on_b_receives(frm, session_id, payload):
            b.send_relay("morningstar2", session_id, {"reply": True})

        def on_a_receives(frm, session_id, payload):
            arrived.set()

        a.on_relay_message = on_a_receives
        b.on_relay_message = on_b_receives

        start = time.monotonic()
        a.send_relay("sofia2", "session-2", {"hello": True})
        got_it = arrived.wait(timeout=3)
        elapsed = time.monotonic() - start

        assert got_it, "resposta reativa nunca chegou"
        assert elapsed < 2.0, f"round-trip levou {elapsed:.2f}s — sinal de autodeadlock no _send() reativo"
    finally:
        a.close()
        b.close()

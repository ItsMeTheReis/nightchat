"""
handshake.py — Handshake X25519 efêmero autenticado por Ed25519 (STS
simplificado), Fase 4. Ver shared/handshake.py para o formato exato das
mensagens e docs/ARCHITECTURE.md seção 4.4 para o desenho.

Produz uma `SessionState` (client/session.py) por par de usuários — NÃO
cifra/decifra mensagens (isso é Fase 5).

Este módulo é framework-agnostic (não sabe de WebSocket nem de asyncio):
`send_relay` e `fetch_public_key` são injetados pelo chamador
(normalmente client/relay_client.py). Isso torna a máquina de estados
testável sem rede real.

Resistência (ver docs no topo de shared/handshake.py e o relatório da
Fase 4 para a análise completa):
- MITM / alteração de transcript: qualquer chave efêmera ou campo do
  transcript adulterado em trânsito invalida a assinatura verificada do
  outro lado.
- Replay: o transcript inclui o session_id (mintado uma única vez pelo
  relay no accept, ver server/sessions.py) — uma assinatura de uma sessão
  não serve para outra. Mensagens repetidas na MESMA sessão são
  descartadas pela máquina de estados assim que ela sai do dicionário de
  pendentes (ESTABLISHED ou FAILED).
- Mensagens fora de ordem: cada handler de fase confere o papel e o
  estado atual da sessão antes de processar; qualquer mensagem que não
  bata é silenciosamente descartada (nunca derruba nada).
- Timeout: cada handshake pendente tem um prazo (`threading.Timer`,
  padrão 15s); se não concluir a tempo, é abortado e removido.
"""

from __future__ import annotations

import base64
import threading
from dataclasses import dataclass, field
from typing import Callable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import crypto, x25519
from .crypto_identity import CryptographicIdentity
from .session import SessionState

import os
import sys

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared import handshake as hs

DEFAULT_TIMEOUT_SECONDS = 15.0

_STATE_WAITING_RESPONSE = "waiting_response"  # initiator: mandou init, espera response
_STATE_WAITING_CONFIRM = "waiting_confirm"  # responder: mandou response, espera confirm


def _hkdf(shared_secret: bytes, info: bytes, length: int = 32) -> bytes:
    """REGRA DO PROJETO: nunca implementar KDF na mão — usamos
    `cryptography.hazmat...HKDF` (HKDF-SHA256, RFC 5869)."""
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(shared_secret)


def _derive_directional_keys(shared_secret: bytes, local_username: str, peer_username: str) -> tuple[bytes, bytes]:
    k_send = _hkdf(shared_secret, hs.hkdf_info(local_username, peer_username))
    k_recv = _hkdf(shared_secret, hs.hkdf_info(peer_username, local_username))
    return k_send, k_recv


def _b64decode(value: object) -> bytes | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception:
        return None


@dataclass
class _PendingHandshake:
    session_id: str
    peer: str
    role: str  # "initiator" | "responder"
    state: str
    eph_private: bytes
    eph_public: bytes
    peer_eph_public: bytes | None = None
    timer: threading.Timer | None = None


class HandshakeManager:
    """
    Orquestra handshakes concorrentes (um por session_id). Callbacks
    `on_established`/`on_failed` são chamados de qualquer thread que
    entregar mensagens (normalmente a thread de fundo do RelayClient) —
    quem registrar esses callbacks deve ser thread-safe (ver client/main.py,
    que só faz prints e escreve em connection_state-like registries com lock).
    """

    def __init__(
        self,
        identity: CryptographicIdentity,
        send_relay: Callable[[str, str, dict], bool],
        fetch_public_key: Callable[[str], bytes | None],
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._identity = identity
        self._send_relay = send_relay
        self._fetch_public_key = fetch_public_key
        self._timeout_seconds = timeout_seconds
        self._lock = threading.Lock()
        self._sessions: dict[str, _PendingHandshake] = {}

        self.on_established: Callable[[SessionState], None] | None = None
        self.on_failed: Callable[[str, str, str], None] | None = None  # (session_id, peer, reason)

    # -- API pública -----------------------------------------------------

    def initiate(self, peer: str, session_id: str) -> None:
        """Chamado pelo INICIADOR (quem mandou o connect_request original)
        assim que recebe a confirmação de accept com um session_id."""
        eph_private, eph_public = x25519.generate_ephemeral_keypair()
        pending = _PendingHandshake(
            session_id=session_id,
            peer=peer,
            role="initiator",
            state=_STATE_WAITING_RESPONSE,
            eph_private=eph_private,
            eph_public=eph_public,
        )
        with self._lock:
            self._sessions[session_id] = pending
        self._arm_timeout(pending)
        self._send_relay(peer, session_id, {"kind": hs.KIND_INIT, "eph_pub": crypto.encode_public_key(eph_public)})

    def handle_message(self, from_user: str, session_id: str, payload: dict) -> None:
        if not isinstance(payload, dict):
            return
        kind = payload.get("kind")
        if kind == hs.KIND_INIT:
            self._handle_init(from_user, session_id, payload)
        elif kind == hs.KIND_RESPONSE:
            self._handle_response(from_user, session_id, payload)
        elif kind == hs.KIND_CONFIRM:
            self._handle_confirm(from_user, session_id, payload)
        # kind desconhecido/ausente: ignora silenciosamente — nunca derruba a conexão.

    def abort(self, session_id: str, reason: str = "aborted") -> None:
        with self._lock:
            pending = self._sessions.pop(session_id, None)
        if pending is None:
            return
        self._cancel_timer(pending)
        if self.on_failed:
            self.on_failed(session_id, pending.peer, reason)

    def pending_session_ids(self) -> list[str]:
        with self._lock:
            return list(self._sessions.keys())

    # -- Fases -------------------------------------------------------------

    def _handle_init(self, from_user: str, session_id: str, payload: dict) -> None:
        with self._lock:
            if session_id in self._sessions:
                return  # duplicado/replay de um init já visto — ignora

        eph_initiator_pub = _b64decode(payload.get("eph_pub"))
        if not x25519.is_valid_public_point(eph_initiator_pub):
            return  # mensagem malformada/maliciosa — ignora, não derruba nada

        eph_private, eph_public = x25519.generate_ephemeral_keypair()
        pending = _PendingHandshake(
            session_id=session_id,
            peer=from_user,
            role="responder",
            state=_STATE_WAITING_CONFIRM,
            eph_private=eph_private,
            eph_public=eph_public,
            peer_eph_public=eph_initiator_pub,
        )
        with self._lock:
            if session_id in self._sessions:
                return  # corrida rara: outra init para o mesmo id já processada
            self._sessions[session_id] = pending
        self._arm_timeout(pending)

        transcript = hs.transcript(session_id, from_user, self._identity.username, eph_initiator_pub, eph_public)
        signature = self._identity.sign(transcript)
        self._send_relay(
            from_user,
            session_id,
            {
                "kind": hs.KIND_RESPONSE,
                "eph_pub": crypto.encode_public_key(eph_public),
                "signature": base64.b64encode(signature).decode("ascii"),
            },
        )

    def _handle_response(self, from_user: str, session_id: str, payload: dict) -> None:
        pending = self._get(session_id)
        if pending is None or pending.role != "initiator" or pending.state != _STATE_WAITING_RESPONSE or pending.peer != from_user:
            return  # sessão desconhecida, papel errado, fase errada ou remetente errado

        eph_responder_pub = _b64decode(payload.get("eph_pub"))
        signature = _b64decode(payload.get("signature"))
        if not x25519.is_valid_public_point(eph_responder_pub) or signature is None:
            self._fail(pending, "malformed_response")
            return

        peer_identity_key = self._fetch_public_key(from_user)
        if peer_identity_key is None:
            self._fail(pending, "peer_identity_unavailable")
            return

        transcript = hs.transcript(session_id, self._identity.username, from_user, pending.eph_public, eph_responder_pub)
        if not crypto.verify(peer_identity_key, transcript, signature):
            self._fail(pending, "signature_verification_failed")
            return

        try:
            shared_secret = x25519.compute_shared_secret(pending.eph_private, eph_responder_pub)
        except ValueError:
            self._fail(pending, "degenerate_shared_secret")
            return

        k_send, k_recv = _derive_directional_keys(shared_secret, self._identity.username, from_user)
        session_state = SessionState(session_id=session_id, peer_username=from_user, k_send=k_send, k_recv=k_recv)

        my_signature = self._identity.sign(transcript)
        self._send_relay(
            from_user,
            session_id,
            {"kind": hs.KIND_CONFIRM, "signature": base64.b64encode(my_signature).decode("ascii")},
        )

        self._finish(pending, session_state)

    def _handle_confirm(self, from_user: str, session_id: str, payload: dict) -> None:
        pending = self._get(session_id)
        if pending is None or pending.role != "responder" or pending.state != _STATE_WAITING_CONFIRM or pending.peer != from_user:
            return

        signature = _b64decode(payload.get("signature"))
        if signature is None:
            self._fail(pending, "malformed_confirm")
            return

        peer_identity_key = self._fetch_public_key(from_user)
        if peer_identity_key is None:
            self._fail(pending, "peer_identity_unavailable")
            return

        transcript = hs.transcript(session_id, from_user, self._identity.username, pending.peer_eph_public, pending.eph_public)
        if not crypto.verify(peer_identity_key, transcript, signature):
            self._fail(pending, "signature_verification_failed")
            return

        try:
            shared_secret = x25519.compute_shared_secret(pending.eph_private, pending.peer_eph_public)
        except ValueError:
            self._fail(pending, "degenerate_shared_secret")
            return

        k_send, k_recv = _derive_directional_keys(shared_secret, self._identity.username, from_user)
        session_state = SessionState(session_id=session_id, peer_username=from_user, k_send=k_send, k_recv=k_recv)

        self._finish(pending, session_state)

    # -- Helpers -------------------------------------------------------------

    def _get(self, session_id: str) -> _PendingHandshake | None:
        with self._lock:
            return self._sessions.get(session_id)

    def _arm_timeout(self, pending: _PendingHandshake) -> None:
        timer = threading.Timer(self._timeout_seconds, self._on_timeout, args=(pending.session_id,))
        timer.daemon = True
        pending.timer = timer
        timer.start()

    def _cancel_timer(self, pending: _PendingHandshake) -> None:
        if pending.timer is not None:
            pending.timer.cancel()

    def _on_timeout(self, session_id: str) -> None:
        with self._lock:
            pending = self._sessions.pop(session_id, None)
        if pending is None:
            return
        if self.on_failed:
            self.on_failed(session_id, pending.peer, "timeout")

    def _fail(self, pending: _PendingHandshake, reason: str) -> None:
        with self._lock:
            self._sessions.pop(pending.session_id, None)
        self._cancel_timer(pending)
        if self.on_failed:
            self.on_failed(pending.session_id, pending.peer, reason)

    def _finish(self, pending: _PendingHandshake, session_state: SessionState) -> None:
        self._cancel_timer(pending)
        with self._lock:
            self._sessions.pop(pending.session_id, None)
        if self.on_established:
            self.on_established(session_state)

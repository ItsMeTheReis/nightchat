"""
chat.py — Camada de mensagens cifradas (Fase 5).

Usa uma `SessionState` já estabelecida (Fase 4, client/session.py) para
cifrar/decifrar mensagens de chat com XChaCha20-Poly1305
(client/aead.py) + anti-replay por contador monotônico. Isto é TUDO que
roda no cliente — o relay nunca vê nada além do envelope opaco
(`TYPE_ENCRYPTED_MESSAGE`, roteado por session_id, ver server/relay.py).
Nunca chega perto de plaintext, chave de sessão, segredo compartilhado
ou chave privada.

Formato do frame (ver shared/messaging.py): um JSON `{"counter": int,
"ciphertext": "<base64>"}`, ele mesmo base64-codificado para caber no
campo `payload` do envelope L1 — o mesmo padrão já usado pelo handshake
da Fase 4 (client/relay_client.py:send_relay).
"""

from __future__ import annotations

import base64
import json
import os
import sys

from . import aead
from .session import SessionState

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared import messaging


class ReplayError(Exception):
    """Contador repetido, retrocedido, ou já visto para esta sessão —
    a mensagem NÃO foi decifrada nem aceita."""


class WrongSessionError(Exception):
    """O envelope recebido não corresponde a esta SessionState (session_id
    ou remetente diferentes) — nunca decifra com a chave/sessão errada."""


def encrypt_outgoing(session: SessionState, local_username: str, plaintext: str) -> str:
    """
    Cifra `plaintext` para enviar a `session.peer_username`. Incrementa
    `session.send_counter` (nunca reusa um contador, mesmo que o envio
    falhe depois — reenviar é uma mensagem NOVA, não um reenvio do
    mesmo contador). Retorna o payload pronto para o campo 'payload' do
    envelope L1 (base64 de um JSON com counter+ciphertext).
    """
    session.send_counter += 1
    counter = session.send_counter
    aad = messaging.message_aad(session.session_id, counter, local_username)
    ciphertext = aead.encrypt(session.k_send, counter, aad, plaintext.encode("utf-8"))
    frame = {"counter": counter, "ciphertext": base64.b64encode(ciphertext).decode("ascii")}
    return base64.b64encode(json.dumps(frame).encode("utf-8")).decode("ascii")


def decrypt_incoming(session: SessionState, envelope_session_id: str, sender_username: str, payload_b64: str) -> str:
    """
    Decifra um payload recebido para `session`. Levanta:
    - `WrongSessionError` se o session_id do envelope ou o remetente não
      correspondem a esta SessionState;
    - `ReplayError` se o contador já foi visto ou retrocedeu;
    - `aead.DecryptionError` se a autenticação AEAD falhar (ciphertext
      adulterado, contador adulterado, ou chave incorreta — o AEAD não
      distingue essas causas, de propósito).

    `session.recv_counter` SÓ avança em caso de sucesso completo — uma
    tentativa que falhe (replay, adulteração) não move o estado.
    """
    if envelope_session_id != session.session_id or sender_username != session.peer_username:
        raise WrongSessionError(
            f"mensagem não pertence a esta sessão (esperava session={session.session_id!r} "
            f"peer={session.peer_username!r}, recebeu session={envelope_session_id!r} from={sender_username!r})"
        )

    try:
        frame = json.loads(base64.b64decode(payload_b64.encode("ascii")).decode("utf-8"))
    except Exception as e:
        raise aead.DecryptionError("payload malformado") from e

    if not isinstance(frame, dict):
        raise aead.DecryptionError("payload malformado")

    counter = frame.get("counter")
    ciphertext_b64 = frame.get("ciphertext")
    if not isinstance(counter, int) or isinstance(counter, bool) or not isinstance(ciphertext_b64, str):
        raise aead.DecryptionError("payload malformado")

    if counter <= session.recv_counter:
        raise ReplayError(f"contador {counter} <= último aceito {session.recv_counter}")

    try:
        ciphertext = base64.b64decode(ciphertext_b64.encode("ascii"), validate=True)
    except Exception as e:
        raise aead.DecryptionError("ciphertext base64 inválido") from e

    aad = messaging.message_aad(session.session_id, counter, sender_username)
    plaintext = aead.decrypt(session.k_recv, counter, aad, ciphertext)

    session.recv_counter = counter  # só avança depois de autenticar com sucesso
    return plaintext.decode("utf-8")

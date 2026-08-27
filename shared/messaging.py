"""
shared/messaging.py — Contrato do envelope de mensagem cifrada (Fase 5).

Só o formato dos dados autenticados (associated data) do AEAD — a cifra
em si (XChaCha20-Poly1305) e as chaves ficam inteiramente no cliente
(client/aead.py, client/chat.py). O relay nunca vê nada definido aqui
além do envelope opaco já existente (ver server/relay.py).

Formato do quadro (frame) que vai, cifrado, dentro do payload opaco de
TYPE_ENCRYPTED_MESSAGE:

    {"counter": <int>, "ciphertext": "<base64 de nonce-implícito + tag>"}

O nonce XChaCha20 (24 bytes) NUNCA é transmitido — é derivado
deterministicamente do `counter` (ver client/aead.py:derive_nonce), que
por sua vez é autenticado como associated data (AAD) do AEAD. Como a
chave (`k_send`/`k_recv`, Fase 4) já é única por sessão E por direção,
um `counter` que nunca se repete (garantido pelo anti-replay, ver
client/chat.py) garante que o par (chave, nonce) nunca se repete —
condição necessária para a segurança do XChaCha20-Poly1305.

O AAD amarra o ciphertext a exatamente esta sessão, este contador e este
remetente — adulterar qualquer um desses campos em trânsito invalida a
tag de autenticação do AEAD, mesmo que o ciphertext em si não seja
tocado.
"""

from __future__ import annotations

from .wire import len_prefixed

MESSAGE_VERSION = "v1"


def message_aad(session_id: str, counter: int, sender: str) -> bytes:
    """Dados associados autenticados (mas não cifrados) de uma mensagem —
    amarram o ciphertext à sessão, ao contador e a quem enviou."""
    return len_prefixed(
        f"nightchat-message:{MESSAGE_VERSION}".encode("utf-8"),
        session_id.encode("utf-8"),
        counter.to_bytes(8, "big"),
        sender.encode("utf-8"),
    )

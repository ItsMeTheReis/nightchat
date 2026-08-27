"""
session.py — Estado de uma sessão segura estabelecida (Fase 4).

Guarda o `session_id` e as chaves de sessão (k_send/k_recv) derivadas por
HKDF-SHA256 após o handshake X25519/STS (client/handshake.py) ter sido
concluído e autenticado com sucesso.

Este módulo continua sendo só o ESTADO — cifrar/decifrar mensagens
(AEAD XChaCha20-Poly1305 + anti-replay usando `send_counter`/
`recv_counter`) é responsabilidade de client/chat.py (Fase 5), para
manter esta classe simples e sem lógica criptográfica própria.

As chaves de sessão nunca são persistidas em disco, nunca vão para logs,
nunca são enviadas a lugar nenhum — vivem só na memória do processo,
pela duração da sessão (ver client/active_sessions.py para o registro em
memória de sessões estabelecidas).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SessionState:
    session_id: str
    peer_username: str
    k_send: bytes  # chave para cifrar mensagens ENVIADAS a peer_username (Fase 5)
    k_recv: bytes  # chave para decifrar mensagens RECEBIDAS de peer_username (Fase 5)
    send_counter: int = 0  # reservado para o anti-replay da Fase 5 (ainda não usado)
    recv_counter: int = -1  # idem

    def __repr__(self) -> str:  # nunca inclui as chaves de sessão
        return f"SessionState(session_id={self.session_id!r}, peer={self.peer_username!r})"

"""
active_sessions.py — Registro em memória de SessionState estabelecidas
(Fase 4).

Fase 5 vai usar isso para cifrar/decifrar mensagens de chat. Nesta fase,
só guardamos o estado (chaves de sessão) por username de par — nunca em
disco, nunca fora do processo.
"""

from __future__ import annotations

import threading

from .session import SessionState

_lock = threading.Lock()
_by_peer: dict[str, SessionState] = {}


def store(session: SessionState) -> None:
    with _lock:
        _by_peer[session.peer_username] = session


def get(peer_username: str) -> SessionState | None:
    with _lock:
        return _by_peer.get(peer_username)


def remove(peer_username: str) -> None:
    with _lock:
        _by_peer.pop(peer_username, None)


def list_peers() -> list[str]:
    with _lock:
        return list(_by_peer.keys())


def reset() -> None:
    """Usado por testes para isolar estado entre casos."""
    with _lock:
        _by_peer.clear()

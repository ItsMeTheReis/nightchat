"""
chat_state.py — Rastreia com qual peer o shell está em modo `chat` agora
(Fase 5). Serve só para a UI decidir qual prompt reimprimir quando um
evento assíncrono (mensagem recebida, pedido de conexão, etc.) chega
enquanto o usuário está bloqueado num `input()` — nenhum dado de sessão
ou chave vive aqui.
"""

from __future__ import annotations

import threading

_lock = threading.Lock()
_active_peer: str | None = None


def enter(peer: str) -> None:
    global _active_peer
    with _lock:
        _active_peer = peer


def leave() -> None:
    global _active_peer
    with _lock:
        _active_peer = None


def current() -> str | None:
    with _lock:
        return _active_peer


def reset() -> None:
    """Usado por testes para isolar estado entre casos."""
    leave()

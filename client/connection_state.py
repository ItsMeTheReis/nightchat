"""
connection_state.py — Estado efêmero de pedidos de conexão (Fase 2/3).

Guarda só QUEM pediu conexão e PARA QUEM pedimos. Nenhum material
criptográfico vive aqui — isso é o transporte que antecede o handshake
E2EE (Fase 4+). Protegido por lock porque eventos chegam de uma thread
de rede em segundo plano enquanto o shell principal roda em outra.

Suporta MÚLTIPLOS pedidos de entrada pendentes ao mesmo tempo (fila FIFO):
se A e depois B pedem conexão a C antes de C responder a qualquer um dos
dois, C precisa ver os dois pedidos — o segundo não pode sobrescrever o
primeiro silenciosamente (auditoria Fase 2).
"""

from __future__ import annotations

import threading
from collections import deque

_lock = threading.Lock()
_incoming: deque[str] = deque()
_outgoing_to: str | None = None


def push_incoming(username: str) -> None:
    with _lock:
        if username not in _incoming:
            _incoming.append(username)


def pop_incoming(target: str | None = None) -> str | None:
    """
    Remove e retorna um pedido pendente.
    - Se `target` for dado, remove esse username específico (ex.: `accept
      "sofia"` quando há mais de um pedido pendente).
    - Senão, remove o mais antigo da fila (FIFO) — o `accept`/`deny`
      simples continua funcionando exatamente como antes quando só há um
      pedido pendente.
    """
    with _lock:
        if not _incoming:
            return None
        if target is None:
            return _incoming.popleft()
        if target in _incoming:
            _incoming.remove(target)
            return target
        return None


def list_incoming() -> list[str]:
    with _lock:
        return list(_incoming)


def set_outgoing(username: str) -> None:
    global _outgoing_to
    with _lock:
        _outgoing_to = username


def pop_outgoing() -> str | None:
    global _outgoing_to
    with _lock:
        value = _outgoing_to
        _outgoing_to = None
        return value


def reset() -> None:
    """Usado por testes para isolar estado entre casos."""
    global _outgoing_to
    with _lock:
        _incoming.clear()
        _outgoing_to = None

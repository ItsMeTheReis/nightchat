"""
ratelimit.py — Rate limiting simples, em memória, janela fixa.

Propositalmente pequeno: sem dependência nova, sem algoritmo sofisticado
(token bucket, sliding log distribuído). Um `FixedWindowLimiter` por
operação sensível, chave é IP (endpoints REST não-autenticados) ou
username (operações de WebSocket já autenticadas).

Limitação conhecida (a mesma de server/presence.py e server/sessions.py):
isto é estado em memória de UM processo. Com `uvicorn --workers N>1` ou
múltiplas réplicas, cada processo tem seus próprios contadores — o limite
efetivo vira "limite x número de processos". Não é distribuído. Ver
docs/ARCHITECTURE.md, seção de escalabilidade.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque


class FixedWindowLimiter:
    def __init__(self, max_events: int, window_seconds: float) -> None:
        self.max_events = max_events
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        q = self._hits[key]
        while q and now - q[0] > self.window_seconds:
            q.popleft()
        if len(q) >= self.max_events:
            return False
        q.append(now)
        return True

    def reset(self) -> None:
        """Usado por testes para isolar estado entre casos."""
        self._hits.clear()

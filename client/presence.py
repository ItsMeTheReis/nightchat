"""
presence.py — Presença online/offline.

Fase 2: consulta o relay de verdade através do RelayClient conectado
(ver relay_client.py). A interface pública (online_users()) é a mesma
da Fase 1, então a UI (commands.py) não precisou mudar para usar dados
reais em vez de mock.
"""

from __future__ import annotations

from dataclasses import dataclass

_client = None  # relay_client.RelayClient | None — setado por main.py após login


@dataclass
class Peer:
    username: str
    online: bool = True


def set_client(client) -> None:
    global _client
    _client = client


def online_users(exclude: str | None = None) -> list[Peer]:
    if _client is None:
        return []
    usernames = _client.request_users()
    return [Peer(u, True) for u in usernames if u != exclude]


def is_mock() -> bool:
    """Fase 1 era sempre mock. A partir da Fase 2, só é mock sem relay conectado."""
    return _client is None

"""
shared/wire.py — Codificação canônica sem ambiguidade, usada em qualquer
lugar que precise concatenar campos de tamanho variável antes de assinar
ou autenticar (handshake da Fase 4, dados associados do AEAD da Fase 5).

Extraído de shared/handshake.py para não duplicar a mesma lógica quando
shared/messaging.py (Fase 5) precisou dela também.
"""

from __future__ import annotations


def len_prefixed(*parts: bytes) -> bytes:
    """Concatena campos com prefixo de tamanho (4 bytes big-endian) —
    elimina qualquer ambiguidade de concatenação (ex.: "ab"+"cd" seria
    igual a "a"+"bcd" numa concatenação ingênua; aqui não)."""
    out = bytearray()
    for part in parts:
        out += len(part).to_bytes(4, "big")
        out += part
    return bytes(out)

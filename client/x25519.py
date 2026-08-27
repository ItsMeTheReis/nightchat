"""
x25519.py — Primitivas do acordo de chave efêmero X25519 (Fase 4).

Via PyNaCl (libsodium), usando as primitivas de baixo nível
`crypto_scalarmult`/`crypto_scalarmult_base` para obter o segredo
compartilhado CRU — o protocolo do NightChat faz sua PRÓPRIA derivação
via HKDF-SHA256 (ver shared/handshake.py e client/handshake.py), não a
derivação HSalsa20 que `nacl.public.Box` faria por baixo dos panos se a
usássemos.

REGRA DO PROJETO: nunca implementar curva elíptica na mão — aqui só
chamamos a implementação do libsodium (que já faz a "clamping" de chave
exigida pela RFC 7748 internamente).

Proteção contra chave de baixa ordem (defensivo, além do handshake em
si): o libsodium recusa (`RuntimeError`) calcular um segredo compartilhado
que resulte em todos-zeros — o resultado clássico de um atacante mandar
um ponto de ordem baixa como chave pública efêmera. `compute_shared_secret`
converte isso num `ValueError` claro; `is_valid_public_point` já rejeita
de cara o ponto todo-zero antes de tentar.
"""

from __future__ import annotations

import os

from nacl.bindings import crypto_scalarmult, crypto_scalarmult_base

X25519_KEY_BYTES = 32
_ALL_ZERO_POINT = b"\x00" * X25519_KEY_BYTES


def generate_ephemeral_keypair() -> tuple[bytes, bytes]:
    """Gera um par X25519 efêmero. Retorna (private_scalar, public_point)."""
    private_scalar = os.urandom(X25519_KEY_BYTES)
    public_point = crypto_scalarmult_base(private_scalar)
    return private_scalar, public_point


def is_valid_public_point(raw: bytes | None) -> bool:
    if raw is None or len(raw) != X25519_KEY_BYTES:
        return False
    return raw != _ALL_ZERO_POINT


def compute_shared_secret(private_scalar: bytes, peer_public_point: bytes) -> bytes:
    """ECDH: retorna o segredo compartilhado cru (32 bytes) — NUNCA use
    isto diretamente como chave de sessão; sempre passe por HKDF antes
    (ver client/handshake.py)."""
    try:
        secret = crypto_scalarmult(private_scalar, peer_public_point)
    except RuntimeError as e:
        raise ValueError("segredo compartilhado degenerado (ponto de ordem baixa?)") from e
    if secret == _ALL_ZERO_POINT:
        raise ValueError("segredo compartilhado degenerado (ponto de ordem baixa?)")
    return secret

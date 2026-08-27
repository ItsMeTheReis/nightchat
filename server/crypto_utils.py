"""
crypto_utils.py — Verificação de assinaturas Ed25519 no servidor (Fase 3).

O relay NUNCA gera, guarda ou usa uma chave PRIVADA — ele só verifica
assinaturas com a chave PÚBLICA que o próprio cliente está tentando
registrar, como prova de posse (ver PUT /users/me/public-key em
server/main.py). Regra do projeto: nunca implementar Ed25519 na mão —
aqui só usamos PyNaCl.
"""

from __future__ import annotations

import base64

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

ED25519_PUBLIC_KEY_BYTES = 32


def decode_b64(value: str) -> bytes | None:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception:
        return None


def is_valid_ed25519_public_key(raw: bytes | None) -> bool:
    return raw is not None and len(raw) == ED25519_PUBLIC_KEY_BYTES


def verify_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        VerifyKey(public_key).verify(message, signature)
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False

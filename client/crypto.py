"""
crypto.py — Wrappers criptográficos de IDENTIDADE (Fase 3).

Só Ed25519 (par de chaves, assinar, verificar, fingerprint) via PyNaCl
(libsodium). REGRA DO PROJETO: nunca implementar primitivas criptográficas
na mão — este módulo só compõe funções prontas da biblioteca.

O que NÃO está aqui (fica para Fase 4/5, ver docs/ARCHITECTURE.md):
handshake X25519 efêmero, HKDF, cifra AEAD (XChaCha20-Poly1305),
anti-replay. Fase 3 é só identidade — nenhum canal de mensagens
criptografado é estabelecido aqui.
"""

from __future__ import annotations

import base64
import hashlib

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

ED25519_PUBLIC_KEY_BYTES = 32
ED25519_PRIVATE_KEY_BYTES = 32  # seed usado por SigningKey


def generate_keypair() -> tuple[bytes, bytes]:
    """Gera um novo par Ed25519. Retorna (private_key_seed, public_key)."""
    signing_key = SigningKey.generate()
    return bytes(signing_key), bytes(signing_key.verify_key)


def public_key_from_private(private_key: bytes) -> bytes:
    return bytes(SigningKey(private_key).verify_key)


def sign(private_key: bytes, message: bytes) -> bytes:
    return SigningKey(private_key).sign(message).signature


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        VerifyKey(public_key).verify(message, signature)
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False


def fingerprint(public_key: bytes) -> str:
    """
    Fingerprint humano-legível de uma identidade: SHA-256 da chave
    pública Ed25519 crua, em hex maiúsculo, formatado em blocos de 4
    caracteres para leitura/comparação (estilo 'safety number').

    Determinístico e derivado SOMENTE da chave pública — nunca do
    username, de um identificador aleatório, timestamp ou qualquer dado
    pessoal. Dois clientes que possuem a mesma chave pública sempre
    calculam o mesmo fingerprint, de forma independente.
    """
    digest = hashlib.sha256(public_key).hexdigest().upper()
    blocks = [digest[i : i + 4] for i in range(0, len(digest), 4)]
    return " ".join(blocks)


def encode_public_key(public_key: bytes) -> str:
    return base64.b64encode(public_key).decode("ascii")


def decode_public_key(encoded: str) -> bytes | None:
    try:
        raw = base64.b64decode(encoded.encode("ascii"), validate=True)
    except Exception:
        return None
    return raw if len(raw) == ED25519_PUBLIC_KEY_BYTES else None

"""
Testes de client/aead.py — XChaCha20-Poly1305 (Fase 5), a primitiva
crua usada por client/chat.py. Cobre encrypt/decrypt, chave errada,
ciphertext adulterado, AAD adulterado e nonce determinístico por contador.
"""

from __future__ import annotations

import pytest

from client import aead


def _key(byte: int = 0x11) -> bytes:
    return bytes([byte]) * aead.KEY_BYTES


def test_encrypt_decrypt_round_trip():
    key = _key()
    ciphertext = aead.encrypt(key, 1, b"aad", b"hello world")
    plaintext = aead.decrypt(key, 1, b"aad", ciphertext)
    assert plaintext == b"hello world"


def test_ciphertext_is_not_plaintext():
    key = _key()
    ciphertext = aead.encrypt(key, 1, b"aad", b"super secret message")
    assert b"super secret message" not in ciphertext


def test_wrong_key_fails():
    ciphertext = aead.encrypt(_key(0x11), 1, b"aad", b"hello")
    with pytest.raises(aead.DecryptionError):
        aead.decrypt(_key(0x22), 1, b"aad", ciphertext)


def test_tampered_ciphertext_fails():
    key = _key()
    ciphertext = bytearray(aead.encrypt(key, 1, b"aad", b"hello"))
    ciphertext[0] ^= 0xFF
    with pytest.raises(aead.DecryptionError):
        aead.decrypt(key, 1, b"aad", bytes(ciphertext))


def test_tampered_tag_fails():
    """O tag Poly1305 fica nos últimos 16 bytes — adulterar só o tag
    (sem tocar no corpo do ciphertext) também precisa falhar."""
    key = _key()
    ciphertext = bytearray(aead.encrypt(key, 1, b"aad", b"hello"))
    ciphertext[-1] ^= 0xFF
    with pytest.raises(aead.DecryptionError):
        aead.decrypt(key, 1, b"aad", bytes(ciphertext))


def test_tampered_aad_fails():
    key = _key()
    ciphertext = aead.encrypt(key, 1, b"aad-original", b"hello")
    with pytest.raises(aead.DecryptionError):
        aead.decrypt(key, 1, b"aad-diferente", ciphertext)


def test_wrong_counter_changes_nonce_and_fails():
    """O nonce é derivado do contador — decifrar com um contador
    diferente do usado para cifrar usa um nonce errado e falha."""
    key = _key()
    ciphertext = aead.encrypt(key, 5, b"aad", b"hello")
    with pytest.raises(aead.DecryptionError):
        aead.decrypt(key, 6, b"aad", ciphertext)


def test_nonce_is_deterministic_per_counter():
    assert aead.derive_nonce(42) == aead.derive_nonce(42)
    assert aead.derive_nonce(42) != aead.derive_nonce(43)
    assert len(aead.derive_nonce(1)) == aead.NONCE_BYTES


def test_same_plaintext_different_counter_yields_different_ciphertext():
    """Nonces diferentes (contadores diferentes) nunca podem produzir o
    mesmo ciphertext para o mesmo plaintext — checagem básica de que o
    nonce realmente varia com o contador."""
    key = _key()
    ct1 = aead.encrypt(key, 1, b"aad", b"same message")
    ct2 = aead.encrypt(key, 2, b"aad", b"same message")
    assert ct1 != ct2


def test_wrong_key_length_is_rejected():
    with pytest.raises(ValueError):
        aead.encrypt(b"too-short", 1, b"aad", b"hello")
    with pytest.raises(ValueError):
        aead.decrypt(b"too-short", 1, b"aad", b"whatever-ciphertext-bytes")

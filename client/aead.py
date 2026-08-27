"""
aead.py — Cifra autenticada de mensagem: XChaCha20-Poly1305 (Fase 5).

Via PyNaCl (libsodium), usando a primitiva combinada de baixo nível
`crypto_aead_xchacha20poly1305_ietf_encrypt/decrypt` (construção IETF,
nonce de 24 bytes, tag de 16 bytes anexada ao ciphertext). REGRA DO
PROJETO: nunca implementar AEAD na mão — isto só compõe a função pronta
do libsodium.

O nonce NUNCA é aleatório aqui — é derivado deterministicamente do
`counter` da mensagem (ver `derive_nonce`), que por sua vez é garantido
monotônico/nunca repetido pelo anti-replay de client/chat.py. Como a
chave (k_send/k_recv, Fase 4) já é única por sessão e por direção, isso
garante que o par (chave, nonce) nunca se repete — é essa combinação, e
não a aleatoriedade do nonce, que dá a segurança do XChaCha20-Poly1305
aqui. Ver shared/messaging.py para o formato do dado associado (AAD).
"""

from __future__ import annotations

from nacl import bindings
from nacl.exceptions import CryptoError

KEY_BYTES = bindings.crypto_aead_xchacha20poly1305_ietf_KEYBYTES
NONCE_BYTES = bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
TAG_BYTES = bindings.crypto_aead_xchacha20poly1305_ietf_ABYTES


class DecryptionError(Exception):
    """Falha de autenticação do AEAD — ciphertext adulterado, chave
    errada, ou AAD (sessão/contador/remetente) não corresponde. O AEAD
    não distingue essas causas — e não deveria: revelar qual delas
    ocorreu ajudaria um atacante a calibrar tentativas."""


def derive_nonce(counter: int) -> bytes:
    """Nonce de 24 bytes derivado do contador da mensagem — nunca
    transmitido, nunca aleatório. Determinístico: o par (chave, nonce)
    só é seguro reusar-se-nunca porque o contador nunca se repete
    (garantido pelo anti-replay, não por este módulo)."""
    return counter.to_bytes(NONCE_BYTES, "big")


def encrypt(key: bytes, counter: int, aad: bytes, plaintext: bytes) -> bytes:
    if len(key) != KEY_BYTES:
        raise ValueError(f"chave precisa ter {KEY_BYTES} bytes")
    nonce = derive_nonce(counter)
    return bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)


def decrypt(key: bytes, counter: int, aad: bytes, ciphertext: bytes) -> bytes:
    if len(key) != KEY_BYTES:
        raise ValueError(f"chave precisa ter {KEY_BYTES} bytes")
    nonce = derive_nonce(counter)
    try:
        return bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, aad, nonce, key)
    except (CryptoError, ValueError, TypeError) as e:
        raise DecryptionError("falha na autenticação AEAD (ciphertext adulterado, chave ou AAD incorretos)") from e

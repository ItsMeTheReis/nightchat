"""
crypto_identity.py — Identidade criptográfica local (Fase 3).

Une o par de chaves Ed25519 (client/crypto.py, PyNaCl) com o
armazenamento local da chave privada (client/identity_store.py) numa
única abstração: `CryptographicIdentity`.

A chave privada nunca é exposta como atributo público (nada de
`identity.private_key`) — só através de `identity.sign(mensagem)`. Isso
não é uma garantia de segurança de memória (Python não oferece isso, ver
docs/ARCHITECTURE.md seção 6), mas evita que o resto do código acidente
serialize/logue/envie a chave privada por engano.
"""

from __future__ import annotations

from . import crypto
from . import identity_store as store


class CryptographicIdentity:
    def __init__(self, username: str, private_key: bytes, public_key: bytes) -> None:
        self.username = username
        self.__private_key = private_key
        self.__public_key = public_key

    def public_key_bytes(self) -> bytes:
        return self.__public_key

    def public_key_b64(self) -> str:
        return crypto.encode_public_key(self.__public_key)

    def sign(self, message: bytes) -> bytes:
        return crypto.sign(self.__private_key, message)

    def fingerprint(self) -> str:
        return crypto.fingerprint(self.__public_key)

    def __repr__(self) -> str:  # nunca inclui a chave privada
        return f"CryptographicIdentity(username={self.username!r}, fingerprint={self.fingerprint()!r})"


def load_or_create(
    username: str, identity_store: store.IdentityStore | None = None
) -> tuple[CryptographicIdentity, bool]:
    """
    Carrega a identidade Ed25519 local de `username`, ou gera uma nova se
    não existir. Retorna (identidade, criada_agora) — `criada_agora` é
    True só na primeira vez que essa identidade é gerada para este
    username, para a UI poder mostrar "Generating..." vs "Loading...".
    """
    st = identity_store or store.get_default_store()
    existing = st.load(username)
    if existing is not None:
        public_key = crypto.public_key_from_private(existing)
        return CryptographicIdentity(username, existing, public_key), False

    private_key, public_key = crypto.generate_keypair()
    st.save(username, private_key)
    return CryptographicIdentity(username, private_key, public_key), True

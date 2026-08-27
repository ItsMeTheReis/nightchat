"""
identity.py — Identidade local e armazenamento de credenciais (Fase 1).

Nesta fase NÃO há servidor. A identidade e a credencial vivem localmente,
em ~/.nightchat/credentials.json, para você testar o fluxo de login real
(criação de conta na primeira execução, verificação nas próximas).

Segurança da senha nesta fase:
- A senha NUNCA é gravada em texto puro.
- Guardamos apenas: scrypt(senha, salt) + o salt + os parâmetros.
- scrypt (stdlib hashlib) é um KDF memory-hard legítimo.
- Comparação em tempo constante (hmac.compare_digest) contra timing attacks.

Limitação honesta (documentada em docs/ARCHITECTURE.md):
- Na Fase 4 trocamos scrypt por Argon2id e movemos a autenticação para o relay.
- O 'identity_id' aqui é um identificador local aleatório; a identidade
  criptográfica real (par Ed25519) entra na Fase 4.
"""

from __future__ import annotations

import os
import json
import hmac
import base64
import hashlib
import secrets
from dataclasses import dataclass
from pathlib import Path

# Parâmetros do scrypt. N deve ser potência de 2.
# (N=2**15, r=8, p=1) ~ configuração equilibrada para desktop.
_SCRYPT_N = 2 ** 15
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SALT_BYTES = 16

_STORE_VERSION = 1


def _store_dir() -> Path:
    return Path.home() / ".nightchat"


def _store_file() -> Path:
    return _store_dir() / "credentials.json"


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _derive(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
        # scrypt usa ~128*N*r bytes; damos folga para não estourar o limite.
        maxmem=132 * _SCRYPT_N * _SCRYPT_R,
    )


@dataclass
class Identity:
    username: str
    identity_id: str  # id local aleatório (placeholder até Ed25519 na Fase 4)

    def fingerprint(self) -> str:
        """
        Fingerprint legível (estilo 'safety number').
        Na Fase 1 é derivado do identity_id local; na Fase 4 passa a ser
        derivado da chave pública Ed25519 real.
        """
        digest = hashlib.sha256(
            (self.username + ":" + self.identity_id).encode("utf-8")
        ).hexdigest().upper()
        # Formata em blocos de 4 para leitura/comparação humana.
        blocks = [digest[i:i + 4] for i in range(0, 40, 4)]
        return " ".join(blocks)


# ---------------------------------------------------------------------------
# Persistência
# ---------------------------------------------------------------------------

def store_exists() -> bool:
    return _store_file().exists()


def load_store() -> dict | None:
    if not store_exists():
        return None
    try:
        return json.loads(_store_file().read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _write_store(data: dict) -> None:
    d = _store_dir()
    d.mkdir(parents=True, exist_ok=True)
    path = _store_file()
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    # Restringe permissões onde o SO suporta (POSIX). No Windows é no-op.
    try:
        os.chmod(path, 0o600)
    except (OSError, NotImplementedError):
        pass


def create_account(username: str, password: str) -> Identity:
    """Cria a conta local na primeira execução."""
    salt = secrets.token_bytes(_SALT_BYTES)
    derived = _derive(password, salt)
    identity_id = secrets.token_hex(16)
    data = {
        "version": _STORE_VERSION,
        "username": username,
        "identity_id": identity_id,
        "kdf": {
            "algorithm": "scrypt",
            "n": _SCRYPT_N,
            "r": _SCRYPT_R,
            "p": _SCRYPT_P,
            "dklen": _SCRYPT_DKLEN,
            "salt": _b64e(salt),
        },
        "verifier": _b64e(derived),
    }
    _write_store(data)
    return Identity(username=username, identity_id=identity_id)


# ---------------------------------------------------------------------------
# Identidade local por usuário (Fase 2+)
# ---------------------------------------------------------------------------
# A partir da Fase 2, a SENHA é verificada pelo relay (Argon2id), não mais
# localmente. O que ainda mantemos localmente é só um identity_id estável
# por usuário (placeholder até o par Ed25519 real da Fase 4), para o
# /fingerprint continuar funcionando. Arquivo por username porque dois
# usuários de teste (morningstar, sofia) podem rodar na mesma máquina.

def _identity_id_file(username: str) -> Path:
    return _store_dir() / f"identity_{username}.json"


def get_or_create_identity_id(username: str) -> str:
    path = _identity_id_file(username)
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            existing = data.get("identity_id")
            if existing:
                return existing
        except (json.JSONDecodeError, OSError, KeyError):
            pass
    identity_id = secrets.token_hex(16)
    _store_dir().mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"username": username, "identity_id": identity_id}), encoding="utf-8")
    return identity_id


def verify_password(password: str) -> Identity | None:
    """Verifica a senha contra o verifier armazenado (tempo constante)."""
    data = load_store()
    if not data:
        return None
    try:
        salt = _b64d(data["kdf"]["salt"])
        expected = _b64d(data["verifier"])
    except (KeyError, ValueError):
        return None
    candidate = _derive(password, salt)
    if hmac.compare_digest(candidate, expected):
        return Identity(
            username=data["username"],
            identity_id=data.get("identity_id", ""),
        )
    return None

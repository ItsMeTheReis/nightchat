"""
auth.py — Hash de senha (Argon2id) e tokens de sessão (JWT).

Argon2id é usado exatamente como o ARCHITECTURE.md manda para esta fase:
memory-hard, custo configurável via .env, nunca guardamos a senha em si.
O JWT é só um token de sessão de curta duração para autorizar a conexão
WebSocket depois do login — não carrega nenhum segredo de longo prazo.

Ciclo de vida do JWT (documentado explicitamente, auditoria Fase 2):
- `exp` é validado em TODO novo handshake (REST login e primeira mensagem
  do WebSocket) — um token expirado nunca autentica nada novo.
- Uma conexão WebSocket já autenticada NÃO é revalidada a cada mensagem,
  mas o relay agenda o fechamento automático do socket exatamente no
  instante em que o token expira (ver server/relay.py) — não existe
  conexão "eternamente autenticada" com um token vencido.
- Não há revogação antecipada (ex.: logout forçado, troca de senha
  invalidando tokens antigos) nesta fase. Isso é aceitável porque o TTL é
  curto (padrão 15 min) e fica registrado aqui como limitação conhecida,
  não escondida.
"""

from __future__ import annotations

import time

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from jose import JWTError, jwt

from .config import settings

_hasher = PasswordHasher(
    time_cost=settings.argon2_time_cost,
    memory_cost=settings.argon2_memory_cost,
    parallelism=settings.argon2_parallelism,
)

# Hash Argon2id de uma senha fixa, gerado uma vez no import. Usado para
# "queimar" o mesmo custo de CPU/memória quando o username não existe,
# fechando o canal lateral de tempo entre "usuário não existe" e "usuário
# existe, senha errada" (ver verify_password_or_dummy).
DUMMY_HASH = _hasher.hash("nightchat-dummy-password-for-timing-safety")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def verify_password_or_dummy(password: str, password_hash: str | None) -> bool:
    """
    Sempre executa uma verificação Argon2id de verdade, mesmo quando o
    usuário não existe (password_hash=None) — contra o hash "dummy" fixo.
    Isso elimina o curto-circuito óbvio (`user is None or verify(...)`)
    que fazia usernames inexistentes responderem muito mais rápido que
    usernames existentes com senha errada, vazando por tempo quais
    usernames têm conta. Quando password_hash é None, o retorno é sempre
    False, independentemente do resultado da verificação contra o dummy.
    """
    if password_hash is None:
        verify_password(password, DUMMY_HASH)
        return False
    return verify_password(password, password_hash)


def create_token(username: str) -> str:
    payload = {"sub": username, "exp": time.time() + settings.jwt_ttl_seconds}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token_claims(token: str) -> dict | None:
    """Retorna o payload completo do token (inclui 'exp'), ou None se inválido/expirado."""
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except JWTError:
        return None


def decode_token(token: str) -> str | None:
    """Retorna o username ('sub') do token, ou None se inválido/expirado."""
    claims = decode_token_claims(token)
    return claims.get("sub") if claims else None

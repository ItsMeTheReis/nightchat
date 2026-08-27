"""
deps.py — Dependências FastAPI compartilhadas.

Fase 2 não precisava disto: login/register/exists são anônimos, e a
autenticação do WebSocket usa o padrão de primeira mensagem (ver
server/relay.py). Fase 3 introduz o primeiro endpoint REST que exige
autenticação (`PUT /users/me/public-key`), daí esta dependência: extrai o
username autenticado do header `Authorization: Bearer <jwt>` — nunca de
um campo enviado pelo cliente no corpo da requisição.
"""

from __future__ import annotations

from fastapi import Header, HTTPException, status

from . import auth


def get_authenticated_username(authorization: str | None = Header(default=None)) -> str:
    if not authorization:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing authorization header")

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid authorization header")

    username = auth.decode_token(token)
    if username is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid or expired token")
    return username

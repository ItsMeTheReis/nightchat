"""
main.py — Entrypoint do NightChat Relay (Fase 2 + Fase 3: identidade Ed25519).

Rodar:
    uvicorn server.main:app --reload
ou:
    python -m server.main

Endpoints REST (autenticação):
    POST /auth/register  {username, password} -> {token, username}
    POST /auth/login     {username, password} -> {token, username}
    GET  /auth/exists?username=...            -> {exists: bool}
    GET  /health                              -> {status: "ok"}

Endpoints REST (identidade criptográfica — Fase 3):
    PUT /users/me/public-key  (Authorization: Bearer <jwt>)
        {public_key, signature} -> {username, public_key}
        Publica a chave pública Ed25519 do usuário AUTENTICADO. Exige uma
        assinatura Ed25519 (com a chave privada correspondente) sobre
        shared.identity.key_binding_message(username, public_key) como
        prova de posse — ver server/crypto_utils.py.
    GET /users/{username}/public-key -> {username, public_key | null}
        Público (chave pública é informação pública por natureza),
        rate-limited como /auth/exists.

WebSocket (presença + roteamento de controle):
    GET /ws   — autenticação pela PRIMEIRA MENSAGEM, não pela URL
                (ver server/relay.py: {"type": "auth", "token": "<jwt>"})

Sobre TLS: quando NIGHTCHAT_REQUIRE_TLS=true, requisições HTTP e handshakes
de WebSocket que não chegarem como https/wss (direto ou via
X-Forwarded-Proto de um proxy confiável) são recusados. Em dev, ws:///http://
puro são aceitos — ver server/config.py.
"""

from __future__ import annotations

import os
import sys
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import auth, crypto_utils
from .config import settings
from .database import get_db, init_db
from .deps import get_authenticated_username
from .logging_conf import configure_logging, logger
from .models import User
from .ratelimit import FixedWindowLimiter
from .relay import router as relay_router
from .relay import _is_secure
from .schemas import (
    ExistsResponse,
    LoginRequest,
    PublicKeyRequest,
    PublicKeyResponse,
    RegisterRequest,
    TokenResponse,
)
from .validation import normalize_username

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared import identity as shared_identity

_register_limiter = FixedWindowLimiter(settings.rate_limit_register_max, settings.rate_limit_register_window)
_login_limiter = FixedWindowLimiter(settings.rate_limit_login_max, settings.rate_limit_login_window)
_exists_limiter = FixedWindowLimiter(settings.rate_limit_exists_max, settings.rate_limit_exists_window)


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    configure_logging(settings.log_level)
    init_db()
    logger.info("NightChat Relay iniciado (env=%s)", settings.environment)
    yield
    logger.info("NightChat Relay finalizado")


app = FastAPI(title="NightChat Relay", version="phase-3", lifespan=_lifespan)
app.include_router(relay_router)


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@app.middleware("http")
async def _enforce_tls(request: Request, call_next):
    if settings.require_tls and not _is_secure(request.url.scheme, request.headers):
        return JSONResponse({"detail": "TLS required"}, status_code=400)
    return await call_next(request)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/auth/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(req: RegisterRequest, request: Request, db: Session = Depends(get_db)) -> TokenResponse:
    client_key = _client_key(request)
    if not _register_limiter.allow(client_key):
        logger.warning("rate limit triggered op=register key=%s", client_key)
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="too many registration attempts")

    existing = db.query(User).filter(User.username == req.username).first()
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="username already exists")

    user = User(username=req.username, password_hash=auth.hash_password(req.password))
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="username already exists")

    token = auth.create_token(user.username)
    logger.info("account registered user=%s", user.username)
    return TokenResponse(token=token, username=user.username)


@app.post("/auth/login", response_model=TokenResponse)
def login(req: LoginRequest, request: Request, db: Session = Depends(get_db)) -> TokenResponse:
    client_key = _client_key(request)
    if not _login_limiter.allow(client_key):
        logger.warning("rate limit triggered op=login key=%s", client_key)
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="too many login attempts")

    user = db.query(User).filter(User.username == req.username).first()
    password_hash = user.password_hash if user is not None else None
    # Sempre roda a verificação Argon2id (mesmo hash dummy quando o usuário
    # não existe) para não vazar por tempo de resposta quem tem conta —
    # ver server/auth.py:verify_password_or_dummy.
    valid = auth.verify_password_or_dummy(req.password, password_hash)

    if user is None or not valid:
        logger.warning("authentication failure user=%s", req.username)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")

    token = auth.create_token(user.username)
    logger.info("authentication success user=%s channel=rest", user.username)
    return TokenResponse(token=token, username=user.username)


@app.get("/auth/exists", response_model=ExistsResponse)
def exists(username: str, request: Request, db: Session = Depends(get_db)) -> ExistsResponse:
    client_key = _client_key(request)
    if not _exists_limiter.allow(client_key):
        logger.warning("rate limit triggered op=exists key=%s", client_key)
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="too many requests")

    normalized = normalize_username(username)
    found = db.query(User).filter(User.username == normalized).first() is not None
    return ExistsResponse(exists=found)


@app.put("/users/me/public-key", response_model=PublicKeyResponse)
def publish_public_key(
    req: PublicKeyRequest,
    username: str = Depends(get_authenticated_username),
    db: Session = Depends(get_db),
) -> PublicKeyResponse:
    """
    Publica a chave pública Ed25519 do usuário AUTENTICADO (nunca de um
    campo `username` no corpo — não existe esse campo no schema). Exige
    prova de posse: uma assinatura Ed25519, feita com a chave PRIVADA
    correspondente, sobre a mensagem canônica
    shared.identity.key_binding_message(username, public_key). Isso
    também rejeita, na prática, qualquer "chave pública" que não seja um
    ponto Ed25519 válido — não dá para forjar uma assinatura válida sem a
    chave privada de verdade.
    """
    raw_key = crypto_utils.decode_b64(req.public_key)
    if not crypto_utils.is_valid_ed25519_public_key(raw_key):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="invalid public key")

    raw_sig = crypto_utils.decode_b64(req.signature)
    if raw_sig is None:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="invalid signature encoding")

    message = shared_identity.key_binding_message(username, req.public_key)
    if not crypto_utils.verify_signature(raw_key, message, raw_sig):
        logger.warning("public key rejected (bad signature) user=%s", username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="signature does not prove possession of the private key",
        )

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        # Não deveria acontecer: um JWT válido implica que a conta existia
        # no momento do login. Defensivo contra a conta ter sido removida
        # nesse meio-tempo (fora de escopo desta fase).
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")

    user.public_key = req.public_key
    db.commit()
    logger.info("public key published user=%s", username)
    return PublicKeyResponse(username=username, public_key=user.public_key)


@app.get("/users/{username}/public-key", response_model=PublicKeyResponse)
def get_public_key(username: str, request: Request, db: Session = Depends(get_db)) -> PublicKeyResponse:
    """Chave pública é informação pública por natureza — sem autenticação,
    mas com o mesmo rate limit de /auth/exists (mesma forma de abuso:
    varredura de usernames)."""
    client_key = _client_key(request)
    if not _exists_limiter.allow(client_key):
        logger.warning("rate limit triggered op=get_public_key key=%s", client_key)
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="too many requests")

    normalized = normalize_username(username)
    user = db.query(User).filter(User.username == normalized).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user not found")

    return PublicKeyResponse(username=user.username, public_key=user.public_key)


def main() -> None:
    import uvicorn

    uvicorn.run("server.main:app", host=settings.host, port=settings.port, reload=False)


if __name__ == "__main__":
    main()

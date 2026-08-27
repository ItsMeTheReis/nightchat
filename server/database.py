"""
database.py — Engine/sessão SQLAlchemy.

Usa DATABASE_URL do .env. Em produção é PostgreSQL; em dev/teste aceitamos
sqlite:/// para não exigir um Postgres instalado só para rodar os testes
automatizados. O código de modelo/consulta é o mesmo nos dois casos —
SQLAlchemy é quem abstrai o dialeto.

Ciclo de vida das sessões (auditoria Fase 2): `get_db()` é para rotas REST
de vida curta (uma sessão por requisição, fechada ao final). O endpoint
WebSocket (server/relay.py) NÃO usa `Depends(get_db)` — ele abre uma
sessão curta só para a checagem pontual de usuário no handshake e a fecha
imediatamente, para não prender uma conexão do pool pela vida inteira do
socket (que pode durar horas).
"""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings

_connect_args: dict = {}
_engine_kwargs: dict = {}
if settings.database_url.startswith("sqlite"):
    # SQLite não tem pool de conexões de verdade; check_same_thread=False é
    # necessário porque o WebSocket e as rotas REST podem cair em threads
    # diferentes do worker do uvicorn.
    _connect_args["check_same_thread"] = False
else:
    # PostgreSQL (produção): limites explícitos para que um punhado de
    # conexões WebSocket não consiga esgotar o pool e travar login/registro
    # de todo mundo. Ver server/config.py (DB_POOL_SIZE, DB_MAX_OVERFLOW).
    _engine_kwargs["pool_size"] = settings.db_pool_size
    _engine_kwargs["max_overflow"] = settings.db_max_overflow
    _engine_kwargs["pool_timeout"] = settings.db_pool_timeout
    _engine_kwargs["pool_pre_ping"] = True

engine = create_engine(settings.database_url, connect_args=_connect_args, **_engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def init_db() -> None:
    from . import models  # noqa: F401  (registra as tabelas no Base.metadata)

    Base.metadata.create_all(bind=engine)


def get_db():
    """Dependency para rotas REST: uma sessão por requisição, sempre fechada."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

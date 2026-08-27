"""
Teste de integração contra um PostgreSQL REAL (não SQLite).

A suíte principal (test_phase2_server.py) roda contra SQLite de propósito
— rápido, sem infraestrutura externa, mesmo comportamento de aplicação
graças ao SQLAlchemy. Mas "passou no SQLite" não é o mesmo que "passou no
banco de produção", então este arquivo existe para validar especificamente
contra Postgres: criação de tabelas, registro, login, unicidade de
username, presença e o fluxo de pedido de conexão.

Como rodar:
    1. Suba um PostgreSQL (local, Docker, o que for) e crie um banco vazio.
    2. Exporte a variável de ambiente:
           NIGHTCHAT_TEST_POSTGRES_URL=postgresql+psycopg://user:pass@host:5432/nightchat_test
    3. python -m pytest tests/test_postgres_integration.py -v

Sem essa variável definida, os testes deste arquivo são PULADOS
explicitamente (não simulados, não substituídos por SQLite) — o pytest
reporta "skipped" com o motivo, para não fingir que o Postgres foi
validado quando não foi.

Ambiente desta tarefa: havia um PostgreSQL rodando na máquina (porta 5432),
mas sem credenciais conhecidas para esta sessão automatizada — por isso,
mesmo aqui, o teste continua pendente de execução real. Ver relatório
final da Fase 2.
"""

from __future__ import annotations

import os
import uuid

import pytest

POSTGRES_URL = os.getenv("NIGHTCHAT_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not POSTGRES_URL,
    reason=(
        "NIGHTCHAT_TEST_POSTGRES_URL não definido — teste contra PostgreSQL real "
        "pulado de propósito (ver docstring deste arquivo para como rodar)."
    ),
)


@pytest.fixture()
def pg_app():
    """
    Constrói uma instância isolada do app FastAPI apontando para o
    PostgreSQL informado em NIGHTCHAT_TEST_POSTGRES_URL, criando as
    tabelas do zero e limpando ao final.
    """
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import sessionmaker

    from server.database import Base
    from server import models  # noqa: F401 registra User no metadata

    engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    Base.metadata.create_all(bind=engine)
    TestSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    from server.main import app
    from server.database import get_db

    def override_get_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    try:
        yield app
    finally:
        app.dependency_overrides.clear()
        with engine.begin() as conn:
            conn.execute(text("TRUNCATE TABLE users"))
        engine.dispose()


def _unique(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex[:6]}"


def test_postgres_table_creation_and_register_login(pg_app):
    from fastapi.testclient import TestClient

    with TestClient(pg_app) as client:
        username = _unique("pgmorning")
        resp = client.post("/auth/register", json={"username": username, "password": "s3nh4-forte"})
        assert resp.status_code == 201

        resp = client.post("/auth/login", json={"username": username, "password": "s3nh4-forte"})
        assert resp.status_code == 200


def test_postgres_username_uniqueness_is_enforced_by_the_database(pg_app):
    from fastapi.testclient import TestClient

    with TestClient(pg_app) as client:
        username = _unique("pgdup")
        client.post("/auth/register", json={"username": username, "password": "s3nh4-forte"})
        resp = client.post("/auth/register", json={"username": username.upper(), "password": "outra"})
        assert resp.status_code == 409


def test_postgres_presence_and_connect_flow(pg_app):
    from fastapi.testclient import TestClient
    from shared import protocol as proto

    with TestClient(pg_app) as client:
        a, b = _unique("pga"), _unique("pgb")
        ta = client.post("/auth/register", json={"username": a, "password": "s3nh4-forte"}).json()["token"]
        tb = client.post("/auth/register", json={"username": b, "password": "s3nh4-forte"}).json()["token"]

        with client.websocket_connect("/ws") as wa:
            wa.send_json({"type": proto.TYPE_AUTH, "token": ta})
            assert wa.receive_json()["ok"] is True
            wa.receive_json()  # user_list inicial

            with client.websocket_connect("/ws") as wb:
                wb.send_json({"type": proto.TYPE_AUTH, "token": tb})
                assert wb.receive_json()["ok"] is True
                wb.receive_json()  # user_list inicial
                wa.receive_json()  # presence: b online

                wa.send_json({"type": "connect_request", "from": a, "to": b})
                req = wb.receive_json()
                assert req["from"] == a.lower()

                wb.send_json({"type": "connect_response", "from": b, "to": a, "payload": "accept"})
                resp = wa.receive_json()
                assert resp["payload"] == "accept"

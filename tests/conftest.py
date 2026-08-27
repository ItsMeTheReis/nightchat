"""
conftest.py — Configuração global de testes.

Roda ANTES de qualquer módulo do servidor ser importado, para garantir:
- um banco sqlite isolado e temporário (evita depender de um Postgres
  real só para rodar os testes automatizados — ver README/limitações);
- custo baixo de Argon2id (os parâmetros de produção seriam lentos
  demais para uma suíte de testes).
"""

import os
import sys
import tempfile
from pathlib import Path

import pytest

_tmp_dir = tempfile.TemporaryDirectory()
_db_path = Path(_tmp_dir.name) / "test_nightchat.db"

os.environ.setdefault("DATABASE_URL", f"sqlite:///{_db_path}")
os.environ.setdefault("JWT_SECRET", "test-secret-not-for-production")
os.environ.setdefault("JWT_TTL_SECONDS", "900")
os.environ.setdefault("ARGON2_TIME_COST", "1")
os.environ.setdefault("ARGON2_MEMORY_COST", "8192")
os.environ.setdefault("ARGON2_PARALLELISM", "1")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(scope="session", autouse=True)
def _dispose_engine_and_tempdir():
    yield
    # Libera o handle do arquivo sqlite antes do TemporaryDirectory tentar
    # se auto-limpar no fim do processo (senão o Windows recusa o unlink).
    from server.database import engine

    engine.dispose()
    _tmp_dir.cleanup()

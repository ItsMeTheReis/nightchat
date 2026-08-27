"""
config.py — Configuração do relay lida do ambiente (.env).

Regra do projeto: secrets e configuração ficam FORA do código. O único
segredo "hardcoded" é o fallback óbvio de desenvolvimento (contém
"dev-insecure"), para nunca ser confundido com um segredo de produção.

Validação de produção (NIGHTCHAT_ENV=production): se a configuração for
insegura (JWT_SECRET fraco/padrão, TLS não exigido, banco não-Postgres),
o processo se recusa a subir (RuntimeError) em vez de só avisar.
"""

from __future__ import annotations

import os
import warnings
from dataclasses import dataclass

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    # python-dotenv é opcional: sem ele, só lemos variáveis de ambiente reais.
    pass


def _env_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


_INSECURE_JWT_SECRETS = {"dev-insecure-secret-change-me", "", "changeme", "secret", "insecure"}
_MIN_PRODUCTION_JWT_SECRET_LEN = 32


@dataclass(frozen=True)
class Settings:
    # PostgreSQL em produção, ex.: postgresql+psycopg://user:pass@host:5432/nightchat
    # Em dev/testes, aceitamos sqlite:/// para rodar sem instalar um servidor Postgres.
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./nightchat.db")

    # SQLAlchemy connection pool. Importante: o WebSocket NÃO deve manter uma
    # sessão do pool aberta durante toda a conexão (ver server/relay.py) —
    # esses limites protegem contra o cenário em que muitos usuários online
    # simultaneamente esgotariam o pool e travariam login/registro de todos.
    db_pool_size: int = int(os.getenv("DB_POOL_SIZE", "10"))
    db_max_overflow: int = int(os.getenv("DB_MAX_OVERFLOW", "10"))
    db_pool_timeout: int = int(os.getenv("DB_POOL_TIMEOUT_SECONDS", "30"))

    jwt_secret: str = os.getenv("JWT_SECRET", "dev-insecure-secret-change-me")
    jwt_algorithm: str = "HS256"
    jwt_ttl_seconds: int = int(os.getenv("JWT_TTL_SECONDS", "900"))

    argon2_time_cost: int = int(os.getenv("ARGON2_TIME_COST", "3"))
    argon2_memory_cost: int = int(os.getenv("ARGON2_MEMORY_COST", "65536"))
    argon2_parallelism: int = int(os.getenv("ARGON2_PARALLELISM", "4"))

    host: str = os.getenv("NIGHTCHAT_HOST", "0.0.0.0")
    port: int = int(os.getenv("NIGHTCHAT_PORT", "8000"))

    # "development" (padrão) ou "production". Em produção, config insegura
    # falha o startup (ver validate_production_config abaixo) em vez de só avisar.
    environment: str = os.getenv("NIGHTCHAT_ENV", "development").strip().lower()

    # Em produção isto DEVE ser true: o relay passa a exigir que a conexão
    # (HTTP ou WebSocket) chegue como https/wss — direto ou via
    # X-Forwarded-Proto de um proxy reverso confiável na frente. Em dev,
    # ws:// puro é aceito. Ver _is_secure_request() em server/main.py e
    # server/relay.py.
    require_tls: bool = _env_bool("NIGHTCHAT_REQUIRE_TLS", False)

    log_level: str = os.getenv("NIGHTCHAT_LOG_LEVEL", "INFO")

    # --- Rate limiting (janela fixa, em memória — ver server/ratelimit.py) ---
    rate_limit_register_max: int = int(os.getenv("RATE_LIMIT_REGISTER_MAX", "3"))
    rate_limit_register_window: float = float(os.getenv("RATE_LIMIT_REGISTER_WINDOW_SECONDS", "60"))

    rate_limit_login_max: int = int(os.getenv("RATE_LIMIT_LOGIN_MAX", "5"))
    rate_limit_login_window: float = float(os.getenv("RATE_LIMIT_LOGIN_WINDOW_SECONDS", "60"))

    rate_limit_exists_max: int = int(os.getenv("RATE_LIMIT_EXISTS_MAX", "20"))
    rate_limit_exists_window: float = float(os.getenv("RATE_LIMIT_EXISTS_WINDOW_SECONDS", "60"))

    rate_limit_connect_request_max: int = int(os.getenv("RATE_LIMIT_CONNECT_REQUEST_MAX", "10"))
    rate_limit_connect_request_window: float = float(
        os.getenv("RATE_LIMIT_CONNECT_REQUEST_WINDOW_SECONDS", "60")
    )

    rate_limit_ws_message_max: int = int(os.getenv("RATE_LIMIT_WS_MESSAGE_MAX", "30"))
    rate_limit_ws_message_window: float = float(os.getenv("RATE_LIMIT_WS_MESSAGE_WINDOW_SECONDS", "10"))


def validate_production_config(s: Settings) -> None:
    """
    Recusa subir com configuração insegura quando NIGHTCHAT_ENV=production.

    Separado de Settings() para ser testável isoladamente (constrói-se um
    Settings customizado no teste, sem depender de variáveis de ambiente
    reais do processo).
    """
    if s.environment != "production":
        if s.jwt_secret in _INSECURE_JWT_SECRETS:
            warnings.warn(
                "JWT_SECRET não configurado — usando segredo de DESENVOLVIMENTO. "
                "Defina JWT_SECRET e NIGHTCHAT_ENV=production antes de rodar em produção.",
                stacklevel=2,
            )
        return

    problems = []
    if s.jwt_secret in _INSECURE_JWT_SECRETS or len(s.jwt_secret) < _MIN_PRODUCTION_JWT_SECRET_LEN:
        problems.append(
            f"JWT_SECRET precisa ter pelo menos {_MIN_PRODUCTION_JWT_SECRET_LEN} caracteres "
            "e não pode ser o valor padrão de desenvolvimento."
        )
    if not s.require_tls:
        problems.append("NIGHTCHAT_REQUIRE_TLS precisa ser 'true' em produção (wss:// obrigatório).")
    if s.database_url.startswith("sqlite"):
        problems.append("DATABASE_URL aponta para SQLite; produção deve usar PostgreSQL.")

    if problems:
        raise RuntimeError(
            "Configuração insegura para NIGHTCHAT_ENV=production:\n- " + "\n- ".join(problems)
        )


settings = Settings()
validate_production_config(settings)

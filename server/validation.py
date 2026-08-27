"""
validation.py — Regra única de normalização/validação de username.

Usado em TODO lugar que aceita um username (registro, login, /auth/exists,
alvo de connect_request/connect_response) para garantir que
"morningstar" / "MorningStar" / "MORNINGSTAR" sejam sempre a MESMA conta.

Normalização: strip() + lower(). O valor normalizado é o que vai para o
banco (chave primária) e para o campo "sub" do JWT — não guardamos a
capitalização original que o usuário digitou.
"""

from __future__ import annotations

import re

USERNAME_MIN_LEN = 3
USERNAME_MAX_LEN = 20

# Aceita letras (maiúsculas/minúsculas na entrada), dígitos, '_' e '-'.
# A validação roda ANTES da normalização para dar uma mensagem de erro
# clara; o padrão em si é case-insensitive por construção (re.IGNORECASE
# não é necessário porque already cobre A-Z e a-z explicitamente).
_USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


def normalize_username(raw: str) -> str:
    """Forma canônica de um username: sem espaços nas pontas, minúsculo."""
    return raw.strip().lower()


def is_valid_username(raw: str) -> bool:
    """Valida o formato ANTES da normalização (aceita mixed case)."""
    text = raw.strip()
    if not (USERNAME_MIN_LEN <= len(text) <= USERNAME_MAX_LEN):
        return False
    return bool(_USERNAME_PATTERN.match(text))

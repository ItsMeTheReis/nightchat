"""schemas.py — Modelos Pydantic da API REST de autenticação.

Normalização de username (auditoria Fase 2): "morningstar", "MorningStar"
e "MORNINGSTAR" precisam ser a MESMA conta. A validação roda sobre o
valor ORIGINAL digitado (para mensagens de erro claras sobre tamanho/
caracteres permitidos) e o validator já devolve a forma normalizada
(minúscula, sem espaços nas pontas) — o resto do código sempre recebe o
username já canônico.
"""

from __future__ import annotations

from pydantic import BaseModel, field_validator

from .validation import is_valid_username, normalize_username, USERNAME_MAX_LEN, USERNAME_MIN_LEN


def _validate_and_normalize(raw: str) -> str:
    if not is_valid_username(raw):
        raise ValueError(
            f"username deve ter {USERNAME_MIN_LEN}-{USERNAME_MAX_LEN} caracteres "
            "(letras, números, '_' ou '-', sem espaços)"
        )
    return normalize_username(raw)


class RegisterRequest(BaseModel):
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def _username(cls, v: str) -> str:
        return _validate_and_normalize(v)

    @field_validator("password")
    @classmethod
    def _password(cls, v: str) -> str:
        if len(v) < 6 or len(v) > 256:
            raise ValueError("password deve ter entre 6 e 256 caracteres")
        return v


class LoginRequest(BaseModel):
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def _username(cls, v: str) -> str:
        # No login normalizamos sem validar formato rígido: um username
        # inválido simplesmente não vai existir no banco (401 igual a
        # qualquer outra credencial errada) — não vale a pena reportar erro
        # de formato aqui e abrir uma distinção observável.
        return normalize_username(v)


class TokenResponse(BaseModel):
    token: str
    username: str


class ExistsResponse(BaseModel):
    exists: bool


class PublicKeyRequest(BaseModel):
    """
    Corpo de PUT /users/me/public-key. Note que NÃO há campo `username`
    aqui de propósito (auditoria Fase 3): o dono da chave é sempre a
    identidade autenticada pelo JWT, nunca um valor que o cliente possa
    declarar no corpo da requisição.
    """

    public_key: str  # base64 de 32 bytes (Ed25519) — validação de forma/tamanho na rota
    signature: str  # base64 da assinatura Ed25519 sobre shared.identity.key_binding_message(...)

    @field_validator("public_key", "signature")
    @classmethod
    def _not_absurdly_long(cls, v: str) -> str:
        if not v or len(v) > 256:
            raise ValueError("valor base64 inválido")
        return v


class PublicKeyResponse(BaseModel):
    username: str
    public_key: str | None

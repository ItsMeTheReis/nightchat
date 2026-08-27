"""
models.py — Modelo de usuários do relay (minimização extrema de dados).

A filosofia do NightChat é que o relay sabe o MÍNIMO necessário para
operar. Uma conta é só:

    username (identidade lógica, chave primária)
    password_hash (Argon2id — nunca a senha em si)

Nenhum dado pessoal (nome real, e-mail, telefone, CPF, endereço, data de
nascimento, avatar) é coletado. Não há UUID interno substituindo o
username como identificador — o username JÁ é o identificador da conta.

Não existe (e não deve existir) tabela de mensagens, histórico de
conversas ou lista persistente de contatos. Presença é estado em memória
(ver server/presence.py), não uma coluna nesta tabela — ela desaparece
quando o usuário desconecta.

Fase 3 acrescenta exatamente UMA coluna: `public_key` (Ed25519, base64,
opcional). É informação pública por natureza — a chave PRIVADA correspondente
nunca é vista pelo relay (fica só no dispositivo do usuário, ver
client/identity_store.py). Nenhuma outra coluna foi adicionada: sem
created_at, sem last_seen_at, sem histórico de troca de chave.
"""

from __future__ import annotations

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base
from .validation import USERNAME_MAX_LEN


class User(Base):
    __tablename__ = "users"

    username: Mapped[str] = mapped_column(String(USERNAME_MAX_LEN), primary_key=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    public_key: Mapped[str | None] = mapped_column(Text, nullable=True)

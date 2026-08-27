"""
shared/identity.py — Contrato compartilhado para prova de posse de chave
pública Ed25519 (Fase 3).

Cliente e servidor precisam concordar EXATAMENTE na mensagem que é
assinada para provar posse da chave privada ao publicar uma chave
pública no relay — ver `PUT /users/me/public-key` em `server/main.py` e
`client/authentication.py`. Ficar num módulo compartilhado evita que os
dois lados divirjam silenciosamente (um bug de "off-by-one byte" na
mensagem faria toda assinatura válida ser rejeitada, ou pior, os dois
lados narrowly concordarem por acidente).

Isto NÃO é o handshake de sessão E2EE (Fase 4/5) — é só a prova de que
"eu controlo a chave privada correspondente a esta chave pública que
estou publicando". Não precisa de nonce/desafio do servidor: reenviar a
mesma assinatura válida para o mesmo par (username, public_key) não
concede nada de novo (não deriva sessão nem autorização adicional), então
não existe uma janela de replay a explorar aqui — diferente da
autenticação de login, que usa JWT com expiração justamente porque *essa*
prova concede uma sessão.
"""

from __future__ import annotations

KEY_BINDING_VERSION = "v1"


def key_binding_message(username: str, public_key_b64: str) -> bytes:
    """
    Mensagem canônica que o cliente assina com sua chave PRIVADA Ed25519
    ao publicar a chave pública correspondente. `username` deve ser a
    identidade JÁ AUTENTICADA (do JWT no lado servidor) — nunca um valor
    arbitrário enviado pelo cliente no corpo da requisição.
    """
    return f"nightchat-key-binding:{KEY_BINDING_VERSION}:{username}:{public_key_b64}".encode("utf-8")

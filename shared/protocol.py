"""
shared/protocol.py — Contrato de protocolo compartilhado entre cliente e servidor.

Definido cedo (mesmo antes do servidor existir) para que cliente e relay
"falem a mesma língua" quando a Fase 2 começar. Nada aqui carrega texto de
mensagem em claro: o campo de conteúdo é sempre ciphertext opaco (base64).

Ver docs/ARCHITECTURE.md, seção 4.
"""

from __future__ import annotations

PROTOCOL_VERSION = "nightchat/1"

# Tipos de mensagem no nível do relay (L1). O servidor entende só isto.
#
# CONTROLE (o servidor participa da lógica — autenticação, presença,
# aprovação social, roteamento do handshake):
TYPE_AUTH = "auth"                     # cliente -> servidor: autenticação
TYPE_AUTH_CHALLENGE = "auth_challenge" # servidor -> cliente: nonce de desafio
TYPE_AUTH_RESULT = "auth_result"       # servidor -> cliente: ok/erro + token
TYPE_PRESENCE = "presence"             # atualização online/offline
TYPE_USER_LIST = "user_list"           # servidor -> cliente: usuários online
TYPE_CONNECT_REQUEST = "connect_request"   # A quer sessão com B
TYPE_CONNECT_RESPONSE = "connect_response" # B aceita/recusa (inclui "session" quando aceita — Fase 4)
TYPE_RELAY = "relay"                   # transporta o HANDSHAKE X25519/STS opaco (client/handshake.py)
TYPE_SESSION_END = "session_end"       # encerra uma sessão de handshake/E2EE
TYPE_LIST_USERS = "list_users"         # cliente -> servidor: pede lista de online
TYPE_ERROR = "error"                   # servidor -> cliente: erro de protocolo
#
# DADOS (o servidor só encaminha — nunca entende o conteúdo, Fase 5):
TYPE_ENCRYPTED_MESSAGE = "encrypted_message"  # mensagem de chat cifrada (XChaCha20-Poly1305), opaca para o relay

# NOTA DE HONESTIDADE (Fase 5): TYPE_RELAY continua transportando só o
# handshake (payload opaco, roteado por "session" — server/sessions.py).
# TYPE_ENCRYPTED_MESSAGE é o tipo NOVO e SEPARADO para mensagens de chat
# de verdade — usa exatamente o mesmo envelope L1 (from/to/session/payload)
# e a mesma autorização por session_id do TYPE_RELAY (server/relay.py),
# só com um nome diferente para deixar claro, em qualquer lugar que leia
# o protocolo (incluindo logs — que nunca registram `payload`), a
# distinção entre "tráfego de controle do handshake" e "tráfego de
# conteúdo do usuário". O servidor trata os dois de forma estruturalmente
# idêntica (nunca decifra, nunca loga o payload) — a separação é de
# nomenclatura/auditoria, não de tratamento privilegiado de um sobre o
# outro. Ver shared/messaging.py para o formato do quadro cifrado.

# Respostas a um connect_request
CONNECT_ACCEPT = "accept"
CONNECT_DENY = "deny"


def envelope(msg_type: str, sender: str, recipient: str | None = None,
             session: str | None = None, payload: str | None = None) -> dict:
    """
    Monta o envelope L1 que o servidor roteia. 'payload' é ciphertext em
    base64 (para TYPE_RELAY) ou None para mensagens de controle.
    """
    env = {"v": PROTOCOL_VERSION, "type": msg_type, "from": sender}
    if recipient is not None:
        env["to"] = recipient
    if session is not None:
        env["session"] = session
    if payload is not None:
        env["payload"] = payload
    return env

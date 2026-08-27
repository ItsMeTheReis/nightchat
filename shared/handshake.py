"""
shared/handshake.py — Contrato do handshake X25519 autenticado por
Ed25519 (Station-to-Station simplificado), Fase 4.

Só o essencial para os DOIS CLIENTES (não o servidor — ele só roteia
bytes opacos por session_id, ver server/relay.py e server/sessions.py)
concordarem byte-a-byte no que é assinado e em como as chaves de sessão
são derivadas. Ver docs/ARCHITECTURE.md, seções 4.4/4.5.

Mensagens trocadas (dentro do payload opaco de TYPE_RELAY):

    1. initiator -> responder : {"kind": "handshake_init",     "eph_pub": b64}
    2. responder -> initiator : {"kind": "handshake_response", "eph_pub": b64, "signature": b64}
    3. initiator -> responder : {"kind": "handshake_confirm",  "signature": b64}

`signature` em (2) e (3) é SEMPRE sobre o MESMO transcript canônico (ver
`transcript()` abaixo) — os dois lados assinam exatamente os mesmos
bytes. Isso é uma simplificação deliberada em relação ao esboço original
do ARCHITECTURE.md (lá, cada lado assinava a dupla de chaves numa ordem
"própria" — aqui a ordem é sempre (initiator, responder) para os dois
signatários, o que elimina qualquer chance de bug de transposição ao
montar/verificar a mensagem).

Autenticação mútua: a assinatura Ed25519 amarra as duas chaves efêmeras
X25519 + os dois usernames + o session_id às identidades de longo prazo
já publicadas no relay (Fase 3). Um atacante sem a chave privada Ed25519
de uma das partes não consegue forjar uma assinatura válida — inclusive
se ele for o próprio relay tentando substituir uma chave efêmera em
trânsito (ver docs/ARCHITECTURE.md e o relatório da Fase 4 para a análise
de por que isso é detectado mesmo sem o msg 1 ser assinado).
"""

from __future__ import annotations

from .wire import len_prefixed as _len_prefixed

HANDSHAKE_VERSION = "v1"

KIND_INIT = "handshake_init"
KIND_RESPONSE = "handshake_response"
KIND_CONFIRM = "handshake_confirm"

HKDF_INFO_PREFIX = "nightchat-v1"


def transcript(
    session_id: str,
    initiator: str,
    responder: str,
    eph_initiator_pub: bytes,
    eph_responder_pub: bytes,
) -> bytes:
    """
    Mensagem canônica assinada pelas DUAS partes (bytes idênticos para
    ambas) — prova que concordam exatamente nas mesmas chaves efêmeras,
    para a mesma sessão, entre os mesmos dois usernames. `initiator`/
    `responder` são sempre os papéis fixos da sessão (quem mandou o
    connect_request original / quem aceitou), não "quem está assinando".
    """
    return _len_prefixed(
        f"nightchat-handshake:{HANDSHAKE_VERSION}".encode("utf-8"),
        session_id.encode("utf-8"),
        initiator.encode("utf-8"),
        responder.encode("utf-8"),
        eph_initiator_pub,
        eph_responder_pub,
    )


def hkdf_info(sender: str, recipient: str) -> bytes:
    """Rótulo de direção para a HKDF — a chave usada por `sender` para
    mandar mensagens a `recipient` é diferente da usada no sentido
    inverso, mesmo vindo do mesmo segredo compartilhado X25519."""
    return f"{HKDF_INFO_PREFIX}|{sender}|{recipient}".encode("utf-8")

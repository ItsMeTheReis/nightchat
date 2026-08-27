"""
sessions.py — Estado básico de pedidos de conexão pendentes (Fase 2) e de
sessões de handshake E2EE em andamento (Fase 4).

A parte de PEDIDOS PENDENTES (`_pending`) é só o registro de "quem pediu
conexão a quem", para que:

1. um connect_response só seja encaminhado se corresponder a um pedido
   real (sem isso, um cliente poderia forjar um "accept" para um pedido
   que nunca existiu);
2. um alvo possa ter MÚLTIPLOS pedidos pendentes ao mesmo tempo (A e B
   pedem conexão a C — C precisa ver os dois, não só o último);
3. pedidos órfãos sejam limpos quando qualquer um dos dois lados
   desconecta, não só quando o alvo desconecta.

A parte de SESSÕES DE HANDSHAKE (`_handshake_sessions`, Fase 4) é o
registro de "session_id X é uma troca X25519 autorizada entre A e B",
mintado pelo relay no momento em que um connect_response(accept) é
processado. O relay usa isso para só encaminhar TYPE_RELAY/TYPE_SESSION_END
daquele session_id exatamente entre A e B — nunca para um terceiro, nunca
com um session_id inventado. O CONTEÚDO do handshake (chaves efêmeras,
assinaturas) é opaco para o relay; só o roteamento é autorizado aqui.
Isto continua NÃO sendo a sessão E2EE em si — o relay nunca vê chaves
efêmeras, segredo compartilhado ou chaves de sessão derivadas.

Estado em memória de processo único — mesma limitação de escalabilidade
de server/presence.py (ver docs/ARCHITECTURE.md).
"""

from __future__ import annotations

import secrets

# alvo -> lista (ordem de chegada) de requerentes com pedido pendente
_pending: dict[str, list[str]] = {}

# session_id -> {"initiator": username, "responder": username}
_handshake_sessions: dict[str, dict[str, str]] = {}

# Teto defensivo: evita que alguém encha a memória de um alvo com pedidos
# forjados de usernames distintos (rate limiting cuida da frequência; isto
# cobre o caso de "muitos requerentes distintos" que a janela de tempo por
# usuário não limita sozinha).
_MAX_PENDING_PER_TARGET = 50


def add_request(requester: str, target: str) -> bool:
    """Registra um pedido pendente. Retorna False se o alvo já tem pedidos
    pendentes demais (defesa contra flood de requerentes distintos)."""
    reqs = _pending.setdefault(target, [])
    if requester in reqs:
        return True  # já pendente — reenviar não duplica
    if len(reqs) >= _MAX_PENDING_PER_TARGET:
        return False
    reqs.append(requester)
    return True


def pending_for(target: str) -> list[str]:
    """Lista (cópia) dos requerentes com pedido pendente para `target`."""
    return list(_pending.get(target, []))


def pop_pending(target: str, expected_requester: str) -> bool:
    """Confirma e consome um pedido pendente específico. True se era válido."""
    reqs = _pending.get(target)
    if not reqs or expected_requester not in reqs:
        return False
    reqs.remove(expected_requester)
    if not reqs:
        _pending.pop(target, None)
    return True


def clear_for_user(username: str) -> None:
    """
    Usuário desconectou: remove pedidos pendentes onde ele era o ALVO
    (ninguém mais vai responder por ele) e também onde ele era o
    REQUERENTE (não faz sentido um pedido pendente de alguém que já saiu —
    sem isso, o pedido ficava órfão para sempre até o alvo responder).
    """
    _pending.pop(username, None)
    for target, reqs in list(_pending.items()):
        if username in reqs:
            reqs.remove(username)
            if not reqs:
                _pending.pop(target, None)


# ---------------------------------------------------------------------------
# Sessões de handshake E2EE (Fase 4)
# ---------------------------------------------------------------------------

def create_handshake_session(initiator: str, responder: str) -> str:
    """Mintado pelo relay quando processa um connect_response(accept).
    Retorna o session_id — um correlator opaco, sem propriedade de
    segurança própria (a segurança vem das assinaturas Ed25519 dos
    clientes, não do sigilo deste id)."""
    session_id = secrets.token_hex(16)
    _handshake_sessions[session_id] = {"initiator": initiator, "responder": responder}
    return session_id


def other_party(session_id: str, username: str) -> str | None:
    """Retorna o outro participante da sessão, se `username` for
    realmente um dos dois — None se a sessão não existe ou `username` não
    participa dela (usado tanto para autorizar roteamento quanto para
    rejeitar injeção de mensagens em sessões alheias)."""
    s = _handshake_sessions.get(session_id)
    if s is None:
        return None
    if s["initiator"] == username:
        return s["responder"]
    if s["responder"] == username:
        return s["initiator"]
    return None


def end_handshake_session(session_id: str) -> None:
    _handshake_sessions.pop(session_id, None)


def clear_handshake_sessions_for_user(username: str) -> list[tuple[str, str]]:
    """Usuário desconectou: remove toda sessão de handshake em que ele
    participava. Retorna [(session_id, outro_participante), ...] para o
    chamador poder avisar a outra parte com TYPE_SESSION_END."""
    removed: list[tuple[str, str]] = []
    for session_id, s in list(_handshake_sessions.items()):
        if username in (s["initiator"], s["responder"]):
            other = s["responder"] if s["initiator"] == username else s["initiator"]
            _handshake_sessions.pop(session_id, None)
            removed.append((session_id, other))
    return removed

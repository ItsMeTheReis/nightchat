"""
presence.py — Gerenciador de conexões WebSocket ativas (presença online/offline).

Puramente em memória: presença é estado efêmero de processo, não é gravado
no banco como histórico. Quando o usuário desconecta, a presença some —
não existe coluna "last_seen"/"is_online" na tabela de usuários.

LIMITAÇÃO CONHECIDA (documentada, não escondida): isto é um dict Python de
UM processo. Rodar `uvicorn --workers N>1` ou múltiplas réplicas atrás de
um load balancer QUEBRA presença — cada processo veria só uma fatia dos
usuários conectados, sem nenhum mecanismo de sincronização (Redis pub/sub
ou equivalente) entre eles. Isso fica para uma fase futura; hoje o relay
só é suportado como processo único.

Correção de race condition (auditoria Fase 2): cada conexão WebSocket roda
como uma Task asyncio própria. Numa reconexão, a Task da conexão ANTIGA
pode terminar seu bloco `finally` DEPOIS que a conexão NOVA já foi
registrada — se o cleanup da antiga simplesmente apagasse `active[username]`
por chave, ele removeria a conexão nova por engano, fazendo o usuário
"sumir" da presença mesmo com o socket novo vivo. Por isso `disconnect()`
exige o objeto do WebSocket e só remove a entrada se ela ainda for
exatamente aquele socket (`active.get(username) is websocket`).
"""

from __future__ import annotations

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self) -> None:
        self.active: dict[str, WebSocket] = {}

    async def replace(self, username: str, new_ws: WebSocket) -> None:
        """
        Registra `new_ws` como a conexão ativa de `username`, fechando uma
        conexão antiga do mesmo usuário se houver (reconexão). Não usa
        `disconnect()` aqui porque queremos fechar e substituir
        incondicionalmente — a proteção de identidade em `disconnect()` é
        para o cleanup tardio da conexão antiga (no `finally` dela), não
        para este caminho de substituição explícita.
        """
        old = self.active.get(username)
        if old is not None and old is not new_ws:
            try:
                await old.close(code=4409)  # 4409: substituído por nova conexão
            except Exception:
                pass
        self.active[username] = new_ws

    def disconnect(self, username: str, websocket: WebSocket) -> bool:
        """
        Remove a entrada de `username` APENAS se `websocket` ainda for a
        conexão ativa registrada. Retorna True se removeu (ou seja: esta
        era mesmo a conexão "corrente" do usuário — o usuário ficou
        offline de verdade). Retorna False se uma conexão mais nova já
        assumiu o lugar (esta era uma conexão obsoleta se limpando) — nesse
        caso o usuário continua online e nenhum evento de "offline" deve
        ser emitido para ele.
        """
        if self.active.get(username) is websocket:
            self.active.pop(username, None)
            return True
        return False

    def is_online(self, username: str) -> bool:
        return username in self.active

    def online_usernames(self) -> list[str]:
        return list(self.active.keys())

    async def send_to(self, username: str, message: dict) -> bool:
        ws = self.active.get(username)
        if ws is None:
            return False
        try:
            await ws.send_json(message)
        except Exception:
            self.disconnect(username, ws)
            return False
        return True

    async def broadcast(self, message: dict, exclude: str | None = None) -> None:
        for username in list(self.active.keys()):
            if username == exclude:
                continue
            await self.send_to(username, message)


manager = ConnectionManager()

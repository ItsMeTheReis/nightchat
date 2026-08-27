"""
logging_conf.py — Logging operacional mínimo do relay.

Filosofia: "o relay sabe o mínimo necessário para operar" também vale
para logs. O que é registrado (nível INFO/WARNING, para stdout):

    - início/parada do relay
    - sucesso/falha de autenticação (username — NUNCA senha ou hash)
    - desconexão inesperada de WebSocket (username)
    - rate limit acionado (operação + chave: username ou IP)
    - erro de protocolo (tipo de mensagem + motivo — nunca o payload bruto)

O que NUNCA é registrado, em nenhuma circunstância:

    - senha em texto puro
    - password_hash (Argon2id)
    - o token JWT (nem completo nem parcial)
    - conteúdo de mensagens — inclusive futuros payloads cifrados E2EE
      (isso continuará valendo quando TYPE_RELAY carregar ciphertext de
      verdade: o relay não deve logar `payload`, cifrado ou não)

Retenção: esta aplicação só emite logs para stdout via `logging` padrão.
Ela não persiste logs em disco/banco por conta própria — retenção,
rotação e armazenamento são responsabilidade de quem opera o processo
(systemd/journald, Docker, um agregador de logs etc.), fora do escopo
deste código.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("nightchat.relay")

_configured = False


def configure_logging(level: str = "INFO") -> None:
    global _configured
    if _configured:
        return
    logging.basicConfig(
        level=level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    _configured = True

"""
server — NightChat Relay (Fase 2): FastAPI + WebSocket + PostgreSQL.

O relay é intencionalmente "burro" a respeito de conteúdo: autentica
usuários, mantém presença online/offline, faz descoberta de usuários e
encaminha pedidos de conexão. Ele NUNCA guarda plaintext de mensagens
nem chaves privadas/de sessão. Ver docs/ARCHITECTURE.md.
"""

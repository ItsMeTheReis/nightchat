"""
commands.py — Tabela e dispatcher de comandos do shell NightChat (Fase 1).

Separado da UI (terminal.py) e do loop (main.py) para que adicionar um novo
comando seja só registrar um handler aqui.

Aceitamos duas formas para conforto:
  - estilo slash:      /users, /help, /connect sofia
  - estilo linguagem:  connect to user "sofia"

Comandos que dependem de servidor/cripto (connect/accept/deny) estão
presentes mas retornam um aviso honesto de "disponível a partir da Fase 3/5".
Nada de fingir que funciona.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from . import active_sessions
from . import chat
from . import chat_state
from . import connection_state as cstate
from . import crypto
from . import terminal as term
from . import presence
from .terminal import C

# Sinaliza ao loop principal o que fazer depois do comando.
CONTINUE = "continue"
EXIT = "exit"


@dataclass
class Context:
    username: str
    fingerprint: str
    client: object = None  # relay_client.RelayClient | None (Fase 2)
    crypto_identity: object = None  # crypto_identity.CryptographicIdentity | None (Fase 3)


def _parse_connect_target(raw: str) -> str | None:
    """
    Extrai 'sofia' de várias formas:
      connect to user "sofia"
      /connect to user sofia
      /connect sofia
    """
    m = re.search(r'user\s+"?([A-Za-z0-9_-]+)"?', raw)
    if m:
        return m.group(1)
    m = re.search(r'^/?connect\s+"?([A-Za-z0-9_-]+)"?\s*$', raw.strip())
    if m:
        return m.group(1)
    return None


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def _cmd_help(ctx: Context, raw: str) -> str:
    term.line()
    term.boxed_title("COMMANDS", 46)
    term.line()
    rows = [
        ("/help", "mostra esta ajuda"),
        ("/users", "lista usuários online"),
        ("/status", "estado da sessão e conexão"),
        ("/fingerprint", "mostra seu fingerprint de identidade"),
        ("identity", "detalhes da identidade criptográfica Ed25519 local"),
        ('identity verify "name"', "consulta o fingerprint de outro usuário"),
        ("/clear", "limpa a tela"),
        ('connect to user "name"', "solicita sessão segura + handshake E2EE"),
        ("accept | deny", "responde a um pedido de conexão"),
        ('chat "name"', "entra no modo de conversa cifrada (E2EE)"),
        ("/exit", "encerra a sessão / o programa"),
    ]
    for cmd, desc in rows:
        term.line(f"  {term.color(cmd.ljust(24), C.CYAN)} {desc}")
    term.line()
    return CONTINUE


def _cmd_users(ctx: Context, raw: str) -> str:
    peers = presence.online_users(exclude=ctx.username)
    term.line()
    term.line("ONLINE USERS", C.WHITE, C.BOLD)
    term.line()
    if not peers:
        term.line("  (ninguém online)", C.GREY)
    for p in peers:
        term.line(f"  [+] {p.username}", C.GREEN)
    if presence.is_mock():
        term.line()
        term.line("  (lista simulada — Fase 1 é local; presença real na Fase 2)",
                  C.GREY, C.DIM)
    term.line()
    return CONTINUE


def _cmd_status(ctx: Context, raw: str) -> str:
    online = ctx.client is not None and getattr(ctx.client, "connected", False)
    relay_state = "connected" if online else "offline (no relay)"
    relay_color = C.GREEN if online else C.YELLOW
    peers = active_sessions.list_peers()

    term.line()
    term.line("SESSION STATUS", C.WHITE, C.BOLD)
    term.line(f"  user  : {term.color(ctx.username, C.CYAN)}")
    term.line(f"  relay : {term.color(relay_state, relay_color)}")
    term.line()
    term.line("ACTIVE SECURE SESSIONS", C.WHITE, C.BOLD)
    term.line()
    if not peers:
        term.line("  (none)", C.GREY)
    for peer in peers:
        session = active_sessions.get(peer)
        term.line(f"  [+] {peer}", C.GREEN, C.BOLD)
        if session is not None:
            term.line(f"      Session: {session.session_id[:8]}...", C.GREY)
        term.line("      E2EE: XChaCha20-Poly1305", C.GREY)
        term.line("      State: ESTABLISHED", C.GREY)
    term.line()
    return CONTINUE


def _cmd_fingerprint(ctx: Context, raw: str) -> str:
    term.line()
    term.line("IDENTITY FINGERPRINT", C.WHITE, C.BOLD)
    term.line(f"  {ctx.username}", C.CYAN, C.BOLD)
    term.line(f"  {ctx.fingerprint}", C.GREEN)
    term.line()
    term.line("  Compare este fingerprint com seu par por um canal externo", C.GREY, C.DIM)
    term.line("  (voz/pessoalmente) para detectar man-in-the-middle.", C.GREY, C.DIM)
    term.line("  (SHA-256 da chave pública Ed25519 — ver 'identity' para mais detalhes)",
              C.GREY, C.DIM)
    term.line()
    return CONTINUE


def _cmd_identity(ctx: Context, raw: str) -> str:
    """
    `identity`              -> mostra a identidade criptográfica local.
    `identity verify "nome"` -> consulta e mostra o fingerprint de outro
                                usuário (comparação manual/fora de banda —
                                não há pinning/TOFU persistente nesta fase).
    """
    parts = raw.strip().split(maxsplit=2)
    term.line()
    if len(parts) >= 2 and parts[1].lower() == "verify":
        target = None
        if len(parts) >= 3:
            m = re.match(r'"?([A-Za-z0-9_-]+)"?', parts[2])
            target = m.group(1) if m else None
        if not target:
            term.line('  [!] Uso: identity verify "nome"', C.RED)
            term.line()
            return CONTINUE
        if ctx.client is None:
            term.line("  [!] Não conectado ao relay.", C.RED)
            term.line()
            return CONTINUE
        ok, public_key_b64, err = ctx.client.get_public_key(target)
        if not ok:
            term.line(f"  [!] Não foi possível consultar \"{target}\": {err}", C.RED)
            term.line()
            return CONTINUE
        if public_key_b64 is None:
            term.line(f'  [i] "{target}" ainda não publicou uma chave pública.', C.YELLOW)
            term.line()
            return CONTINUE
        public_key = crypto.decode_public_key(public_key_b64)
        if public_key is None:
            term.line(f'  [!] Chave pública de "{target}" está corrompida/inválida.', C.RED)
            term.line()
            return CONTINUE
        term.line("IDENTITY VERIFY", C.WHITE, C.BOLD)
        term.line(f"  Username    : {target}", C.CYAN)
        term.line(f"  Fingerprint : {crypto.fingerprint(public_key)}", C.GREEN)
        term.line()
        term.line("  Compare isto com o que a outra pessoa vê por um canal", C.GREY, C.DIM)
        term.line("  externo (voz/pessoalmente) antes de confiar na identidade.", C.GREY, C.DIM)
        term.line()
        return CONTINUE

    term.line("Identity", C.WHITE, C.BOLD)
    term.line(f"Username: {ctx.username}", C.CYAN)
    term.line(f"Fingerprint: {ctx.fingerprint}", C.GREEN)
    term.line("Algorithm: Ed25519")
    term.line("Status: registered", C.GREEN)
    term.line()
    term.line("  (a chave privada nunca sai desta máquina — ver client/identity_store.py)",
              C.GREY, C.DIM)
    term.line()
    return CONTINUE


def _cmd_clear(ctx: Context, raw: str) -> str:
    term.clear_screen()
    return CONTINUE


def _cmd_exit(ctx: Context, raw: str) -> str:
    return EXIT


def _relay_connected(ctx: Context) -> bool:
    return ctx.client is not None and getattr(ctx.client, "connected", False)


def _parse_pending_target(raw: str) -> str | None:
    """Extrai um alvo opcional de `accept "nome"` / `deny nome` — usado só
    para desambiguar quando há mais de um pedido pendente. `accept`/`deny`
    sem argumento continuam funcionando (pega o mais antigo da fila)."""
    m = re.match(r'^/?(?:accept|deny)\s+"?([A-Za-z0-9_-]+)"?\s*$', raw.strip(), re.IGNORECASE)
    return m.group(1) if m else None


def _cmd_connect(ctx: Context, raw: str) -> str:
    target = _parse_connect_target(raw)
    term.line()
    if not target:
        term.line("  [!] Uso: connect to user \"nome\"", C.RED)
        term.line()
        return CONTINUE
    if target == ctx.username:
        term.line("  [!] Você não pode conectar consigo mesmo.", C.RED)
        term.line()
        return CONTINUE
    if not _relay_connected(ctx):
        term.line("  [!] Não conectado ao relay.", C.RED)
        term.line()
        return CONTINUE
    cstate.set_outgoing(target)
    if not ctx.client.send_connect_request(target):
        term.line("  [!] Falha ao enviar o pedido — conexão com o relay perdida.", C.RED)
        term.line()
        return CONTINUE
    term.line(f"  [*] Connection request sent to \"{target}\".", C.CYAN)
    term.line()
    return CONTINUE


def _cmd_accept_deny(ctx: Context, raw: str) -> str:
    decision = "accept" if raw.strip().lower().startswith("accept") else "deny"
    term.line()
    target = _parse_pending_target(raw)
    frm = cstate.pop_incoming(target)
    if frm is None:
        term.line("  [i] Não há pedido de conexão pendente.", C.YELLOW)
        pending = cstate.list_incoming()
        if pending:
            term.line(f"      Pedidos pendentes: {', '.join(pending)}", C.GREY, C.DIM)
        term.line()
        return CONTINUE
    if not _relay_connected(ctx):
        term.line("  [!] Não conectado ao relay.", C.RED)
        term.line()
        return CONTINUE
    if not ctx.client.send_connect_response(frm, decision):
        term.line("  [!] Falha ao enviar a resposta — conexão com o relay perdida.", C.RED)
        term.line()
        return CONTINUE
    if decision == "accept":
        term.line(f'  [+] Connection accepted with "{frm}".', C.GREEN, C.BOLD)
        term.line("      (negotiating secure session...)", C.GREY, C.DIM)
    else:
        term.line(f'  [!] Connection denied for "{frm}".', C.RED)
    term.line()
    return CONTINUE


def _parse_chat_target(raw: str) -> str | None:
    m = re.match(r'^/?chat\s+"?([A-Za-z0-9_-]+)"?\s*$', raw.strip(), re.IGNORECASE)
    return m.group(1) if m else None


def _cmd_chat(ctx: Context, raw: str) -> str:
    """
    `chat "nome"` entra num modo de conversa cifrada com um peer que já
    tem uma sessão segura ESTABLISHED (ver active_sessions.py, Fase 4).
    Cada linha digitada é cifrada com XChaCha20-Poly1305 (client/chat.py)
    e mandada via TYPE_ENCRYPTED_MESSAGE — o relay nunca vê o texto.
    """
    peer = _parse_chat_target(raw)
    term.line()
    if not peer:
        term.line('  [!] Uso: chat "nome"', C.RED)
        term.line()
        return CONTINUE
    if peer == ctx.username:
        term.line("  [!] Você não pode conversar consigo mesmo.", C.RED)
        term.line()
        return CONTINUE

    session = active_sessions.get(peer)
    if session is None:
        term.line(f'  [!] Nenhuma sessão segura estabelecida com "{peer}".', C.RED)
        term.line(f'      Use: connect to user "{peer}"', C.GREY, C.DIM)
        term.line()
        return CONTINUE

    term.boxed_title(f"SECURE SESSION — {peer}", 48)
    term.line(f"  E2EE: {term.color('XChaCha20-Poly1305', C.GREEN)}")
    term.line(f"  Session: {session.session_id[:8]}...", C.GREY)
    term.line("  (/back ou /exit para sair do modo de chat)", C.GREY, C.DIM)
    term.line()

    chat_state.enter(peer)
    try:
        while True:
            if not _relay_connected(ctx):
                term.line("  [!] Relay connection lost — leaving chat.", C.RED)
                term.line()
                break

            try:
                text = input(term.color("You> ", C.CYAN, C.BOLD))
            except EOFError:
                term.line()
                break
            except KeyboardInterrupt:
                term.line()
                term.line("  (use /back para sair do chat)", C.GREY)
                continue

            stripped = text.strip()
            if stripped.lower() in ("/back", "/exit"):
                term.line("  [*] Leaving chat.", C.GREY, C.DIM)
                term.line()
                break
            if not stripped:
                continue

            # A sessão pode ter sido invalidada enquanto conversávamos
            # (ex.: reconexão do relay — ver client/main.py:_on_reconnected).
            session = active_sessions.get(peer)
            if session is None:
                term.line(f'  [!] Secure session expired with "{peer}".', C.RED)
                term.line(f'      Use: connect to user "{peer}" to re-establish it.', C.GREY, C.DIM)
                term.line()
                break

            payload_b64 = chat.encrypt_outgoing(session, ctx.username, stripped)
            if not ctx.client.send_encrypted_message(peer, session.session_id, payload_b64):
                term.line("  [!] Failed to send — relay connection lost.", C.RED)
                term.line()
    finally:
        chat_state.leave()

    return CONTINUE


# Mapa: primeira palavra (sem '/') -> handler
_HANDLERS = {
    "help": _cmd_help,
    "users": _cmd_users,
    "status": _cmd_status,
    "fingerprint": _cmd_fingerprint,
    "identity": _cmd_identity,
    "clear": _cmd_clear,
    "exit": _cmd_exit,
    "quit": _cmd_exit,
    "connect": _cmd_connect,
    "accept": _cmd_accept_deny,
    "deny": _cmd_accept_deny,
    "chat": _cmd_chat,
}


def dispatch(ctx: Context, raw: str) -> str:
    """Interpreta uma linha de comando e executa o handler. Retorna CONTINUE/EXIT."""
    text = raw.strip()
    if not text:
        return CONTINUE

    # Normaliza: remove '/' inicial para casar com o mapa.
    head = text[1:] if text.startswith("/") else text
    # Primeira palavra decide o handler.
    first = head.split(maxsplit=1)[0].lower()

    handler = _HANDLERS.get(first)
    if handler is None:
        term.line()
        term.line(f"  [!] Comando desconhecido: {first}", C.RED)
        term.line("      digite /help para ver os comandos.", C.GREY)
        term.line()
        return CONTINUE
    return handler(ctx, text)

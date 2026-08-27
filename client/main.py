"""
main.py — Entrypoint do cliente NightChat (Fase 1).

Fluxo:
    init terminal -> banner (ASCII art) -> boot sequence -> login ->
    tela de usuários online -> shell de comandos -> /exit

Fase 1 é 100% local (sem servidor, sem cripto de rede ainda). O objetivo
é a EXPERIÊNCIA de terminal e a base de código organizada para as fases
seguintes.

Execução:
    python -m client.main
ou:
    python client/main.py
"""

from __future__ import annotations

import sys
import os

# Permite tanto 'python -m client.main' quanto 'python client/main.py'.
if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from client import terminal as term
    from client import authentication as auth
    from client import commands
    from client import presence
    from client import connection_state as cstate
    from client import active_sessions
    from client import chat
    from client import chat_state
    from client import crypto
    from client.aead import DecryptionError
    from client.chat import ReplayError, WrongSessionError
    from client.handshake import HandshakeManager
    from client.terminal import C
else:
    from . import terminal as term
    from . import authentication as auth
    from . import commands
    from . import presence
    from . import connection_state as cstate
    from . import active_sessions
    from . import chat
    from . import chat_state
    from . import crypto
    from .aead import DecryptionError
    from .chat import ReplayError, WrongSessionError
    from .handshake import HandshakeManager
    from .terminal import C

PROMPT = "NightChat> "


def _reprint_prompt() -> None:
    """Reimprime o prompt certo depois de um evento assíncrono — 'You> '
    se o usuário estiver em modo `chat` com alguém, senão o prompt normal
    do shell (ver client/chat_state.py)."""
    peer = chat_state.current()
    prompt = "You> " if peer else PROMPT
    sys.stdout.write(term.color(prompt, C.CYAN, C.BOLD))
    sys.stdout.flush()


def _on_incoming_request(from_user: str) -> None:
    """Callback de rede (thread do relay_client): chega a qualquer momento,
    inclusive enquanto o shell está bloqueado esperando input()."""
    cstate.push_incoming(from_user)
    term.line()
    term.boxed_title("INCOMING CONNECTION", 46)
    term.line()
    term.line(f'User "{from_user}" wants to establish', C.WHITE)
    term.line("a communication session.", C.WHITE)
    term.line()
    _reprint_prompt()


def _on_disconnected(reason: str) -> None:
    term.line()
    term.line("  [!] Relay connection lost.", C.RED, C.BOLD)
    term.line(f"      ({reason})", C.GREY, C.DIM)
    term.line()
    _reprint_prompt()


def _on_reconnected() -> None:
    term.line()
    term.line("  [+] Relay connection restored.", C.GREEN, C.BOLD)
    # As chaves X25519 do handshake são efêmeras e o relay já invalidou
    # (server-side) qualquer sessão de handshake em aberto quando a
    # conexão anterior caiu (ver server/relay.py, cleanup no disconnect).
    # Não reaproveitamos silenciosamente uma SessionState antiga — o
    # usuário precisa refazer `connect to user` para negociar de novo.
    expired_peers = active_sessions.list_peers()
    for peer in expired_peers:
        term.line(f'  [!] Secure session with "{peer}" expired.', C.YELLOW)
    active_sessions.reset()
    if expired_peers:
        term.line("  [*] Use 'connect to user \"name\"' to re-establish a secure channel.", C.GREY, C.DIM)
    term.line()
    _reprint_prompt()


def _on_connect_result(from_user: str, decision: str, session_id: str | None, handshake_manager: HandshakeManager) -> None:
    term.line()
    if decision == "accept":
        term.line(f'  [+] Connection accepted.', C.GREEN, C.BOLD)
        term.line(f'      "{from_user}" accepted your connection request.', C.GREY, C.DIM)
        if session_id:
            term.line("  [*] Negotiating secure session...", C.GREY, C.DIM)
            handshake_manager.initiate(from_user, session_id)
        else:
            term.line("  [!] Relay did not provide a session id — cannot start handshake.", C.RED)
    else:
        term.line(f'  [!] Connection denied.', C.RED)
        term.line(f'      "{from_user}" denied your connection request.', C.GREY, C.DIM)
    cstate.pop_outgoing()
    term.line()
    _reprint_prompt()


def _on_handshake_established(session) -> None:
    active_sessions.store(session)
    term.line()
    term.line(f'  [+] Secure session established with "{session.peer_username}".', C.GREEN, C.BOLD)
    term.line(f"      session: {session.session_id[:8]}...", C.GREY, C.DIM)
    term.line(f'      type: chat "{session.peer_username}" to start talking', C.GREY, C.DIM)
    term.line()
    _reprint_prompt()


def _on_encrypted_message(from_user: str, session_id: str, payload_b64: str) -> None:
    session = active_sessions.get(from_user)
    if session is None:
        term.line()
        term.line(f'  [!] Received an encrypted message from "{from_user}" with no active session — discarded.', C.YELLOW)
        term.line()
        _reprint_prompt()
        return

    try:
        plaintext = chat.decrypt_incoming(session, session_id, from_user, payload_b64)
    except WrongSessionError:
        term.line()
        term.line(f'  [!] Message from "{from_user}" does not match the active session — discarded.', C.RED)
        term.line()
        _reprint_prompt()
        return
    except ReplayError:
        term.line()
        term.line(f'  [!] Discarded a replayed/duplicate/out-of-order message from "{from_user}".', C.YELLOW)
        term.line()
        _reprint_prompt()
        return
    except DecryptionError:
        term.line()
        term.line(f'  [!] Discarded a message from "{from_user}" that failed authentication (tampered?).', C.RED)
        term.line()
        _reprint_prompt()
        return

    term.line()
    term.line(f"{from_user}> {plaintext}", C.MAGENTA)
    term.line()
    _reprint_prompt()


def _on_handshake_failed(session_id: str, peer: str, reason: str) -> None:
    term.line()
    term.line(f'  [!] Secure handshake with "{peer}" failed.', C.RED, C.BOLD)
    term.line(f"      reason: {reason}", C.GREY, C.DIM)
    term.line()
    _reprint_prompt()


def _on_session_end(from_user: str, session_id: str) -> None:
    peer_sessions = [p for p in active_sessions.list_peers() if active_sessions.get(p).session_id == session_id]
    for peer in peer_sessions:
        active_sessions.remove(peer)
    term.line()
    term.line(f'  [!] Secure session with "{from_user}" was ended.', C.YELLOW)
    term.line()
    _reprint_prompt()


def _on_error(data: dict) -> None:
    reason = data.get("reason", "unknown_error")
    term.line()
    term.line(f"  [!] Relay error: {reason}", C.RED)
    term.line()
    _reprint_prompt()


def _post_login_screen(username: str) -> None:
    term.clear_screen()
    term.line()
    term.boxed_title("NIGHTCHAT ONLINE", 46)
    term.line()
    # Reaproveita o handler de /users para mostrar a lista.
    ctx = commands.Context(username=username, fingerprint="")
    commands._cmd_users(ctx, "/users")
    term.line("  digite /help para ver os comandos.", C.GREY)


def _shell(ctx: commands.Context) -> None:
    while True:
        try:
            raw = input(term.color(PROMPT, C.CYAN, C.BOLD))
        except EOFError:
            # Ctrl-D / fim de entrada: encerra limpo.
            term.line()
            raw = "/exit"
        except KeyboardInterrupt:
            # Ctrl-C não derruba o app; pede /exit explícito.
            term.line()
            term.line("  (use /exit para sair)", C.GREY)
            continue

        try:
            result = commands.dispatch(ctx, raw)
        except Exception as e:  # defesa em profundidade: um comando nunca deve
            # derrubar o shell inteiro (ex.: uma queda de rede não tratada
            # em algum ponto interno) — ver auditoria Fase 2, item 8.
            term.line()
            term.line(f"  [!] Unexpected error: {e}", C.RED)
            term.line()
            result = commands.CONTINUE

        if result == commands.EXIT:
            _shutdown_sequence(ctx.username)
            return


def _shutdown_sequence(username: str) -> None:
    """A contrapartida do boot: encerramento visível (sem falsas promessas)."""
    term.line()
    term.type_out(term.color("  [*] Terminating session...", C.YELLOW), 0.01)
    term.pause(0.25)
    term.type_out(term.color("  [*] Clearing temporary session state...", C.YELLOW), 0.01)
    term.pause(0.25)
    term.line()
    term.line("  [+] SESSION TERMINATED", C.GREEN, C.BOLD)
    term.line("      (Fase 1: nenhum dado de rede/cripto foi criado)", C.GREY, C.DIM)
    term.line()


def run() -> int:
    term.init_terminal()
    term.clear_screen()
    term.show_banner()
    term.boot_sequence()

    result = auth.login()
    if result is None:
        term.line()
        term.line("  Encerrando.", C.GREY)
        return 1
    identity, client, crypto_identity = result

    def _fetch_public_key(username: str) -> bytes | None:
        ok, public_key_b64, _err = client.get_public_key(username)
        if not ok or public_key_b64 is None:
            return None
        return crypto.decode_public_key(public_key_b64)

    handshake_manager = HandshakeManager(
        identity=crypto_identity,
        send_relay=client.send_relay,
        fetch_public_key=_fetch_public_key,
    )
    handshake_manager.on_established = _on_handshake_established
    handshake_manager.on_failed = _on_handshake_failed

    presence.set_client(client)
    client.on_incoming_request = _on_incoming_request
    client.on_connect_result = lambda frm, decision, session_id: _on_connect_result(frm, decision, session_id, handshake_manager)
    client.on_relay_message = handshake_manager.handle_message
    client.on_session_end = _on_session_end
    client.on_encrypted_message = _on_encrypted_message
    client.on_error = _on_error
    client.on_disconnected = _on_disconnected
    client.on_reconnected = _on_reconnected

    _post_login_screen(identity.username)

    ctx = commands.Context(
        username=identity.username,
        fingerprint=crypto_identity.fingerprint(),
        client=client,
        crypto_identity=crypto_identity,
    )
    _shell(ctx)
    client.close()
    return 0


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1].lower() == "uninstall":
        if __package__ in (None, ""):
            from client import uninstall
        else:
            from . import uninstall
        sys.exit(uninstall.run())

    try:
        code = run()
    except KeyboardInterrupt:
        print()
        code = 130
    sys.exit(code)


if __name__ == "__main__":
    main()

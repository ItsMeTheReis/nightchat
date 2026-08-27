"""
authentication.py — Fluxo de login do NightChat (Fase 2 contra o relay,
Fase 3 acrescenta a identidade criptográfica local).

O cliente fala com o NightChat Relay (FastAPI) por HTTP:
    GET  /auth/exists?username=...
    POST /auth/register  {username, password}
    POST /auth/login     {username, password}

A senha nunca é gravada localmente: o relay guarda apenas
Argon2id(senha). Em caso de sucesso, o cliente carrega (ou gera, no
primeiro uso) sua identidade criptográfica Ed25519 local
(client/crypto_identity.py) e garante que o relay conhece a chave
pública correspondente — nunca a privada, que não sai desta máquina.

A UI de senha continua mascarada (mostra '*'), como na Fase 1.
"""

from __future__ import annotations

import base64
import os
import sys

from . import crypto
from . import crypto_identity as cryptoid
from . import identity as ident
from . import terminal as term
from .relay_client import RelayClient
from .terminal import C

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared import identity as shared_identity

def _relay_bases() -> tuple[str, str]:
    """
    O cliente só precisa saber UM endereço público do relay
    (NIGHTCHAT_RELAY_URL, ex.: "https://relay.example.com") — o HTTP e o
    WebSocket são derivados dele (http(s):// -> ws(s)://, + "/ws").
    NIGHTCHAT_RELAY_HTTP/NIGHTCHAT_RELAY_WS continuam funcionando como
    override explícito (ex.: para apontar HTTP e WS a hosts diferentes
    atrás de um proxy) e têm prioridade se definidos.
    """
    relay_url = os.getenv("NIGHTCHAT_RELAY_URL")
    if relay_url:
        relay_url = relay_url.rstrip("/")
        if relay_url.startswith("https://"):
            default_http, default_ws = relay_url, "wss://" + relay_url[len("https://") :] + "/ws"
        elif relay_url.startswith("http://"):
            default_http, default_ws = relay_url, "ws://" + relay_url[len("http://") :] + "/ws"
        else:
            default_http, default_ws = f"http://{relay_url}", f"ws://{relay_url}/ws"
    else:
        default_http, default_ws = "http://localhost:8000", "ws://localhost:8000/ws"

    http_base = os.getenv("NIGHTCHAT_RELAY_HTTP", default_http)
    ws_base = os.getenv("NIGHTCHAT_RELAY_WS", default_ws)
    return http_base, ws_base


DEFAULT_USERNAME = os.getenv("NIGHTCHAT_USERNAME", "morningstar")
DEFAULT_HTTP_BASE, DEFAULT_WS_BASE = _relay_bases()

MAX_ATTEMPTS = 3
MIN_PASSWORD_LEN = 6


def _ask_username() -> str:
    term.line()
    raw = input(term.color(f"Username [{DEFAULT_USERNAME}]: ", C.WHITE))
    return raw.strip() or DEFAULT_USERNAME


def _register_flow(client: RelayClient, username: str) -> ident.Identity | None:
    term.line()
    term.line(f'  Nenhuma conta "{username}" encontrada no relay. Criando conta.', C.YELLOW)
    term.line("  Defina uma senha para esta identidade.", C.GREY)
    term.line()
    for _ in range(MAX_ATTEMPTS):
        pw1 = term.masked_input(f"  Set password for {username}: ")
        if len(pw1) < MIN_PASSWORD_LEN:
            term.line(f"  [!] A senha precisa de ao menos {MIN_PASSWORD_LEN} caracteres.", C.RED)
            continue
        pw2 = term.masked_input("  Confirm password: ")
        if pw1 != pw2:
            term.line("  [!] As senhas não conferem. Tente novamente.", C.RED)
            continue
        ok, err = client.register(username, pw1)
        if not ok:
            term.line(f"  [!] Falha ao registrar no relay: {err}", C.RED)
            return None
        term.line()
        term.line("  [+] Conta criada no relay.", C.GREEN, C.BOLD)
        identity_id = ident.get_or_create_identity_id(username)
        return ident.Identity(username=username, identity_id=identity_id)
    term.line("  [!] Não foi possível configurar a conta.", C.RED)
    return None


def _login_flow(client: RelayClient, username: str) -> ident.Identity | None:
    term.line()
    term.line(f'execute NightChat as "{username}"', C.CYAN, C.BOLD)
    term.line()
    for attempt in range(1, MAX_ATTEMPTS + 1):
        password = term.masked_input("Password: ")
        ok, err = client.login(username, password)
        if ok:
            term.line()
            term.line("  [+] Authentication successful.", C.GREEN, C.BOLD)
            identity_id = ident.get_or_create_identity_id(username)
            return ident.Identity(username=username, identity_id=identity_id)
        remaining = MAX_ATTEMPTS - attempt
        if remaining > 0:
            term.line(f"  [!] Access denied. {remaining} tentativa(s) restante(s).", C.RED)
        else:
            term.line(f"  [!] Access denied ({err}).", C.RED)
    return None


def _load_and_publish_identity(client: RelayClient, username: str) -> cryptoid.CryptographicIdentity | None:
    """
    Garante que:
    1. existe uma identidade Ed25519 local para `username` (gera se for a
       primeira vez);
    2. o relay conhece a chave pública correspondente.

    Política de troca de chave (Fase 3, documentada — ver README.md e
    docs/ARCHITECTURE.md): se o relay já tem uma chave pública publicada
    para este username e ela é DIFERENTE da que corresponde à chave
    privada local, o NightChat NÃO sobrescreve silenciosamente nada — a
    função retorna None (o chamador trata como falha de login). Resolver
    isso automaticamente (qual das duas chaves "vence") é uma decisão de
    confiança que não deve ser tomada sem o usuário perceber; um fluxo de
    resolução explícito fica para uma fase futura.
    """
    identity, created = cryptoid.load_or_create(username)

    term.line()
    if created:
        term.line("  [*] Generating cryptographic identity...", C.GREY, C.DIM)
        term.line("  [+] Identity generated.", C.GREEN, C.BOLD)
    else:
        term.line("  [*] Loading cryptographic identity...", C.GREY, C.DIM)
        term.line("  [+] Identity loaded.", C.GREEN, C.BOLD)

    term.line()
    term.line("  [*] Verifying public key with relay...", C.GREY, C.DIM)
    ok, relay_key_b64, err = client.get_public_key(username)
    local_key_b64 = identity.public_key_b64()

    if not ok:
        term.line(f"  [!] Falha ao consultar chave pública no relay: {err}", C.RED)
        return None

    if relay_key_b64 is None:
        # Primeira vez que esta conta publica uma chave.
        term.line("  [*] Publishing public key...", C.GREY, C.DIM)
        message = shared_identity.key_binding_message(username, local_key_b64)
        signature_b64 = base64.b64encode(identity.sign(message)).decode("ascii")
        ok, err = client.publish_public_key(local_key_b64, signature_b64)
        if not ok:
            term.line(f"  [!] Falha ao publicar chave pública: {err}", C.RED)
            return None
        term.line("  [+] Public key registered.", C.GREEN, C.BOLD)
    elif relay_key_b64 != local_key_b64:
        relay_public_key = crypto.decode_public_key(relay_key_b64)
        relay_fp = crypto.fingerprint(relay_public_key) if relay_public_key else "(chave inválida)"
        term.line()
        term.line("  [!] Cryptographic identity changed.", C.RED, C.BOLD)
        term.line(f"      Relay fingerprint : {relay_fp}", C.GREY)
        term.line(f"      Local fingerprint : {identity.fingerprint()}", C.GREY)
        term.line("      Isso pode significar que a identidade local foi perdida/trocada,", C.GREY, C.DIM)
        term.line("      ou que outra sessão publicou uma chave diferente para este username.", C.GREY, C.DIM)
        term.line("      Por segurança, o NightChat não sobrescreve isso automaticamente.", C.GREY, C.DIM)
        return None
    # else: relay_key_b64 == local_key_b64 -> já está tudo certo, nada a fazer.

    term.line()
    term.line("  [+] Identity ready.", C.GREEN, C.BOLD)
    return identity


def login(username: str | None = None) -> tuple[ident.Identity, RelayClient, cryptoid.CryptographicIdentity] | None:
    """Ponto de entrada de autenticação. Retorna (Identity, RelayClient
    conectado, CryptographicIdentity) ou None."""
    chosen = username or _ask_username()

    client = RelayClient(http_base=DEFAULT_HTTP_BASE, ws_base=DEFAULT_WS_BASE, username=chosen)

    term.line()
    term.line(f"  [*] Conectando ao relay ({DEFAULT_HTTP_BASE}) ...", C.GREY, C.DIM)
    if not client.exists(chosen) and not _relay_reachable(client):
        term.line(f"  [!] Não foi possível alcançar o relay em {DEFAULT_HTTP_BASE}.", C.RED)
        term.line("      Suba o servidor primeiro: uvicorn server.main:app", C.GREY, C.DIM)
        return None

    if client.exists(chosen):
        identity = _login_flow(client, chosen)
    else:
        identity = _register_flow(client, chosen)

    if identity is None:
        return None

    crypto_identity = _load_and_publish_identity(client, chosen)
    if crypto_identity is None:
        return None

    ok, err = client.connect_ws()
    if not ok:
        term.line(f"  [!] Falha ao abrir conexão WebSocket com o relay: {err}", C.RED)
        return None

    return identity, client, crypto_identity


def _relay_reachable(client: RelayClient) -> bool:
    # client.exists() já faz uma chamada HTTP real; se o relay estiver fora
    # do ar, ela retorna False silenciosamente (status 0). Distinguimos
    # "usuário não existe" de "relay fora do ar" tentando de novo e olhando
    # o resultado bruto seria mais preciso, mas para o propósito desta fase
    # (mensagem de erro amigável) uma nova tentativa com /health basta.
    from .relay_client import _http_get  # import tardio: função utilitária interna

    status, _ = _http_get(f"{client.http_base}/health")
    return status == 200

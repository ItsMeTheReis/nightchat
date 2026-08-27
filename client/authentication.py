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

IDENTIDADE PADRÃO (revisão pós-release): uma instalação nova NÃO tem
username padrão. `NIGHTCHAT_USERNAME` continua existindo só como uma
conveniência OPCIONAL de desenvolvimento/teste (sugere um valor no
prompt, mas não é obrigatório nem é definido pelo instalador) — sem essa
variável, o prompt não sugere nada e exige que o usuário digite um
username de verdade. "morningstar"/"sofia" nunca são um fallback
automático aqui; eles só aparecem em testes, fixtures e exemplos de
documentação.
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

# Relay oficial da release (ver docs/DEPLOYMENT.md). NÃO ESTÁ NO AR ainda
# nesta versão — não há VPS/domínio provisionado neste ambiente de
# desenvolvimento (ver docs/DEPLOYMENT.md, seção "O que falta"). Está
# aqui como o padrão de PRODUÇÃO (nunca localhost — ver auditoria
# multi-máquina) para que o comportamento do cliente já seja o correto
# assim que a infraestrutura real existir. Até lá, tentar conectar sem
# configurar NIGHTCHAT_RELAY_URL vai falhar com uma mensagem clara
# (ver _ensure_relay_reachable), não travar silenciosamente.
OFFICIAL_RELAY_HTTP = "https://relay.nightchat.dev"
OFFICIAL_RELAY_WS = "wss://relay.nightchat.dev/ws"


def _relay_bases() -> tuple[str, str]:
    """
    O cliente só precisa saber UM endereço público do relay
    (NIGHTCHAT_RELAY_URL, ex.: "https://relay.example.com") — o HTTP e o
    WebSocket são derivados dele (http(s):// -> ws(s)://, + "/ws").
    NIGHTCHAT_RELAY_HTTP/NIGHTCHAT_RELAY_WS continuam funcionando como
    override explícito (ex.: para apontar HTTP e WS a hosts diferentes
    atrás de um proxy) e têm prioridade se definidos.

    Sem NENHUMA variável definida, o padrão é o relay OFICIAL da release
    (`OFFICIAL_RELAY_HTTP`/`OFFICIAL_RELAY_WS`) — nunca localhost. Para
    desenvolvimento local, defina NIGHTCHAT_RELAY_URL=http://localhost:8000
    explicitamente.
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
        default_http, default_ws = OFFICIAL_RELAY_HTTP, OFFICIAL_RELAY_WS

    http_base = os.getenv("NIGHTCHAT_RELAY_HTTP", default_http)
    ws_base = os.getenv("NIGHTCHAT_RELAY_WS", default_ws)
    return http_base, ws_base


# Conveniência OPCIONAL de dev/teste — nunca definida pelo instalador,
# nunca um valor "de fábrica". Ver docstring do módulo.
DEFAULT_USERNAME = os.getenv("NIGHTCHAT_USERNAME") or None
DEFAULT_HTTP_BASE, DEFAULT_WS_BASE = _relay_bases()

MAX_ATTEMPTS = 3
MIN_PASSWORD_LEN = 6


def _ask_username() -> str:
    """
    Pede o username. Só sugere um valor padrão se o desenvolvedor
    explicitamente definiu NIGHTCHAT_USERNAME no ambiente — numa
    instalação real isso nunca está definido, então o prompt fica
    "Username: " puro e exige uma resposta não-vazia.
    """
    while True:
        term.line()
        if DEFAULT_USERNAME:
            raw = input(term.color(f"Username [{DEFAULT_USERNAME}]: ", C.WHITE))
            candidate = raw.strip() or DEFAULT_USERNAME
        else:
            raw = input(term.color("Username: ", C.WHITE))
            candidate = raw.strip()
        if candidate:
            return candidate
        term.line("  [!] Username não pode ficar em branco.", C.RED)


def _register_flow(client: RelayClient, username: str) -> ident.Identity | None:
    term.line()
    term.boxed_title("NO IDENTITY FOUND", 46)
    term.line()
    term.line(f'  No account "{username}" exists on this relay yet.', C.YELLOW)
    term.line("  Create a new account?", C.WHITE)
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
        term.line("  [+] Account created successfully.", C.GREEN, C.BOLD)
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
    if not _ensure_relay_reachable():
        term.line()
        term.line("  [i] Cannot continue without a relay connection.", C.GREY)
        return None

    chosen = username or _ask_username()

    client = RelayClient(http_base=DEFAULT_HTTP_BASE, ws_base=DEFAULT_WS_BASE, username=chosen)

    term.line()
    term.line(f"  [*] Connecting to relay ({DEFAULT_HTTP_BASE}) ...", C.GREY, C.DIM)

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

    term.line()
    term.line("  [+] Connected to relay.", C.GREEN, C.BOLD)
    term.line("  [+] Online.", C.GREEN, C.BOLD)

    return identity, client, crypto_identity


def _check_relay_health() -> bool:
    from .relay_client import _http_get  # import tardio: função utilitária interna

    status, _ = _http_get(f"{DEFAULT_HTTP_BASE}/health")
    return status == 200


def _prompt_relay_unreachable() -> bool:
    """
    Mostra um erro claro (item 15 da auditoria multi-máquina) — não um
    'OFFLINE' silencioso — e pergunta se o usuário quer tentar de novo.
    Retorna True se deve tentar de novo, False se deve desistir.
    """
    term.line()
    term.line("  [!] Unable to connect to NightChat Relay.", C.RED, C.BOLD)
    term.line()
    term.line(f"      Relay: {DEFAULT_HTTP_BASE}", C.GREY)
    term.line()
    term.line("      Possible causes:", C.GREY)
    term.line("        - Internet unavailable", C.GREY, C.DIM)
    term.line("        - Relay unavailable", C.GREY, C.DIM)
    term.line("        - Invalid relay configuration (NIGHTCHAT_RELAY_URL)", C.GREY, C.DIM)
    term.line()
    try:
        answer = input(term.color("      Retry? [Y/n]: ", C.WHITE)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        term.line()
        answer = "n"
    return answer in ("", "y", "yes")


def _ensure_relay_reachable() -> bool:
    """Confere o relay ANTES de pedir username/senha — não faz sentido
    coletar credenciais só para descobrir depois que o relay está fora
    do ar. Faz o operador decidir explicitamente entre tentar de novo ou
    desistir, em vez de travar silenciosamente."""
    while not _check_relay_health():
        if not _prompt_relay_unreachable():
            return False
    return True

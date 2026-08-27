# NightChat

> Um messenger de **terminal** com comunicação criptografada ponta-a-ponta de verdade.
> Projeto **educacional sério** — sem promessas de "cripto militar" ou "apagamento absoluto".
> **Estado atual: Release Candidate.** Fases 1-5 implementadas (relay, identidade
> Ed25519, handshake X25519/STS, chat E2EE com XChaCha20-Poly1305) e instalador
> para Windows via PowerShell. Ver "Limitações conhecidas" antes de confiar
> nisso para algo sensível de verdade.

## Instalação rápida (Windows)

```powershell
irm https://raw.githubusercontent.com/ItsMeTheReis/nightchat/main/install.ps1 | iex
```

Isso baixa o NightChat do GitHub, prepara um Python privado para ele
(instala Python via `winget` se você não tiver), instala as
dependências, configura o comando `nightchat` e já abre o app — sem
precisar saber o que é Python, pip, venv ou git. Depois da primeira
instalação, `nightchat` funciona em qualquer PowerShell novo. Detalhes,
limitações honestas do instalador e como desinstalar: seção
"Instalação" mais abaixo.

```
 ███    ██ ██  ██████  ██   ██ ████████  ██████ ██   ██  █████  ████████
 ████   ██ ██ ██       ██   ██    ██    ██      ██   ██ ██   ██    ██
 ██ ██  ██ ██ ██   ███ ███████    ██    ██      ███████ ███████    ██
 ██  ██ ██ ██ ██    ██ ██   ██    ██    ██      ██   ██ ██   ██    ██
 ██   ████ ██  ██████  ██   ██    ██     ██████ ██   ██ ██   ██    ██
              terminal-based encrypted messenger
```

## O que é

Dois usuários rodam o NightChat em seus computadores e estabelecem uma sessão
de conversa criptografada direto pelo terminal, encaminhada por um **relay**
que nunca vê o conteúdo em claro. A filosofia é *messages are ephemeral by
default* **e** *minimização extrema de dados*: o servidor não guarda
histórico de mensagens, não coleta nenhum dado pessoal, e uma conta é só
`username` + `password_hash`.

A arquitetura completa, o **threat model** e o **protocolo criptográfico** estão
em [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). Leia antes de evoluir a cripto.

## Modelo de privacidade e identidade

Criar uma conta pede **só** username e senha — nada de nome real, e-mail,
telefone, CPF, endereço, data de nascimento ou avatar.

```
username VARCHAR(20) PRIMARY KEY   -- a própria identidade da conta; sem UUID interno
password_hash TEXT                 -- Argon2id; a senha em si nunca é gravada
```

Regras de username: 3-20 caracteres, letras, números, `_` ou `-`, sem
espaços. **Case-insensitive por normalização**: o servidor sempre reduz o
username digitado a minúsculas antes de comparar/gravar, então
`morningstar`, `MorningStar` e `MORNINGSTAR` são sempre a mesma conta (ver
`server/validation.py`).

O que o relay **nunca** guarda: mensagens (não existe tabela para isso),
histórico de conversas, lista persistente de contatos, dado pessoal de
qualquer tipo. Presença (quem está online agora) vive só em memória
enquanto o processo roda — desconectou, a entrada some (`server/presence.py`).

## Identidade criptográfica (Fase 3)

**Conta do relay ≠ identidade criptográfica.** São duas coisas
separadas, de propósito:

| | Conta NightChat | Identidade criptográfica |
|---|---|---|
| O que é | `username` + senha | par de chaves **Ed25519** |
| Onde vive | relay (PostgreSQL/SQLite) | **só no dispositivo do usuário** |
| Prova | Argon2id(senha) verificado pelo servidor | assinatura verificada com a chave pública |
| O relay conhece | username, hash da senha, **chave pública** | **nunca a chave privada** |

**Geração e algoritmo.** No primeiro uso de um username neste
dispositivo, o cliente gera um par Ed25519 via **PyNaCl** (libsodium) —
`client/crypto.py`. Regra do projeto: nenhuma primitiva criptográfica é
implementada na mão, só composição de biblioteca madura. Nos usos
seguintes, a mesma identidade é recarregada — nunca gerada de novo.

**Onde a chave privada fica.** Localmente, nunca no relay, nunca no
banco, nunca em log, nunca no JWT, nunca no protocolo de rede. No
Windows (cliente inicial), ela é protegida com **DPAPI**
(`CryptProtectData`/`CryptUnprotectData`, a API de proteção de dados
nativa do Windows, amarrada à conta do usuário na máquina local) via
`ctypes` puro — sem depender de `pywin32`. Existe uma abstração
`IdentityStore` (`client/identity_store.py`) para permitir
`LinuxIdentityStore`/`MacIdentityStore` (keyring/Secret Service/Keychain)
quando o cliente rodar nessas plataformas — **não implementado ainda**;
o fallback multiplataforma atual (`PlaintextIdentityStore`) grava em
texto puro com permissão 0600 e é deliberadamente marcado como mais
fraco, nunca escondido.

**Fingerprint.** `SHA-256(chave pública Ed25519)`, em hex maiúsculo,
formatado em blocos de 4 caracteres — determinístico, derivado **só** da
chave pública (nunca do username, de um identificador aleatório ou de
qualquer dado pessoal). Dois usuários com a mesma chave pública sempre
calculam o mesmo fingerprint de forma independente — é a base para
verificação manual fora de banda (`identity verify "nome"` no shell).

**Publicação da chave pública.**

```
PUT /users/me/public-key   (Authorization: Bearer <jwt>)
    {"public_key": "<base64, 32 bytes>", "signature": "<base64>"}
GET /users/{username}/public-key
    -> {"username": ..., "public_key": "<base64>" | null}
```

O dono da chave é **sempre** a identidade do JWT autenticado — o corpo da
requisição nem tem um campo `username`. `PUT` exige **prova de posse**:
uma assinatura Ed25519 (com a chave PRIVADA) sobre a mensagem canônica
`shared/identity.py:key_binding_message(username, public_key)`. Isso
prova que quem está publicando controla a chave privada correspondente —
e como efeito colateral, rejeita qualquer "chave pública" que não seja um
ponto Ed25519 de verdade (não dá para forjar uma assinatura válida sem a
chave privada real). `GET` é público, sem autenticação — chave pública é
informação pública por natureza — mas com o mesmo rate limit de
`/auth/exists`.

**Troca inesperada de chave.** Se o relay já tem uma chave publicada para
um username e ela é diferente da que corresponde à identidade local
carregada, o cliente **não sobrescreve silenciosamente**: mostra
`[!] Cryptographic identity changed.` com os dois fingerprints e recusa
continuar o login. Não existe ainda um fluxo de resolução automática
(qual das duas "vence") — essa é uma decisão de confiança que fica para
uma fase futura; por ora, resolver exige intervenção manual (ex.: apagar
a identidade local se você tem certeza que o relay está certo).

**`FASE 3 ≠ E2EE`.** Ter uma identidade Ed25519 publicada, por si só, não
estabelece nenhum segredo compartilhado entre dois usuários — isso é o
handshake X25519 da Fase 4, descrito a seguir.

## Handshake seguro X25519/STS (Fase 4)

Depois que `accept` acontece (aprovação social, Fase 2, inalterada), os
dois clientes estabelecem uma sessão criptográfica — **sem trocar
mensagem nenhuma ainda**, só as chaves. `TYPE_RELAY`/`TYPE_SESSION_END`
(definidos desde a Fase 2, até aqui não-funcionais) passam a rotear de
verdade, mas só esse handshake — o relay copia o payload sem entendê-lo.

**`session_id`:** mintado pelo **relay** (não pelo cliente) no exato
momento em que processa um `connect_response(accept)` — vai embutido na
resposta que o requerente recebe. O relay registra
`{session_id: (initiator, responder)}` e só roteia `TYPE_RELAY`/
`TYPE_SESSION_END` daquele id exatamente entre essas duas contas —
qualquer outro par ou um terceiro tentando usá-lo é rejeitado com
`unknown_session` (`server/sessions.py`).

**Troca (3 mensagens, Station-to-Station), dentro do payload opaco de `TYPE_RELAY`:**
```
1. initiator → responder : {kind: "handshake_init",     eph_pub}
2. responder → initiator : {kind: "handshake_response",  eph_pub, signature}
3. initiator → responder : {kind: "handshake_confirm",   signature}
```
`signature` em (2)/(3) é sempre sobre o **mesmo transcript canônico**
(`shared/handshake.py:transcript(session_id, initiator, responder, eph_i, eph_r)`,
com cada campo *length-prefixed* para eliminar ambiguidade de
concatenação) — uma simplificação deliberada do esboço original do
`ARCHITECTURE.md` (lá cada lado assinava a dupla numa ordem "própria";
aqui a ordem é sempre fixa, o que elimina bug de transposição ao montar
ou verificar a mensagem).

**Chaves de sessão:** X25519 via PyNaCl (`crypto_scalarmult`/
`crypto_scalarmult_base` — primitiva de baixo nível do libsodium, nunca
implementada na mão), com o segredo compartilhado passando por
**HKDF-SHA256** (`cryptography` lib) para derivar `k_send`/`k_recv`
**por direção** — a chave que A usa para mandar a B nunca é igual à que
usa para receber de B. Guardadas em `SessionState`
(`client/session.py`), só em memória, nunca em disco.

**O que isso garante:**
- **Autenticação mútua:** cada assinatura é verificada com a chave
  Ed25519 **publicada no relay (Fase 3)** — sem a privada correspondente,
  ninguém forja uma assinatura válida, nem mesmo um relay malicioso
  tentando trocar uma chave efêmera em trânsito (o iniciador monta seu
  transcript com a **própria** `eph_pub`, nunca a que passou pela rede —
  qualquer adulteração de msg 1 é detectada quando a assinatura da
  resposta não bate).
- **Forward secrecy:** as chaves X25519 são efêmeras, geradas do zero a
  cada handshake — comprometer a identidade Ed25519 de longo prazo
  depois não decifra sessões passadas.
- **Anti-replay do handshake:** o `session_id` entra no transcript
  assinado — uma assinatura de uma sessão não serve para outra.
  Mensagens duplicadas na mesma sessão são descartadas assim que ela sai
  do dicionário de handshakes pendentes (estabelecida ou já falhada).
- **Robustez a mensagens fora de ordem e timeout:** a máquina de estados
  do handshake (`client/handshake.py`) só aceita o tipo de mensagem
  esperado para o papel/fase atual; qualquer coisa fora disso é
  descartada sem crash. Cada handshake pendente expira sozinho (padrão
  15s, `threading.Timer`) se a outra parte nunca responder.
- **Rejeição de chave X25519 degenerada:** uma chave efêmera de "ordem
  baixa" (ex.: o ponto todo-zero) nunca produz um segredo compartilhado
  utilizável — `client/x25519.py` rejeita isso tanto na validação de
  entrada quanto via o próprio libsodium recusando o resultado.

## Chat E2EE (Fase 5)

Com a sessão segura estabelecida (Fase 4), `chat "nome"` entra no modo
de conversa cifrada:

```
NightChat> chat "sofia"

╔════════════════════════════════════════════╗
║         SECURE SESSION — sofia              ║
╚════════════════════════════════════════════╝
  E2EE: XChaCha20-Poly1305
  Session: 7f2a9c1e...
  (/back ou /exit para sair do modo de chat)

You> hello
sofia> hello, morningstar
You> /back
NightChat>
```

**Cifra:** XChaCha20-Poly1305 (AEAD) via PyNaCl, usando `k_send`/
`k_recv` já derivados no handshake — nenhuma cifra nova é inventada.
**Nonce nunca é transmitido nem aleatório**: é derivado
deterministicamente do contador da mensagem (`client/aead.py`); como a
chave já é única por sessão e direção, e o contador nunca se repete
(garantido pelo anti-replay), o par (chave, nonce) nunca se repete —
condição necessária para a segurança do XChaCha20-Poly1305.

**Formato do quadro** (dentro do payload opaco de `TYPE_ENCRYPTED_MESSAGE`,
mesmo envelope L1 de sempre — `shared/messaging.py`):
```
{"counter": <int>, "ciphertext": "<base64>"}
```
O `counter` entra como dado associado autenticado (AAD) junto com
`session_id` e o remetente — adulterar qualquer um deles (mesmo sem
tocar no ciphertext) invalida a tag do AEAD.

**Anti-replay real:** cada `SessionState` mantém `send_counter`/
`recv_counter`. Uma mensagem só é aceita se seu contador for **maior**
que o último aceito — contador repetido, retrocedido ou de uma sessão/
remetente diferente é rejeitado (`client/chat.py`), e o estado só avança
depois de autenticar com sucesso (uma tentativa de replay nunca
"consome" o contador). Coberto por 15 testes dedicados
(`tests/test_phase5_chat.py`): replay, duplicata, fora de ordem,
ciphertext adulterado, contador adulterado, session_id adulterado,
mensagem de outro peer, chave incorreta.

**O relay nunca decifra.** `TYPE_ENCRYPTED_MESSAGE` é roteado pela
mesma função que já roteava o handshake (`server/relay.py:_route_opaque`)
— o servidor só confere que o `session_id` é uma sessão real entre
remetente e destinatário e copia `payload` byte a byte, sem entender,
logar ou guardar o conteúdo. Verificado em
`tests/test_phase5_relay_e2ee.py`, inclusive checando que a tabela
`users` não tem nenhuma coluna capaz de guardar uma chave de sessão.

**Reconexão invalida sessões antigas.** Como as chaves X25519 são
efêmeras e o relay já limpa as sessões de handshake de um usuário
quando ele desconecta (Fase 4), o cliente nunca reaproveita
silenciosamente uma `SessionState` depois de uma queda de conexão —
`[+] Relay connection restored.` vem acompanhado de
`[!] Secure session with "..." expired.` para cada sessão que existia, e
o usuário precisa mandar `connect to user` de novo para negociar uma
sessão nova.

`/status` mostra as sessões seguras ativas sem nunca revelar segredos:

```
NightChat> /status

ACTIVE SECURE SESSIONS

  [+] sofia
      Session: 7f2a9c1e...
      E2EE: XChaCha20-Poly1305
      State: ESTABLISHED
```

## Como rodar a partir do código-fonte (desenvolvimento)

> Se você só quer **usar** o NightChat, veja "Instalação (Windows)" mais
> abaixo — `irm ... | iex` faz tudo isto por você. Esta seção é para
> quem vai desenvolver ou rodar o relay.

Instale as dependências (Python 3.10+):

```bash
pip install -r requirements.txt
```

### 1. Banco de dados

Em produção use PostgreSQL. Para rodar localmente sem instalar nada, o
relay também aceita SQLite — basta não definir `DATABASE_URL` (o padrão
é um arquivo `nightchat.db` na raiz do projeto).

Com PostgreSQL real:

```sql
CREATE USER nightchat WITH PASSWORD 'nightchat';
CREATE DATABASE nightchat OWNER nightchat;
```

```bash
# .env
DATABASE_URL=postgresql+psycopg://nightchat:nightchat@localhost:5432/nightchat
JWT_SECRET=<gere um segredo forte, >=32 caracteres>
NIGHTCHAT_ENV=production
NIGHTCHAT_REQUIRE_TLS=true
```

A única tabela (`users`) é criada automaticamente no startup do servidor.

Em produção (`NIGHTCHAT_ENV=production`), o servidor **se recusa a subir**
(`RuntimeError`) se `JWT_SECRET` for fraco/padrão, se `NIGHTCHAT_REQUIRE_TLS`
não estiver ligado, ou se `DATABASE_URL` continuar apontando para SQLite —
ver `server/config.py:validate_production_config`.

### 2. Subir o relay

```bash
uvicorn server.main:app --reload
#   ou:  ./run_server.sh   /   run_server.bat
```

Isso sobe o relay em `http://localhost:8000` (REST de autenticação) e
`ws://localhost:8000/ws` (WebSocket de presença/roteamento). O JWT **não**
vai na URL do WebSocket — o cliente autentica mandando
`{"type": "auth", "token": "..."}` como primeira mensagem depois de
conectar (ver "Segurança" abaixo). Em produção, tudo isso deve ficar atrás
de TLS (`https://` / `wss://`) — `ws://` puro é só para dev local.

### 3. Subir os clientes

Em dois terminais separados (na mesma máquina ou em máquinas diferentes,
desde que apontem para o mesmo relay):

```bash
# Terminal 1
python -m client.main
# Username [morningstar]:  (Enter para aceitar o padrão)
# Password: ********

# Terminal 2
python -m client.main
# Username [morningstar]: sofia
# Password: ********
```

Na primeira vez que um username loga, o relay não o conhece: o cliente
pede para você **definir** uma senha e registra a conta (Argon2id no
servidor). Nas vezes seguintes, ele pede a senha para autenticar.

Dentro do shell (`NightChat>`):

```
/users                        -> lista quem está online agora (dado real do relay)
connect to user "sofia"       -> envia um pedido de conexão via relay + inicia o handshake E2EE ao ser aceito
accept  /  deny                -> responde ao pedido pendente mais antigo (FIFO)
accept "sofia" / deny "sofia" -> responde a um pedido específico, se houver mais de um pendente
chat "sofia"                   -> entra no modo de conversa cifrada (Fase 5) com quem já tem sessão ESTABLISHED
identity                       -> mostra sua identidade criptográfica local (fingerprint, algoritmo, status)
identity verify "sofia"        -> consulta e mostra o fingerprint de outro usuário (comparação manual)
/status, /fingerprint, /help, /clear, /exit
```

Se a conexão com o relay cair no meio da sessão, o cliente avisa
(`[!] Relay connection lost.`) e tenta reconectar sozinho algumas vezes
com backoff — ele não trava nem derruba o shell. Sessões E2EE ativas são
invalidadas nesse processo (chaves efêmeras não são reaproveitadas —
ver "Chat E2EE (Fase 5)" acima); refaça `connect to user` depois de
`[+] Relay connection restored.` se precisar.

### Testando em duas máquinas diferentes

Se `morningstar` e `sofia` estiverem em computadores diferentes, os dois
precisam apontar para o **mesmo** relay publicamente alcançável (não
`localhost`):

```powershell
# em cada máquina, antes de abrir o NightChat:
[Environment]::SetEnvironmentVariable("NIGHTCHAT_RELAY_URL", "https://seu-relay.example.com", "User")
```

(o instalador (`install.ps1 -RelayUrl ...`) já faz isso por você — ver
seção "Instalação" abaixo.) A partir daí, `/users`, `connect to user`,
`accept` e `chat` funcionam exatamente igual, não importa se os dois
clientes estão na mesma rede ou em continentes diferentes — o relay é
quem os conecta.

## Instalação (Windows)

```powershell
irm https://raw.githubusercontent.com/ItsMeTheReis/nightchat/main/install.ps1 | iex
```

O que o instalador faz, na ordem:

1. Confere que é Windows (e detecta a arquitetura, informativo).
2. Procura Python 3.10+; se não achar, instala via `winget` (silencioso).
3. Baixa o código-fonte oficial do GitHub (só de `github.com`/
   `raw.githubusercontent.com` — nunca um mirror configurável).
4. Confere que o download é um arquivo zip válido antes de extrair.
5. Instala em `%LOCALAPPDATA%\NightChat` (`app/` + um `venv/` Python
   privado, isolado do Python do sistema).
6. Cria o comando `nightchat` (`%LOCALAPPDATA%\NightChat\bin\nightchat.cmd`)
   e adiciona esse diretório ao **PATH do usuário** (não precisa de admin).
7. Cria `~\.nightchat` (onde a identidade vai morar) se ainda não existir.
8. Abre o NightChat automaticamente ao final.

Depois da primeira instalação, **`nightchat` funciona em qualquer
PowerShell novo** — sem `python -m client.main`, sem `cd`, sem venv
manual.

Para apontar direto para um relay ao instalar:

```powershell
$script = irm https://raw.githubusercontent.com/ItsMeTheReis/nightchat/main/install.ps1
& ([scriptblock]::Create($script)) -RelayUrl "https://seu-relay.example.com"
```

**Desinstalar:**

```powershell
nightchat uninstall
```

Remove o programa (`%LOCALAPPDATA%\NightChat`) sem perguntar (é só
código, reinstala em segundos), mas **pergunta explicitamente** antes de
tocar em `~\.nightchat` — sua identidade Ed25519 privada não tem cópia
em nenhum outro lugar (nem o relay a tem) e uma exclusão acidental é
irreversível.

### Honestidade sobre o instalador (leia antes de confiar)

- **Não é um `.exe` único autocontido.** NightChat é Python puro; o
  instalador prepara um Python privado para ele (via `winget` se
  necessário) em vez de compilar um binário. Isso significa que a
  primeira instalação precisa de internet para baixar o Python (se você
  não tiver) e as dependências — depois disso, `nightchat` roda offline
  (só a conversa em si precisa da rede, para falar com o relay).
- **Verificação de integridade é parcial.** O instalador confere que o
  download veio de `github.com`/`raw.githubusercontent.com` via HTTPS e
  que o arquivo é um zip válido — mas **não há checksum/assinatura de
  release publicada para conferir ainda** (não existe um pipeline de
  release assinado). Isso é uma limitação real, documentada aqui, não
  escondida atrás de uma mensagem de "[+] Verified" que não significa
  nada.
- **Não existe relay público oficial do NightChat.** O instalador não
  aponta para nenhum servidor compartilhado por padrão — você (ou quem
  quer que rode o relay) precisa hospedar um em algum lugar alcançável
  pelas duas pontas e configurar `NIGHTCHAT_RELAY_URL`. Sem isso, dois
  computadores diferentes não conseguem se falar (só `localhost`
  funciona, e só se o relay também rodar na mesma máquina).
- **Testado nesta sessão de desenvolvimento em uma máquina Windows real**
  (baixando o zip publicado no GitHub, criando o venv, instalando
  dependências, criando o shim e rodando `nightchat` de um PowerShell
  novo) — não em uma variedade de configurações de "máquina limpa"
  (idioma do Windows, política de execução de scripts restritiva,
  antivírus corporativo etc.). Se `irm ... | iex` for bloqueado pela
  política de execução, rode
  `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` antes,
  só para a sessão atual do PowerShell.

## Segurança e endurecimento (pós-auditoria)

A Fase 2 passou por uma auditoria e uma rodada de correções antes de ser
congelada. Resumo do que mudou/existe hoje:

- **Race condition de presença corrigida**: reconectar não derruba mais a
  própria sessão nova por engano — `ConnectionManager.disconnect()` só
  remove uma entrada se o socket ainda for exatamente o mesmo objeto
  (`server/presence.py`).
- **WebSocket não prende conexão do banco**: o handshake abre uma sessão
  curta (`SessionLocal`), faz a checagem pontual do usuário e fecha antes
  de entrar no loop de mensagens — o socket pode ficar aberto por horas
  sem segurar uma conexão do pool (`server/relay.py`, `server/database.py`).
  Pool configurável via `DB_POOL_SIZE`/`DB_MAX_OVERFLOW` (só Postgres).
- **Sem canal lateral de tempo óbvio no login**: usuário inexistente
  também dispara uma verificação Argon2id de verdade (contra um hash
  dummy fixo), em vez de responder quase instantaneamente
  (`server/auth.py:verify_password_or_dummy`).
- **JWT não trafega mais na URL do WebSocket**: autenticação por primeira
  mensagem (`{"type":"auth","token":"..."}`), evitando que o token acabe
  em logs de acesso de proxies/uvicorn/load balancers.
- **Rate limiting básico** (em memória, janela fixa — `server/ratelimit.py`):

  | Operação | Limite padrão | Janela | Resposta ao exceder |
  |---|---|---|---|
  | `POST /auth/register` | 3 | 60s | HTTP 429 |
  | `POST /auth/login` | 5 | 60s | HTTP 429 |
  | `GET /auth/exists` | 20 | 60s | HTTP 429 |
  | `connect_request` (WS) | 10 | 60s | `{"type":"error","reason":"rate_limited"}` |
  | qualquer mensagem WS | 30 | 10s | `{"type":"error","reason":"rate_limited"}` |

  Todos configuráveis via `.env` (`RATE_LIMIT_*`, ver `.env.example`).
- **Cliente resiliente a queda do relay**: `RelayClient` nunca propaga
  exceção para o shell — `_send()` retorna `False` em vez de levantar, um
  callback `on_disconnected` avisa a UI, e uma rotina de reconexão com
  backoff exponencial tenta um número limitado de vezes (padrão 5) antes
  de desistir. O shell (`client/main.py`) também blinda `commands.dispatch`
  como defesa extra.
- **Múltiplos pedidos de conexão pendentes**: se A e B pedem conexão a C
  antes de C responder, os dois pedidos ficam visíveis — o segundo não
  sobrescreve o primeiro (`server/sessions.py`, fila FIFO no cliente em
  `client/connection_state.py`). Pedidos de quem desconecta (como
  requerente OU como alvo) são limpos automaticamente.
- **Mensagens WebSocket malformadas não derrubam a conexão**: JSON
  inválido, JSON que não é objeto, `type` ausente/desconhecido e campos
  obrigatórios ausentes/com tipo errado respondem com
  `{"type":"error","reason":...}` em vez de crashar o handler.
- **Logging operacional mínimo**: sucesso/falha de autenticação,
  conexão/desconexão, rate limit acionado, erro de protocolo — **nunca**
  senha, hash, JWT ou conteúdo de mensagem (ver `server/logging_conf.py`
  para a lista exata e a política de retenção).

### O que a Fase 2 entrega
- Servidor **FastAPI + WebSocket** (`server/`): autenticação, presença,
  descoberta de usuários e encaminhamento de pedidos de conexão.
- **PostgreSQL** (ou SQLite em dev/teste) com uma única tabela `users`
  (`username` PK, `password_hash`). **Nenhuma tabela de mensagens, nenhum
  dado pessoal.**
- Autenticação real: `POST /auth/register`, `POST /auth/login`,
  `GET /auth/exists`, com **Argon2id** e token JWT de sessão.
- Presença online/offline em tempo real via WebSocket, com broadcast de
  eventos para todos os clientes conectados.
- `connect to user "nome"` / `accept` / `deny` encaminhados de verdade
  pelo relay, com múltiplos pedidos pendentes suportados e limpeza
  automática de pedidos órfãos.
- **Ainda sem E2EE**: a conexão de transporte com o relay não é um canal
  criptografado ponta-a-ponta — isso é Fase 4/5. `TYPE_RELAY` e
  `TYPE_SESSION_END` estão **definidos no protocolo mas não implementados**
  no servidor (respondem `not_implemented_yet`) — ver
  `shared/protocol.py` e a seção "Preparação para o protocolo futuro" abaixo.

### O que a Fase 3 entrega
- Identidade criptográfica **Ed25519** local por usuário (PyNaCl),
  persistida entre execuções (`client/crypto.py`, `client/crypto_identity.py`).
- Armazenamento da chave privada protegido por **DPAPI** no Windows, com
  abstração `IdentityStore` para outras plataformas no futuro
  (`client/identity_store.py`).
- Fingerprint determinístico derivado só da chave pública (`identity`,
  `identity verify "nome"`).
- `users.public_key` (Text, nullable) — única coluna nova; segue
  `username` + `password_hash` como schema mínimo.
- `PUT /users/me/public-key` (autenticado, com prova de posse via
  assinatura Ed25519) e `GET /users/{username}/public-key` (público).
- Detecção (não resolução automática) de troca inesperada de chave pública.
- **Nenhum E2EE**: sem X25519, sem HKDF, sem AEAD, sem `TYPE_RELAY`
  funcional — só identidade.

### O que a Fase 4 entrega
- `TYPE_RELAY`/`TYPE_SESSION_END` passam de "não implementados" para
  roteamento real — mas só do handshake, gated por `session_id`
  autorizado pelo relay (`server/sessions.py`, `server/relay.py`).
- Handshake X25519 efêmero autenticado por Ed25519 (STS simplificado),
  3 mensagens, transcript canônico length-prefixed
  (`shared/handshake.py`, `client/handshake.py`).
- Derivação de chaves de sessão por direção via HKDF-SHA256
  (`cryptography` lib) — `client/session.py:SessionState`.
- Máquina de estados resistente a MITM, alteração de transcript, replay,
  mensagens fora de ordem e timeout — com testes automatizados para
  cada uma dessas categorias (`tests/test_phase4_handshake.py`).
- **Nenhum chat, nenhuma cifra de mensagem**: XChaCha20-Poly1305 e
  anti-replay por contador continuam sendo Fase 5.

## Limitações conhecidas (documentadas, não escondidas)

- **Single-process**: `server/presence.py` (quem está online) e
  `server/sessions.py` (pedidos pendentes) são dicionários em memória de
  UM processo. **`uvicorn --workers N>1` e múltiplas réplicas atrás de um
  load balancer NÃO são suportados** — cada processo veria só uma fatia
  dos usuários conectados, sem nenhuma sincronização (Redis pub/sub ou
  equivalente) entre eles. O mesmo vale para os contadores de rate
  limiting. Resolver isso é trabalho de uma fase futura, não desta.
- **JWT**: validado em todo novo handshake (REST e WebSocket) — um token
  expirado nunca autentica nada novo. Uma conexão WebSocket já aberta é
  encerrada automaticamente no instante exato em que seu token expira
  (ver `server/relay.py:_expire_at`), então não existe "conexão eterna"
  com token vencido. Não há revogação antecipada (logout forçado, troca
  de senha invalidando tokens antigos) nesta fase — aceitável dado o TTL
  curto (padrão 15 min), mas registrado como limitação conhecida.
- **Rate limiting é por processo**, não distribuído (mesma limitação de
  escalabilidade acima).
- **PostgreSQL real**: a suíte principal roda contra SQLite (rápida, sem
  infraestrutura externa — mesmo comportamento de aplicação via
  SQLAlchemy). Existe uma suíte dedicada para Postgres real,
  `tests/test_postgres_integration.py`, mas **ela não foi executada
  contra um Postgres de verdade nesta rodada** (sem credenciais
  disponíveis no ambiente onde a Fase 2 foi endurecida) — ver seção de
  testes abaixo para como rodá-la.
- **Backend de armazenamento de chave privada só para Windows**:
  `LinuxIdentityStore` (libsecret/keyring) e `MacIdentityStore` (Keychain)
  não existem ainda — em qualquer plataforma que não seja Windows, o
  cliente cai no fallback `PlaintextIdentityStore` (sem proteção do SO),
  o que é aceitável só porque o cliente inicial é Windows.
- **Troca de chave pública não tem resolução automática**: o cliente
  detecta e recusa continuar, mas não oferece um comando para o usuário
  decidir explicitamente "confio nesta chave nova" — fica para uma fase
  futura junto com um esquema de confiança mais completo (TOFU).
- **Sem prova de identidade entre pares ainda**: `identity verify` mostra
  o fingerprint de um usuário, mas a comparação em si é manual (fora de
  banda) — não há pinning persistente de chaves de outros usuários nesta
  fase.
- **Handshake não tem retry/renegociação**: se falhar (timeout,
  assinatura inválida, peer offline), o usuário precisa mandar
  `connect to user` de novo — não há uma segunda tentativa automática
  dentro da mesma sessão social já aceita.
- **`SessionState` não sobrevive a uma queda de conexão**: se o
  WebSocket cair depois de um handshake estabelecido, as chaves de
  sessão em memória são perdidas de propósito — um novo `connect`/`accept`
  (e um novo handshake) é necessário. Isso é o comportamento correto para
  chaves efêmeras, não um bug — mas significa que o chat é interrompido a
  cada queda de conexão, mesmo breve.
- **Sem histórico de mensagens.** De propósito (ver "Modelo de
  privacidade" acima) — fechar o chat ou o app perde a conversa. Isso é
  a filosofia do projeto, não uma limitação técnica a resolver.
- **Sem release assinado/checksum publicado** para o `install.ps1`
  verificar — ver seção "Instalação" acima.
- **Sem relay público oficial** — cada implantação precisa hospedar o
  seu próprio relay em algum lugar alcançável pelas duas pontas.

## O que ainda falta (próximos passos honestos)

O núcleo funcional (identidade, handshake, chat E2EE, instalador) está
pronto e testado. O que ficaria para uma iteração futura, se este projeto
continuar:

- pipeline de release assinado (checksum/assinatura publicados, para o
  instalador verificar de verdade em vez de só checar "é um zip válido");
- backends de identidade para Linux (`libsecret`/`keyring`) e macOS
  (Keychain) — hoje só Windows tem proteção de SO para a chave privada;
- persistência opcional de `SessionState` entre reconexões rápidas (hoje
  sempre exige handshake novo);
- escalabilidade horizontal do relay (hoje é single-process, ver acima);
- pinning de identidade de pares (TOFU completo) além da verificação
  manual via `identity verify`.

## Estrutura

```
NightChat/
├── client/          # cliente terminal — Fase 1 (UI) + Fase 2 (relay_client, presence, reconexão)
│                     #   + Fase 3 (crypto, crypto_identity, identity_store)
│                     #   + Fase 4 (x25519, handshake, session, active_sessions)
│                     #   + Fase 5 (aead, chat, chat_state) + uninstall.py
├── server/          # relay FastAPI (Fase 2): main, config, database, models, auth, presence,
│                     #   relay, sessions, ratelimit, validation, logging_conf, deps
│                     #   + Fase 3: crypto_utils
├── shared/          # contrato de protocolo cliente<->servidor (protocol.py), de
│                     #   identidade (identity.py, Fase 3), do handshake (handshake.py, Fase 4)
│                     #   e das mensagens cifradas (messaging.py, Fase 5) — wire.py é utilitário comum
├── tests/           # testes (rodam sem terminal interativo)
├── docs/            # ARCHITECTURE.md — arquitetura, threat model, protocolo
├── install.ps1      # instalador Windows (irm ... | iex) — Fase 5
├── requirements.txt # dependências comentadas por fase
├── .env.example     # configuração por ambiente (secrets fora do código)
└── build/           # reservado para empacotamento binário futuro (não usado — ver "Instalação")
```

## Testes

```bash
python tests/test_phase1.py      # runner embutido da Fase 1 (sem instalar nada)
python -m pytest tests/ -v       # suíte completa: Fases 1-5
```

Os testes do servidor usam SQLite isolado em diretório temporário (não
exigem um PostgreSQL rodando) e Argon2id com custo reduzido para serem
rápidos — os parâmetros de produção continuam configuráveis via `.env`.

Para rodar a suíte **contra um PostgreSQL real**:

```bash
export NIGHTCHAT_TEST_POSTGRES_URL=postgresql+psycopg://user:pass@localhost:5432/nightchat_test
python -m pytest tests/test_postgres_integration.py -v
```

Sem essa variável, esses testes aparecem como `SKIPPED` (não simulados) —
ver `tests/test_postgres_integration.py`.

## Roadmap

| Fase | Entrega |
|---|---|
| **1 ✅** | Cliente terminal: ASCII art, boot, login local, comandos |
| **2 ✅** | Servidor relay (FastAPI+WebSocket+PostgreSQL): auth, presença, `connect`/`accept`/`deny`, endurecido pós-auditoria |
| **3 ✅** | Identidade criptográfica Ed25519: geração/persistência local, fingerprint, publicação/consulta de chave pública, prova de posse |
| **4 ✅** | Handshake X25519 efêmero autenticado (STS) usando a identidade Ed25519 + HKDF; `session_id` mintado no accept |
| **5 ✅** | Chat E2EE (XChaCha20-Poly1305 + anti-replay por contador) + instalador Windows (`install.ps1`) — **release candidate** |

Não há mais fases numeradas planejadas além desta — o que resta é a
lista em "O que ainda falta" acima, caso o projeto continue.

## Aviso honesto de segurança

Este projeto protege o **conteúdo** das mensagens contra a rede e contra
o servidor: identidade Ed25519 (Fase 3) + handshake X25519/STS
autenticado (Fase 4) + cifra XChaCha20-Poly1305 por mensagem com
anti-replay (Fase 5) — de ponta a ponta de verdade, não só no papel.
Mesmo assim, ele **não** é uma ferramenta de anonimato: o relay vê
metadados (quem fala com quem, quando, endereço IP). Ele **não** promete
apagamento absoluto — o sistema operacional (RAM, swap, logs,
screenshots) impõe limites reais, descritos em `docs/ARCHITECTURE.md`,
seção 6. Ele **não** escala horizontalmente ainda, **não** tem um relay
público oficial, e o instalador **não** verifica assinatura/checksum de
release (ver "Limitações conhecidas" e "Instalação" acima). Onde uma
propriedade não pode ser garantida, isso está escrito, não escondido —
essa é a régua deste projeto desde a Fase 1.

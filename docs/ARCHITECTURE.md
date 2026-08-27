# NightChat — Arquitetura, Threat Model e Protocolo

> Documento de design. Escrito **antes** de implementar a criptografia, propositalmente.
> Objetivo do projeto: um messenger de terminal E2EE, **educacional e sério**.
> Não afirmamos ter criptografia auditada, "grau militar" ou apagamento absoluto.
> Onde uma propriedade **não** pode ser garantida, isso está escrito explicitamente.

---

## 0. Sumário executivo (o que decidimos e por quê)

| Decisão | Escolha | Motivo curto |
|---|---|---|
| Modelo de confiança | Servidor **não-confiável** (untrusted relay) | E2EE de verdade: comprometer o servidor não revela mensagens |
| Biblioteca cripto | **PyNaCl** (libsodium) como principal; `cryptography` (pyca) como alternativa | APIs difíceis de usar errado; primitivas modernas; nunca implementar algoritmo na mão |
| Identidade | Par **Ed25519** de longo prazo por usuário | Assinatura/autenticação; base do *fingerprint* (estilo Signal safety number) |
| Acordo de chaves | **X25519 ECDHE efêmero**, autenticado pelas identidades Ed25519 (estilo STS) | Forward secrecy + autenticação mútua |
| Cifra de mensagem | **XChaCha20-Poly1305** (AEAD) | Confidencialidade + integridade/autenticação numa primitiva |
| Derivação de chave | **HKDF-SHA256** a partir do segredo ECDH | Separação de chaves por direção/propósito |
| Senha (login) | **Argon2id** (produção) / `hashlib.scrypt` (Fase 1, zero-dependência) | KDF memory-hard; nunca guardar senha em texto puro |
| Transporte | **WebSocket sobre TLS (wss://)** | TLS protege metadados na rede; E2EE protege do próprio servidor |
| Persistência de mensagem | **Nenhuma no servidor** | "messages are ephemeral by default" |

O ponto central: existem **duas camadas de criptografia** e elas resolvem problemas diferentes.
TLS (`wss://`) protege o tráfego contra quem está **na rede**. O E2EE protege o conteúdo contra o **próprio servidor**. Uma não substitui a outra.

---

## 1. Análise do conceito

A ideia é sólida e o escopo por fases é realista. Três observações de arquiteto antes de começar:

**(a) O "relay" é a decisão estruturante.** Duas topologias possíveis:

- **P2P direto** (os dois clientes conectam um ao outro): melhor privacidade de metadados, mas quebra na prática por causa de NAT/firewall doméstico — exigiria STUN/TURN/hole-punching. Complexo para um projeto educacional.
- **Relay central** (o que você propôs): os dois clientes conectam a um servidor que encaminha pacotes cifrados. Funciona atrás de qualquer NAT, é simples e é exatamente o modelo do WhatsApp/Signal. **É a escolha certa.** O custo é que o servidor **vê metadados** (quem fala com quem, quando, tamanho). Isso é inevitável nesse modelo e está documentado como limitação.

**(b) Autenticação e E2EE são coisas separadas.** Autenticar no relay (provar "eu sou morningstar") é diferente de estabelecer um canal seguro com a Sofia. O relay pode saber que você é morningstar sem nunca ver o conteúdo do que você manda para a Sofia. Mantemos essas duas camadas explicitamente separadas.

**(c) A ameaça mais realista não é criptográfica, é operacional.** Contra um atacante que quebre X25519, não temos defesa (nem o Signal tem). Contra um servidor curioso, um sniffer de rede ou um cliente mal-empacotado, **temos** — e é aí que o projeto ganha ou perde credibilidade. Por isso o threat model vem antes do código.

---

## 2. Arquitetura geral

```
                        ┌───────────────────────────┐
                        │      NIGHTCHAT RELAY       │
                        │  (FastAPI + WebSocket)     │
                        │                            │
                        │  • auth (Argon2id + JWT)   │
                        │  • presença (online/offline)│
                        │  • descoberta de usuários  │
                        │  • roteamento de pacotes    │
                        │    OPACOS (ciphertext)     │
                        │  • pedidos de conexão       │
                        │                            │
                        │  NÃO vê: plaintext,        │
                        │  chaves privadas,           │
                        │  chaves de sessão           │
                        └───────────┬───────────────┘
                           wss:// (TLS)
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
        ┌───────────────────────┐       ┌───────────────────────┐
        │   NightChat Client    │       │   NightChat Client     │
        │      morningstar      │◀─────▶│         sofia          │
        │                       │ canal │                        │
        │ • identidade (Ed25519)│ E2EE  │ • identidade (Ed25519) │
        │ • chaves privadas     │(lógico)│ • chaves privadas     │
        │ • handshake X25519    │       │ • handshake X25519     │
        │ • cifra/decifra        │       │ • cifra/decifra        │
        │ • estado de sessão     │       │ • estado de sessão     │
        └───────────────────────┘       └───────────────────────┘
```

Separação de responsabilidades (contrato do projeto):

```
CLIENTE                          SERVIDOR (relay)
- identidade                     - autenticação
- chaves privadas                - presença
- criptografia                   - descoberta/roteamento
- descriptografia                - relay de ciphertext
- estado de sessão               - pedidos de conexão
                                 - (nunca): plaintext, chaves privadas, chaves de sessão
```

---

## 3. Threat Model

### 3.1 O que estamos protegendo (assets)
1. **Conteúdo das mensagens** (prioridade máxima).
2. **Chaves privadas de identidade** dos usuários.
3. **Chaves de sessão** efêmeras.
4. **Credenciais de login** (senha).
5. Em menor grau: metadados (quem-fala-com-quem). **Não conseguimos escondê-los do servidor** — ver 3.7.

### 3.2 Contra quem (adversários)
- **A1 — Sniffer passivo de rede** (Wi-Fi público, ISP): vê pacotes em trânsito.
- **A2 — Servidor curioso/honesto-mas-curioso**: opera o relay, lê tudo que passa por ele, mas segue o protocolo.
- **A3 — Servidor comprometido/malicioso**: atacante controla o relay (pode tentar *man-in-the-middle*).
- **A4 — Atacante ativo de rede** (MITM sem controlar o servidor): injeta/altera/reordena pacotes.
- **A5 — Comprometimento de máquina cliente**: malware/acesso físico na máquina de um usuário.

### 3.3 O que o **servidor** pode observar
- Que `morningstar` está online e a que horas.
- Que `morningstar` abriu sessão com `sofia` (grafo social + timing).
- Tamanho aproximado e frequência dos pacotes cifrados.
- Endereço IP de conexão de cada cliente.
- **Não** observa: texto das mensagens, chaves privadas, chaves de sessão.

### 3.4 O que um **atacante de rede** (A1/A4) pode observar
- Com `wss://` (TLS): apenas que há tráfego entre cliente e o servidor NightChat, volume e timing. O conteúdo (inclusive quem-fala-com-quem no nível de aplicação) está dentro do túnel TLS.
- Sem TLS (`ws://`, só dev): **tudo que o servidor veria** — por isso `ws://` é só para desenvolvimento local e está marcado assim no código.

### 3.5 Se o **servidor for comprometido** (A3)
- O atacante vê e controla **metadados e roteamento**.
- O atacante **não** decifra mensagens já trocadas, porque as chaves de sessão são efêmeras e nunca saíram dos clientes (**forward secrecy**).
- **Tentativa de MITM no handshake:** o atacante poderia tentar se passar por Sofia. Isso é **detectável** porque as chaves efêmeras são **assinadas pela identidade Ed25519 de longo prazo** de cada parte. A defesa final é a **verificação de fingerprint** fora de banda (os usuários comparam os *safety numbers* por um canal que o servidor não controla — voz, pessoalmente). **Se os usuários não verificarem o fingerprint, um servidor malicioso pode, na primeira conexão, fazer MITM.** Isso está documentado, não escondido. (Este é o mesmo TOFU — *trust on first use* — do Signal/WhatsApp.)

### 3.6 Se uma **máquina cliente for comprometida** (A5)
- **Perdemos.** Não há defesa criptográfica contra malware com privilégio na máquina que digita/lê a mensagem em claro. O atacante pode ler a tela, o teclado, a RAM e as chaves privadas em disco.
- Mitigações **parciais** (não garantias): cifrar a chave privada em disco com a senha do usuário; zerar buffers de sessão no `/exit`; sessões efêmeras limitam o histórico exposto. Ver seção 6 sobre os limites reais disso.

### 3.7 Metadados — o que **não conseguimos esconder**
Sejamos honestos, porque isto é o que separa segurança real de marketing:
- O servidor **sabe quem fala com quem e quando**. Esconder isso exigiria roteamento anônimo (estilo Tor/mixnets) — fora de escopo.
- Padrões de **timing e tamanho** vazam informação mesmo com conteúdo cifrado. Padding e mensagens-isca reduzem isso; não planejamos implementar na v1.
- **IP de cada cliente** é visível ao servidor.
- Nomes de usuário são identificadores públicos no relay.

**Resumo honesto:** o NightChat protege o **conteúdo** contra a rede e contra o servidor. Ele **não** é uma ferramenta de anonimato e **não** esconde o grafo social do operador do servidor.

---

## 4. Protocolo de comunicação

### 4.1 Camadas
```
┌──────────────────────────────────────────────┐
│  L3  Aplicação: comandos, chat, presença      │
├──────────────────────────────────────────────┤
│  L2  E2EE: handshake + AEAD por mensagem      │  ← invisível ao servidor
├──────────────────────────────────────────────┤
│  L1  Envelope de relay (JSON): tipo, from, to │  ← servidor roteia por isto
├──────────────────────────────────────────────┤
│  L0  Transporte: WebSocket sobre TLS (wss://) │
└──────────────────────────────────────────────┘
```

O servidor lê **apenas L1** (o envelope: para quem encaminhar). O campo de payload de L2 é uma *blob* opaca de bytes cifrados que o servidor copia sem entender.

### 4.2 Envelope de relay (L1) — o que o servidor vê
```json
{
  "type": "relay",
  "from": "morningstar",
  "to": "sofia",
  "session": "b7f3...",
  "payload": "<base64 de ciphertext opaco>"
}
```
Tipos de controle que o servidor entende: `auth`, `presence`, `user_list`, `connect_request`, `connect_response`, `relay`, `session_end`. Nenhum deles carrega texto de mensagem.

### 4.3 Autenticação no relay (L1)
1. Cliente conecta via `wss://`.
2. Servidor envia um *nonce* de desafio.
3. Cliente envia `username` + `Argon2id`-prova da senha **e** assina o desafio com sua chave privada Ed25519.
4. Servidor confere o hash Argon2id (registro) e a assinatura contra a chave pública Ed25519 registrada.
5. Em sucesso, emite um token de sessão (JWT curto) para o resto da conexão.

Isso liga a conta (senha) à identidade criptográfica (Ed25519). A senha nunca trafega em claro; o servidor guarda só `Argon2id(senha)` + a chave **pública** de identidade.

> **Nota de honestidade (Fase 3 implementada de forma mais simples que este desenho):** o que existe hoje NÃO é este desafio único combinando senha+assinatura no handshake de login. A Fase 2 já usa login por senha via REST (`POST /auth/login`) + autenticação do WebSocket por primeira mensagem (`{"type":"auth","token":"<jwt>"}`) — isso não mudou. A Fase 3 acrescenta, **separadamente**, `PUT /users/me/public-key` (autenticado pelo JWT já existente) com sua própria prova de posse via assinatura Ed25519 sobre uma mensagem de vínculo fixa (`shared/identity.py:key_binding_message`) — não um nonce de desafio do servidor. O efeito prático (conta ligada à identidade, senha nunca em claro, servidor só vê a chave pública) é o mesmo; o mecanismo é mais simples e foi escolhido de propósito para não misturar autenticação de sessão com prova de posse de chave. Fundir os dois num desafio único, se fizer sentido, fica para quando o handshake X25519 (Fase 4) precisar de algo mais forte.

### 4.4 Handshake E2EE (L2) — o coração do projeto
Estilo **Station-to-Station (STS)**: ECDHE autenticado. Quando `morningstar` conecta com `sofia` (após `accept`):

```
morningstar                                             sofia
  gera par efêmero X25519 (eph_m)
  ── connect_request ──────────────────────────────▶
                                          gera par efêmero X25519 (eph_s)
                        ◀──────── eph_s_pub + Sign_Ed25519_sofia(eph_s_pub, eph_m_pub)
  verifica assinatura de sofia (identidade)
  ── eph_m_pub + Sign_Ed25519_morningstar(eph_m_pub, eph_s_pub) ──▶
                                          verifica assinatura de morningstar

  ambos:  shared = X25519(eph_priv_local, eph_pub_remote)
          k_send, k_recv = HKDF-SHA256(shared, info="nightchat-v1|<A>|<B>")
          (direções separadas para não reusar chave)
```

Propriedades obtidas:
- **Confidencialidade** do canal (só os dois derivam `shared`).
- **Autenticação mútua** (assinaturas Ed25519 amarram as chaves efêmeras às identidades — impede MITM ativo desde que o fingerprint seja verificado).
- **Forward secrecy** (as chaves efêmeras são descartadas no fim; comprometer a identidade depois não decifra o passado).

### 4.5 Formato de mensagem (L2) e anti-replay
Cada mensagem cifrada:
```
nonce(24B XChaCha20) || AEAD_XChaCha20Poly1305(key=k_send, ad=header, plaintext)
header = { session_id, counter (uint64, monotônico), timestamp }
```
- **Nonce** de 24 bytes (XChaCha permite nonce aleatório com margem enorme; ainda assim derivamos do counter para garantir unicidade).
- **`counter` monotônico** vai no *associated data* autenticado. O receptor **rejeita counter ≤ último visto** → proteção contra **replay** e reordenação.
- **Poly1305 (tag AEAD)** garante que qualquer alteração de 1 bit é detectada → proteção contra **adulteração**.

> **Nota de implementação (Fase 5 — bate com este desenho, com uma pequena diferença de formato):** o `nonce` NUNCA trafega (nem em claro nem cifrado) — é recalculado dos dois lados a partir do `counter`, que por sua vez vai no dado associado autenticado junto com `session_id` e o remetente (`shared/messaging.py:message_aad`). O quadro que de fato trafega é `{"counter": int, "ciphertext": base64}` (ver `client/chat.py`), não um `timestamp` explícito — o anti-replay usa só o contador monotônico (`counter <= último aceito` é rejeitado), sem depender de relógio sincronizado entre as partes. `SessionState.recv_counter` só avança após autenticação bem-sucedida.

### 4.6 Encerramento (`/exit`)
`session_end` para o par e para o servidor; ambos os clientes **descartam** chaves efêmeras e buffers (ver limites na seção 6). O servidor apenas marca a sessão como encerrada — ele nunca teve o conteúdo para descartar.

---

## 5. Estratégia criptográfica (resumo das primitivas)

| Função | Primitiva | Biblioteca |
|---|---|---|
| Identidade / assinatura | Ed25519 | PyNaCl `SigningKey`/`VerifyKey` |
| Acordo de chave efêmero | X25519 (ECDHE) | PyNaCl `PrivateKey`/`Box` ou `crypto_scalarmult` |
| Cifra autenticada (AEAD) | XChaCha20-Poly1305 | PyNaCl `aead`/`SecretBox` |
| Derivação de chave | HKDF-SHA256 | `cryptography` HKDF (ou libsodium KDF) |
| Senha → hash | Argon2id | `argon2-cffi` (prod); `hashlib.scrypt` na Fase 1 |
| Fingerprint | SHA-256 da chave pública Ed25519, formatado em blocos | stdlib `hashlib` |

**Regra de ouro do projeto:** nunca implementar AES, RSA, ECC, DH, curvas ou modos "na mão". Só compomos primitivas prontas dessas bibliotecas.

### 5.1 O que este design **ainda não é** (honestidade técnica)
- **Não é o Double Ratchet.** Fazemos ECDHE por sessão (forward secrecy entre sessões), mas **não** re-derivamos chave a cada mensagem. Consequência: se a chave de uma sessão viva vazar, todas as mensagens **daquela** sessão vazam. O Signal resolve isso com ratchet por mensagem (*post-compromise security*). Fica como evolução (pós-v1).
- **TOFU no fingerprint.** Sem verificação fora de banda, a primeira conexão é vulnerável a MITM de um servidor malicioso. Igual ao padrão de mercado, mas precisa ser dito.
- **Sem deniability, sem padding de metadados, sem anonimato de rede.**
- **Argon2 na Fase 1 é adiado** — a Fase 1 usa `scrypt` da stdlib para rodar sem instalar nada. `scrypt` é um KDF memory-hard legítimo; a troca para Argon2id acontece na Fase 4.

---

## 6. Dados apagados vs. limitações reais (a promessa honesta do `/exit`)

**O que o app efetivamente apaga:**
- Chaves de sessão efêmeras (referências Python liberadas; onde possível, sobrescritas com `bytearray` zerado).
- Buffers de mensagens da sessão em memória do processo.
- Estado de sessão (nada é gravado em disco por padrão).

**O que o app NÃO consegue garantir apagar (limitações do SO/hardware — não minta sobre isso):**
- **Memória/RAM:** Python não garante zerar toda cópia de um `str` imutável; o coletor de lixo pode deixar cópias. Sobrescrevemos o que dá (`bytearray`), mas não há garantia total.
- **Swap/paging:** o SO pode ter paginado segredos para o disco (`pagefile.sys`). Não controlamos isso.
- **Logs do terminal / scrollback:** o histórico visível fica no buffer do terminal e pode ir para arquivos de log do próprio terminal.
- **Screenshots, gravação de tela, ombro do vizinho, teclado logger:** fora do alcance de qualquer app.
- **Hibernação (`hiberfil.sys`):** dump da RAM em disco.

Por isso a filosofia é *"messages are ephemeral **by default**"* — e **não** "apagamento absoluto". O servidor não guarda plaintext (não existe tabela de mensagens em claro); o cliente minimiza o que retém. Além disso, o SO manda.

---

## 7. Estrutura de pastas (proposta final)

Próxima da sua, com pequenos acréscimos justificados:

```
NightChat/
├── client/
│   ├── main.py            # entrypoint: boot → login → shell
│   ├── terminal.py        # UI: ASCII art, cores, boot sequence, input mascarado
│   ├── authentication.py  # fluxo de login + verificação de credencial
│   ├── identity.py        # identidade local, credential store, fingerprint
│   ├── presence.py        # (Fase 2+) online/offline; Fase 1 = mock
│   ├── crypto.py          # (Fase 4) wrappers PyNaCl — vazio/stub na Fase 1
│   ├── session.py         # (Fase 5) estado de sessão E2EE — stub na Fase 1
│   ├── protocol.py        # (Fase 3+) mensagens de protocolo cliente-side
│   └── commands.py        # (+) tabela de comandos do shell — coesão melhor
├── server/                # (Fase 2+)
│   ├── main.py  auth.py  relay.py  presence.py  sessions.py  database.py
├── shared/
│   └── protocol.py        # tipos/constantes do protocolo compartilhados
├── tests/
├── docs/
│   └── ARCHITECTURE.md    # este documento
├── .env.example           # (+) config por ambiente; secrets fora do código
├── requirements.txt
├── README.md
└── build/                 # (Fase 8) PyInstaller → NightChat.exe
```

Acréscimos em relação à sua proposta e por quê:
- **`client/commands.py`**: separa a tabela de comandos da renderização do terminal → mais fácil adicionar `/comando` sem tocar na UI.
- **`.env.example`**: contrato de configuração (URL do relay, custo do Argon2 etc.) sem vazar secrets.
- **`docs/`**: para este documento não ficar solto na raiz.

---

## 8. Decisões técnicas (justificativas)

1. **PyNaCl (libsodium) como principal.** Comparado ao `cryptography`/OpenSSL, o libsodium foi desenhado para ser **difícil de usar errado** (nonces, tags, escolhas de modo já resolvidas). Para um projeto que quer segurança *realista*, menos superfície de erro > mais flexibilidade. Mantemos `cryptography` como opção para HKDF e interoperabilidade.
2. **XChaCha20-Poly1305 em vez de AES-GCM.** Nonce de 24 bytes remove o medo de reuso de nonce (o calcanhar de Aquiles do GCM), e ChaCha é rápido em CPU sem AES-NI — bom para um `.exe` que roda em qualquer Windows.
3. **Ed25519 para identidade + X25519 para sessão.** Padrão moderno (mesma família de curvas), assinaturas determinísticas, sem escolher parâmetros de curva na mão.
4. **WebSocket sobre TLS.** WebSocket dá full-duplex (essencial para presença e push de mensagens) e casa direto com FastAPI. TLS é obrigatório em produção; `ws://` só em dev, marcado no `.env`.
5. **Argon2id para senha.** Memory-hard, resistente a GPU/ASIC. Custo configurável por `.env`.
6. **PostgreSQL guarda o mínimo (revisado nas auditorias/Fases 2 e 3):** `username` (chave primária, normalizado para minúsculo), `Argon2id(senha)` e, desde a Fase 3, `public_key` (Ed25519, base64) — informação pública por natureza. Nenhum UUID interno, nenhum dado pessoal, nenhum metadado de presença persistido (presença é só estado em memória, `server/presence.py`). **Nunca** mensagens em claro, **nunca** chave privada, **nunca** chave de sessão — a chave privada Ed25519 fica exclusivamente no dispositivo do usuário (`client/identity_store.py`).
7. **Fase 1 sem dependências externas.** Roda com Python puro (stdlib) para você testar a experiência no terminal do Windows imediatamente. Dependências entram por fase, quando são realmente necessárias.

---

## 9. Roadmap por fases (contrato)

| Fase | Entrega | Dependências novas |
|---|---|---|
| **1** | Cliente terminal: ASCII art, boot, login local (`morningstar`), comandos básicos | nenhuma (stdlib) |
| **2** | Servidor FastAPI: conexão, auth, presença online/offline, `connect to user`/`accept`/`deny` via relay | fastapi, uvicorn, websockets, sqlalchemy, argon2-cffi |
| **3** | Identidade criptográfica Ed25519: geração/persistência local, fingerprint, publicação/consulta de chave pública, prova de posse | pynacl |
| **4** | Handshake X25519 efêmero autenticado (STS), assinado com a identidade Ed25519 da Fase 3, + HKDF; `session_id` mintado no accept | cryptography |
| **5** | Chat E2EE: AEAD (XChaCha20-Poly1305) por mensagem, anti-replay por contador, usando as chaves da Fase 4; instalador Windows (`install.ps1`) | — |

**Estado atual: Fase 5 implementada — chat E2EE completo (identidade
Ed25519 + handshake X25519/STS + HKDF + AEAD XChaCha20-Poly1305 +
anti-replay) e instalador Windows via PowerShell. Release candidate.**
As fases originalmente previstas 6-8 (destruição explícita de buffers no
`/exit`, testes adicionais, empacotamento `.exe` via PyInstaller) não
foram abertas como fases numeradas separadas — o instalador da Fase 5
resolve a distribuição por outro caminho (bootstrap de Python + venv em
vez de binário compilado, ver README.md "Instalação"), e a destruição de
buffers seria trabalho incremental sobre o `SessionState` já existente,
não uma mudança estrutural. Ver [`README.md`](../README.md), seção
"O que ainda falta", para a lista honesta do que ficaria para uma
iteração futura, e "Limitações conhecidas" para o que já existe mas tem
limites reais documentados (single-process, sem backend de identidade
para Linux/macOS, sem release assinado, sem relay público oficial).

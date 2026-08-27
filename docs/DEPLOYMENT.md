# NightChat — Deployment do relay oficial

Este documento descreve como colocar um NightChat Relay real no ar, atrás
de HTTPS/WSS, com PostgreSQL — e é honesto sobre o que já está pronto no
repositório versus o que só existe fora dele (infraestrutura real).

## O que já está pronto neste repositório (implementado, versionado)

- [Dockerfile](../Dockerfile) — imagem do relay, `uvicorn` sem `--reload`,
  roda como usuário sem privilégios.
- [docker-compose.yml](../docker-compose.yml) — orquestra três serviços:
  `relay` (a imagem acima), `postgres` (PostgreSQL 16, volume persistente,
  sem porta exposta ao host), `caddy` (proxy reverso com TLS automático
  via Let's Encrypt, único serviço com portas 80/443 publicadas).
- [deploy/Caddyfile](../deploy/Caddyfile) — configuração do Caddy; só
  falta trocar o domínio pelo real quando ele existir.
- `server/config.py` já recusa subir (`RuntimeError`) com
  `NIGHTCHAT_ENV=production` se `JWT_SECRET` for fraco/padrão,
  `NIGHTCHAT_REQUIRE_TLS` não for `true`, ou `DATABASE_URL` for SQLite —
  isso já foi implementado e testado na Fase 2 e não muda aqui.
- `GET /health` já existe e responde só `{"status": "ok"}` (ver
  `server/main.py`), sem nenhum dado interno/de usuário.

Nenhum desses arquivos, sozinho, coloca um relay no ar publicamente — eles
preparam tudo para quando a infraestrutura abaixo existir.

## O que FALTA (infraestrutura real, fora deste repositório)

Nada disto foi feito neste ambiente de desenvolvimento — não há como
provisionar um VPS, registrar um domínio ou emitir certificados TLS a
partir daqui. Para o relay oficial (`relay.nightchat.dev`) ficar
realmente no ar, alguém com acesso a essa infraestrutura precisa:

1. **Um host** — qualquer VPS/cloud (ex.: um droplet, uma instância EC2,
   uma VM) com Docker e Docker Compose instalados, acessível pela
   Internet nas portas 80 e 443.
2. **Um domínio** — registrar (ou usar um já existente) e criar um
   registro DNS tipo A (ou AAAA, para IPv6) apontando para o IP público
   do host acima. Este documento usa `relay.nightchat.dev` como
   placeholder — troque pelo domínio real escolhido, tanto aqui quanto em
   `deploy/Caddyfile` e em `client/authentication.py`
   (`OFFICIAL_RELAY_HTTP`/`OFFICIAL_RELAY_WS`).
3. **Firewall** — liberar as portas 80/tcp e 443/tcp de entrada no host
   (Caddy precisa da 80 para o desafio HTTP-01 do Let's Encrypt, além da
   443 para o tráfego HTTPS/WSS normal). A porta 8000 (relay) e 5432
   (Postgres) NÃO precisam ficar abertas externamente — só conversam
   dentro da rede interna do `docker compose`.
4. **Segredos reais** — no host, criar um arquivo `.env` (nunca commitado
   — já coberto por `.gitignore`) a partir de `.env.example`, com:
   - `JWT_SECRET` — gerado aleatoriamente, com pelo menos 32 caracteres
     (ex.: `python -c "import secrets; print(secrets.token_urlsafe(48))"`).
   - `POSTGRES_PASSWORD` — gerado aleatoriamente, forte.
5. **Subir os serviços**, no host, dentro do diretório com este
   repositório clonado:
   ```
   git clone https://github.com/ItsMeTheReis/nightchat.git
   cd nightchat
   cp .env.example .env      # e editar JWT_SECRET / POSTGRES_PASSWORD
   docker compose up -d
   docker compose logs -f relay
   ```
6. **Confirmar** que `https://relay.nightchat.dev/health` responde
   `{"status":"ok"}` de fora da rede do host (ex.: de outra máquina, outra
   rede) — só depois disso o relay oficial está de fato utilizável por
   clientes reais.

## Depois que o relay estiver no ar

`client/authentication.py` já aponta, por padrão, para
`https://relay.nightchat.dev` / `wss://relay.nightchat.dev/ws` — nenhuma
mudança de código é necessária no cliente quando essa infraestrutura
existir. Se o domínio final escolhido for outro, atualize as constantes
`OFFICIAL_RELAY_HTTP`/`OFFICIAL_RELAY_WS` em `client/authentication.py` e
o domínio em `deploy/Caddyfile`, e publique uma nova versão do instalador.

## Desenvolvimento local (sem nenhuma infraestrutura acima)

Não é preciso nada disto para desenvolver ou testar localmente:

```
python -m server.main            # relay local, http://localhost:8000
NIGHTCHAT_RELAY_URL=http://localhost:8000 python -m client.main
```

ou, via `install.ps1`, passe `-RelayUrl http://localhost:8000` na
instalação para configurar o cliente instalado a apontar para um relay
local, sem depender do domínio oficial.

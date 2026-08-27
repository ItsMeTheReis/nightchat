# NightChat Relay — imagem de produção.
#
# Roda "server.main:app" via uvicorn SEM --reload (server/main.py já chama
# uvicorn.run(..., reload=False) — ver linha final desse arquivo). Este
# Dockerfile empacota só o que o RELAY precisa (server/ + shared/); o
# cliente (client/) e o instalador (install.ps1) não fazem parte da imagem.
#
# TLS não termina aqui dentro — este container escuta HTTP puro na porta
# 8000 e espera um reverse proxy na frente (ver deploy/Caddyfile e
# docker-compose.yml) fazendo TLS/HTTPS/WSS e repassando
# X-Forwarded-Proto, que server/relay.py e o middleware de
# NIGHTCHAT_REQUIRE_TLS usam para saber que a conexão original era segura.

FROM python:3.11-slim

WORKDIR /app

# Dependências do sistema exigidas pelo driver psycopg[binary] e por
# cryptography/pynacl (compilação de extensões nativas, se necessário).
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server/ ./server/
COPY shared/ ./shared/

# Usuário sem privilégios — o processo nunca precisa de root.
RUN useradd --create-home --shell /usr/sbin/nologin nightchat
USER nightchat

EXPOSE 8000

# server/config.py já valida a configuração de produção no startup
# (recusa subir com JWT_SECRET fraco, NIGHTCHAT_REQUIRE_TLS=false ou
# DATABASE_URL sqlite quando NIGHTCHAT_ENV=production) — ver
# validate_production_config().
CMD ["python", "-m", "server.main"]

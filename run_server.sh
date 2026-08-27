#!/usr/bin/env bash
# NightChat Relay — atalho de execução em Linux/macOS (Fase 2).
uvicorn server.main:app --host 0.0.0.0 --port 8000

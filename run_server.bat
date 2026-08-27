@echo off
REM NightChat Relay — atalho de execução no Windows (Fase 2).
uvicorn server.main:app --host 0.0.0.0 --port 8000

"""
uninstall.py — Remoção limpa do NightChat instalado via install.ps1
(Fase 5/instalador).

Duas coisas são MUITO diferentes e nunca são apagadas pelo mesmo botão:

1. A instalação do PROGRAMA (código + venv), em
   `%LOCALAPPDATA%\\NightChat` — pode ser apagada sem perguntar muito,
   é só código, reinstala em segundos.
2. Os DADOS LOCAIS do usuário (identidade Ed25519 privada, fingerprint),
   em `~/.nightchat` — isso é irrecuperável se apagado (a chave privada
   não existe em nenhum outro lugar, nem no relay). NUNCA apagado sem
   confirmação explícita e separada.

Chamado via `nightchat uninstall` (ver client/main.py).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def _program_dir() -> Path | None:
    local_appdata = os.environ.get("LOCALAPPDATA")
    if not local_appdata:
        return None
    return Path(local_appdata) / "NightChat"


def _identity_dir() -> Path:
    return Path.home() / ".nightchat"


def _remove_program_dir(path: Path) -> tuple[bool, str]:
    """
    No Windows, este processo Python está RODANDO a partir de dentro de
    `path` (o venv) — arquivos nativos como `_rust.pyd` ficam com lock
    enquanto o interpretador está de pé, então apagar `path`
    sincronamente sempre falha aqui (e uma remoção parcial confunde até
    o cmd.exe, que perde a própria noção de working directory). A saída
    padrão do Windows para "instalador se autodeleta" é: agendar a
    remoção num processo separado e destacado, que espera este processo
    terminar e só então apaga a pasta inteira.

    Escrevemos um .bat temporário em vez de tentar montar uma linha de
    comando composta (com `&`, redirecionamento e aspas aninhadas) — o
    quoting de argumentos do Windows para processos filhos não preserva
    isso de forma confiável, e um .bat evita o problema por completo.
    """
    if os.name != "nt":
        try:
            shutil.rmtree(path)
            return True, ""
        except OSError as e:
            return False, str(e)

    try:
        fd, bat_path = tempfile.mkstemp(suffix=".bat", prefix="nightchat_uninstall_")
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write("@echo off\r\n")
            f.write(":wait\r\n")
            f.write(f'rmdir /s /q "{path}" 2>nul\r\n')
            f.write(f'if exist "{path}" (\r\n')
            f.write("    timeout /t 1 /nobreak >nul\r\n")
            f.write("    goto wait\r\n")
            f.write(")\r\n")
            f.write(f'del /f /q "{bat_path}"\r\n')

        subprocess.Popen(
            ["cmd", "/c", bat_path],
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS,
            cwd=tempfile.gettempdir(),  # nunca dentro de `path` — evita o mesmo problema que estamos corrigindo
            close_fds=True,
        )
        return True, "deferred"
    except OSError as e:
        return False, str(e)


def run() -> int:
    print()
    print("NightChat — Uninstall")
    print()

    program_dir = _program_dir()
    identity_dir = _identity_dir()

    if program_dir is not None and program_dir.exists():
        print(f"  [*] Removing program files: {program_dir}")
        ok, detail = _remove_program_dir(program_dir)
        if ok and detail == "deferred":
            print("  [+] Program files will finish removing in a couple seconds")
            print("      (scheduled after this process exits — Windows won't let a")
            print("      running Python delete the very venv it's running from).")
        elif ok:
            print("  [+] Program files removed.")
        else:
            print(f"  [!] Failed to remove program files: {detail}")
    else:
        print("  [i] No installed program directory found (nothing to remove there).")

    print()
    if identity_dir.exists():
        print(f"  [!] Your cryptographic identity is stored at: {identity_dir}")
        print("      This includes your Ed25519 PRIVATE KEY — it cannot be recovered")
        print("      if deleted (it never leaves this machine, not even the relay has it).")
        print()
        try:
            answer = input("      Delete it too? Type 'yes' to confirm, anything else to keep it: ")
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer.strip().lower() == "yes":
            try:
                shutil.rmtree(identity_dir)
                print("  [+] Identity data removed.")
            except OSError as e:
                print(f"  [!] Failed to remove identity data: {e}")
        else:
            print("  [i] Identity data kept.")
    else:
        print("  [i] No local identity data found.")

    print()
    print("  [i] The 'nightchat' command and PATH entry are not removed automatically.")
    print("      Remove the User PATH entry pointing to NightChat\\bin manually if desired.")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(run())

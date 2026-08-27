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
import sys
from pathlib import Path


def _program_dir() -> Path | None:
    local_appdata = os.environ.get("LOCALAPPDATA")
    if not local_appdata:
        return None
    return Path(local_appdata) / "NightChat"


def _identity_dir() -> Path:
    return Path.home() / ".nightchat"


def run() -> int:
    print()
    print("NightChat — Uninstall")
    print()

    program_dir = _program_dir()
    identity_dir = _identity_dir()

    if program_dir is not None and program_dir.exists():
        print(f"  [*] Removing program files: {program_dir}")
        try:
            shutil.rmtree(program_dir)
            print("  [+] Program files removed.")
        except OSError as e:
            print(f"  [!] Failed to remove program files: {e}")
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

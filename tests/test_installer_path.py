"""
Guarda contra regressão do bug: 'nightchat' not recognized numa janela de
PowerShell nova, logo após `irm | iex`.

Causa raiz (ver install.ps1): [Environment]::SetEnvironmentVariable(...,
"User") grava o registro (HKCU\\Environment) corretamente, mas não avisa
processos já rodando -- em especial o Explorer.exe, que cacheia seu
próprio bloco de ambiente e só o atualiza ao receber um broadcast
WM_SETTINGCHANGE (ou no logoff/logon). Sem esse broadcast, uma janela de
PowerShell aberta pelo Menu Iniciar/barra de tarefas logo após a
instalação herda o ambiente NÃO atualizado do Explorer e não encontra o
comando `nightchat`, mesmo com o registro já correto.

Estes testes não podem executar o instalador de verdade (precisa de
Windows + rede) -- eles verificam estaticamente, no texto do script, que
os elementos que corrigem e previnem esse bug continuam presentes. Não
substituem o teste real de instalação limpa + nova janela de PowerShell,
só evitam que a correção seja removida silenciosamente numa edição futura.
"""

from __future__ import annotations

from pathlib import Path

import pytest

INSTALL_PS1 = Path(__file__).resolve().parent.parent / "install.ps1"


@pytest.fixture()
def script_text() -> str:
    return INSTALL_PS1.read_text(encoding="ascii")


def test_install_script_is_pure_ascii_no_bom():
    """Regressão separada (bug do irm | iex): um BOM UTF-8 sobrevive ao
    fetch como string (Invoke-RestMethod) mesmo sendo removido ao
    carregar como arquivo, quebrando `#Requires`/[CmdletBinding()]/param()
    quando parseado via `iex`. O arquivo tem que continuar ASCII puro."""
    raw = INSTALL_PS1.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf"), "install.ps1 nao pode ter BOM UTF-8"
    raw.decode("ascii")  # levanta UnicodeDecodeError se houver qualquer byte nao-ASCII


def test_nightchat_bin_dir_added_to_user_path(script_text):
    assert 'SetEnvironmentVariable("Path", $newPath, "User")' in script_text


def test_path_change_is_broadcast_to_running_processes(script_text):
    """O elemento que efetivamente corrige o bug: sem isto, o registro
    fica certo mas o Explorer.exe (e qualquer coisa que ele lança, tipo
    uma nova janela de PowerShell do Menu Iniciar) continua com o PATH
    antigo em cache até logoff/logon."""
    assert "WM_SETTINGCHANGE" in script_text
    assert "SendMessageTimeout" in script_text
    assert "HWND_BROADCAST" in script_text
    assert '"Environment"' in script_text


def test_broadcast_happens_after_path_registry_write(script_text):
    path_write_idx = script_text.index('SetEnvironmentVariable("Path", $newPath, "User")')
    broadcast_idx = script_text.index("WM_SETTINGCHANGE")
    assert path_write_idx < broadcast_idx, (
        "o broadcast WM_SETTINGCHANGE precisa vir DEPOIS de escrever o PATH no registro"
    )


def test_broadcast_failure_is_non_fatal(script_text):
    """Se o broadcast falhar por algum motivo (ambiente restrito, etc.),
    isso nao pode derrubar a instalacao inteira -- o registro ja foi
    escrito corretamente, so o refresh imediato que pode nao acontecer."""
    broadcast_idx = script_text.index("WM_SETTINGCHANGE")
    surrounding = script_text[max(0, broadcast_idx - 800) : broadcast_idx + 1500]
    assert "try {" in surrounding or "try{" in surrounding
    assert "catch" in surrounding


def test_shim_launcher_is_created_in_bin_dir(script_text):
    assert 'Join-Path $binDir "nightchat.cmd"' in script_text


def test_shim_points_at_the_installed_venv_python(script_text):
    assert "venv\\Scripts\\python.exe" in script_text
    assert "-m client.main" in script_text


def test_installer_does_not_hardcode_a_default_username(script_text):
    assert "morningstar" not in script_text.lower()

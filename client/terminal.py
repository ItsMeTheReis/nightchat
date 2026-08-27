"""
terminal.py — Camada de apresentação do NightChat.

Responsável por toda a experiência visual no terminal:
- habilitar cores ANSI (inclusive no Windows 10+)
- ASCII art e banners
- boot sequence progressivo com pausas
- efeito de digitação (typewriter)
- input de senha mascarado com '*' (cross-platform)

Sem dependências externas — apenas stdlib. Isso garante que a Fase 1 rode
em qualquer Windows com Python instalado, sem 'pip install'.
"""

from __future__ import annotations

import os
import sys
import time
import shutil

# ---------------------------------------------------------------------------
# Cores ANSI
# ---------------------------------------------------------------------------
# No Windows 10+, o console entende ANSI, mas o modo VT precisa ser habilitado.
# Fazemos isso via ctypes. Se falhar (terminal muito antigo), desligamos cores
# em vez de imprimir lixo tipo "[92m".


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREY = "\033[90m"
    WHITE = "\033[97m"


_COLOR_ENABLED = True


def _enable_windows_vt() -> bool:
    """Habilita processamento de sequências VT/ANSI no console do Windows."""
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        # -11 = STD_OUTPUT_HANDLE ; 0x0004 = ENABLE_VIRTUAL_TERMINAL_PROCESSING
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        return True
    except Exception:
        return False


def init_terminal() -> None:
    """Prepara o terminal: cores e título da janela."""
    global _COLOR_ENABLED
    if os.name == "nt":
        _COLOR_ENABLED = _enable_windows_vt()
        # Título da janela (ignorado silenciosamente onde não houver suporte).
        try:
            os.system("title NightChat")
        except Exception:
            pass
    # Se stdout não é um terminal (ex.: redirecionado para arquivo), sem cores.
    if not sys.stdout.isatty():
        _COLOR_ENABLED = False


def color(text: str, *codes: str) -> str:
    if not _COLOR_ENABLED or not codes:
        return text
    return "".join(codes) + text + C.RESET


def clear_screen() -> None:
    if _COLOR_ENABLED:
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()
    else:
        os.system("cls" if os.name == "nt" else "clear")


def term_width(default: int = 80) -> int:
    try:
        return shutil.get_terminal_size((default, 24)).columns
    except Exception:
        return default


# ---------------------------------------------------------------------------
# Efeitos de saída
# ---------------------------------------------------------------------------

def _emit(text: str) -> None:
    sys.stdout.write(text)
    sys.stdout.flush()


def type_out(text: str, delay: float = 0.012, newline: bool = True) -> None:
    """Imprime caractere a caractere (efeito 'digitando')."""
    for ch in text:
        _emit(ch)
        if delay:
            time.sleep(delay)
    if newline:
        _emit("\n")


def line(text: str = "", *codes: str) -> None:
    _emit(color(text, *codes) + "\n")


def pause(seconds: float) -> None:
    time.sleep(seconds)


# ---------------------------------------------------------------------------
# ASCII ART
# ---------------------------------------------------------------------------
# Caracteres de bloco '#' — compatíveis com o code page padrão do Windows.
# Evitamos glyphs Unicode exóticos no banner principal para máxima portabilidade.

_BANNER = r"""
 ███    ██ ██  ██████  ██   ██ ████████  ██████ ██   ██  █████  ████████
 ████   ██ ██ ██       ██   ██    ██    ██      ██   ██ ██   ██    ██
 ██ ██  ██ ██ ██   ███ ███████    ██    ██      ███████ ███████    ██
 ██  ██ ██ ██ ██    ██ ██   ██    ██    ██      ██   ██ ██   ██    ██
 ██   ████ ██  ██████  ██   ██    ██     ██████ ██   ██ ██   ██    ██
"""

_TAGLINE = "terminal-based encrypted messenger"


def show_banner() -> None:
    """Mostra a ASCII art principal centralizada, com fade-in linha a linha."""
    width = term_width()
    lines = [ln for ln in _BANNER.strip("\n").splitlines()]
    for ln in lines:
        pad = max(0, (width - len(ln)) // 2)
        _emit(color(" " * pad + ln, C.CYAN, C.BOLD) + "\n")
        time.sleep(0.06)
    tag_pad = max(0, (width - len(_TAGLINE)) // 2)
    _emit("\n" + color(" " * tag_pad + _TAGLINE, C.GREY, C.DIM) + "\n\n")
    time.sleep(0.2)


# ---------------------------------------------------------------------------
# BOOT SEQUENCE
# ---------------------------------------------------------------------------

def _boot_step(label: str, delay_after: float = 0.35, ok: bool = True) -> None:
    """Linha de boot no estilo '[*] ...' com marcação de sucesso."""
    marker = color("[*]", C.YELLOW)
    _emit(f"  {marker} {label}")
    sys.stdout.flush()
    # Pequena pausa "trabalhando" antes de confirmar.
    time.sleep(delay_after)
    if ok:
        _emit("  " + color("[ ok ]", C.GREEN, C.BOLD) + "\n")
    else:
        _emit("  " + color("[ .. ]", C.GREY) + "\n")


def _progress_bar(width_chars: int = 30, duration: float = 0.9) -> None:
    """Barra de progresso preenchendo até 100%."""
    steps = width_chars
    for i in range(steps + 1):
        filled = "#" * i
        empty = "-" * (steps - i)
        pct = int((i / steps) * 100)
        _emit("\r  " + color(f"[{filled}{empty}] {pct:3d}%", C.CYAN))
        sys.stdout.flush()
        time.sleep(duration / steps)
    _emit("\n")


def boot_sequence() -> None:
    """Sequência de inicialização progressiva — a assinatura do NightChat."""
    line()
    _boot_step("Initializing NightChat", 0.4)
    _boot_step("Loading core modules", 0.3)
    _boot_step("Loading local identity", 0.35)
    _boot_step("Initializing secure subsystem", 0.45)
    _boot_step("Preparing cryptographic providers", 0.4)
    _boot_step("Connecting to relay", 0.5, ok=False)
    line("      " + "(offline mode — Phase 1: local only)", C.GREY, C.DIM)
    _boot_step("Synchronizing presence", 0.3, ok=False)
    line()
    _progress_bar(30, 0.8)
    line()
    line("  [+] System ready.", C.GREEN, C.BOLD)
    line()
    time.sleep(0.3)


# ---------------------------------------------------------------------------
# Molduras / boxes
# ---------------------------------------------------------------------------
# Usamos caracteres de caixa unicode (═ ║ ╔ ...). Eles funcionam no Windows
# Terminal e em consoles modernos. Há um fallback ASCII para consoles legados.

_BOX = {
    "tl": "╔", "tr": "╗", "bl": "╚", "br": "╝", "h": "═", "v": "║",
}
_BOX_ASCII = {
    "tl": "+", "tr": "+", "bl": "+", "br": "+", "h": "=", "v": "|",
}


def _box_chars():
    # No Windows legado sem UTF-8, caracteres de caixa podem virar '?'.
    # Heurística simples: se a saída não for tty, usar ASCII.
    if os.name == "nt":
        enc = (sys.stdout.encoding or "").lower()
        if "utf" not in enc:
            return _BOX_ASCII
    return _BOX


def boxed_title(title: str, width: int = 46, *codes: str) -> None:
    """Imprime um título dentro de uma moldura centralizada."""
    b = _box_chars()
    inner = width - 2
    top = b["tl"] + b["h"] * inner + b["tr"]
    bottom = b["bl"] + b["h"] * inner + b["br"]
    centered = title.center(inner)
    mid = b["v"] + centered + b["v"]
    codes = codes or (C.CYAN, C.BOLD)
    line(top, *codes)
    line(mid, *codes)
    line(bottom, *codes)


def rule(char: str = "─", width: int | None = None, *codes: str) -> None:
    w = width or min(term_width(), 60)
    line(char * w, *(codes or (C.GREY,)))


# ---------------------------------------------------------------------------
# Input de senha mascarado (mostra '*' por caractere)
# ---------------------------------------------------------------------------
# getpass.getpass() esconde tudo (nada aparece). O NightChat quer mostrar '*'.
# Implementamos leitura char-a-char: msvcrt no Windows, termios no POSIX.

def masked_input(prompt: str = "Password: ", mask: str = "*") -> str:
    _emit(color(prompt, C.WHITE))
    sys.stdout.flush()

    if os.name == "nt":
        return _masked_input_windows(mask)
    return _masked_input_posix(mask)


def _masked_input_windows(mask: str) -> str:
    import msvcrt

    buf: list[str] = []
    while True:
        ch = msvcrt.getwch()
        if ch in ("\r", "\n"):
            _emit("\n")
            break
        elif ch == "\003":  # Ctrl-C
            _emit("\n")
            raise KeyboardInterrupt
        elif ch == "\b":  # backspace
            if buf:
                buf.pop()
                _emit("\b \b")
        elif ch == "\x00" or ch == "\xe0":  # teclas especiais → consome o próximo
            msvcrt.getwch()
        else:
            buf.append(ch)
            _emit(mask)
    return "".join(buf)


def _masked_input_posix(mask: str) -> str:
    import termios
    import tty

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    buf: list[str] = []
    try:
        tty.setraw(fd)
        while True:
            ch = sys.stdin.read(1)
            if ch in ("\r", "\n"):
                break
            elif ch == "\003":  # Ctrl-C
                raise KeyboardInterrupt
            elif ch in ("\x7f", "\b"):  # backspace/delete
                if buf:
                    buf.pop()
                    _emit("\b \b")
            else:
                buf.append(ch)
                _emit(mask)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
        _emit("\n")
    return "".join(buf)

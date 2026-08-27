"""
identity_store.py — Armazenamento local da CHAVE PRIVADA de identidade
(Fase 3).

A chave privada NUNCA sai da máquina do usuário: nunca vai para o relay,
nunca para o banco, nunca para logs, nunca para o protocolo de rede. Este
módulo só decide COMO ela fica em disco localmente.

Abstração `IdentityStore` para permitir backends por sistema operacional.
Hoje só `WindowsIdentityStore` (cliente inicial é Windows) e
`PlaintextIdentityStore` (fallback). `LinuxIdentityStore` (libsecret via
`keyring`) e `MacIdentityStore` (Keychain) ficam para quando o cliente
realmente rodar nessas plataformas — não implementados nesta fase.

No Windows: DPAPI (`CryptProtectData`/`CryptUnprotectData`), a API de
proteção de dados nativa do sistema operacional, acessada via `ctypes`
puro (SEM dependência nova como `pywin32`). A chave privada é cifrada
amarrada à conta de usuário do Windows na máquina local — só a mesma
conta, na mesma máquina, consegue decifrar de novo. Isto NÃO é
criptografia caseira: é delegar para a API do SO, exatamente a orientação
do enunciado.

Fallback `PlaintextIdentityStore`: grava os bytes crus em disco com
permissão 0600 (best-effort — o Windows não tem um equivalente real a
isso). Usado só quando o DPAPI genuinamente não está disponível
(plataforma não-Windows, ou a chamada nativa falhou) — marcado como mais
fraco de propósito, nunca escondido.
"""

from __future__ import annotations

import ctypes
import os
import sys
from abc import ABC, abstractmethod
from pathlib import Path


def _store_dir() -> Path:
    return Path.home() / ".nightchat"


def _key_file(username: str) -> Path:
    return _store_dir() / f"ed25519_{username}.key"


class IdentityStore(ABC):
    """Persiste os bytes da chave PRIVADA Ed25519, por username."""

    backend_name: str = "abstract"

    @abstractmethod
    def load(self, username: str) -> bytes | None: ...

    @abstractmethod
    def save(self, username: str, private_key: bytes) -> None: ...

    @abstractmethod
    def exists(self, username: str) -> bool: ...


# Layout binário compatível com CRYPTOAPI_BLOB / DATA_BLOB do Windows.
# Definido com tipos ctypes genéricos (não Windows-específicos), então é
# seguro declarar esta struct em qualquer plataforma — só o USO dela
# (dentro de WindowsIdentityStore, via ctypes.windll) é Windows-only.
class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


class WindowsIdentityStore(IdentityStore):
    backend_name = "windows-dpapi"

    def __init__(self) -> None:
        if not hasattr(ctypes, "windll"):
            raise RuntimeError("DPAPI só está disponível no Windows")
        self._crypt32 = ctypes.windll.crypt32
        self._kernel32 = ctypes.windll.kernel32

    def _protect(self, data: bytes) -> bytes:
        buf = ctypes.create_string_buffer(data, len(data))
        blob_in = _DataBlob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
        blob_out = _DataBlob()
        ok = self._crypt32.CryptProtectData(
            ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
        )
        if not ok:
            raise OSError("CryptProtectData falhou (DPAPI)")
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            self._kernel32.LocalFree(blob_out.pbData)

    def _unprotect(self, data: bytes) -> bytes:
        buf = ctypes.create_string_buffer(data, len(data))
        blob_in = _DataBlob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
        blob_out = _DataBlob()
        ok = self._crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
        )
        if not ok:
            raise OSError("CryptUnprotectData falhou (DPAPI)")
        try:
            return ctypes.string_at(blob_out.pbData, blob_out.cbData)
        finally:
            self._kernel32.LocalFree(blob_out.pbData)

    def load(self, username: str) -> bytes | None:
        path = _key_file(username)
        if not path.exists():
            return None
        try:
            return self._unprotect(path.read_bytes())
        except OSError:
            return None

    def save(self, username: str, private_key: bytes) -> None:
        _store_dir().mkdir(parents=True, exist_ok=True)
        protected = self._protect(private_key)
        path = _key_file(username)
        path.write_bytes(protected)
        try:
            os.chmod(path, 0o600)
        except (OSError, NotImplementedError):
            pass

    def exists(self, username: str) -> bool:
        return _key_file(username).exists()


class PlaintextIdentityStore(IdentityStore):
    backend_name = "plaintext-file"

    def load(self, username: str) -> bytes | None:
        path = _key_file(username)
        if not path.exists():
            return None
        try:
            return path.read_bytes()
        except OSError:
            return None

    def save(self, username: str, private_key: bytes) -> None:
        _store_dir().mkdir(parents=True, exist_ok=True)
        path = _key_file(username)
        path.write_bytes(private_key)
        try:
            os.chmod(path, 0o600)
        except (OSError, NotImplementedError):
            pass

    def exists(self, username: str) -> bool:
        return _key_file(username).exists()


def get_default_store() -> IdentityStore:
    """Escolhe o melhor backend disponível para a plataforma atual."""
    if sys.platform == "win32":
        try:
            return WindowsIdentityStore()
        except Exception:
            pass
    return PlaintextIdentityStore()

"""
Testes do handshake X25519/STS autenticado por Ed25519 (Fase 4) —
client/handshake.py, client/x25519.py, shared/handshake.py.

Usa uma "rede falsa" em memória (sem WebSocket real) para poder
interceptar/adulterar mensagens deliberadamente nos testes de MITM,
tampering de transcript, replay e mensagens fora de ordem. O roteamento
real via relay (autorização por session_id) é testado separadamente em
tests/test_phase4_relay.py.
"""

from __future__ import annotations

import time
import uuid

import pytest

from client import crypto, x25519
from client.crypto_identity import CryptographicIdentity, load_or_create
from client.handshake import HandshakeManager
from client.identity_store import PlaintextIdentityStore
from shared import handshake as hs


# ---------------------------------------------------------------------------
# Infraestrutura de teste: rede em memória entre dois HandshakeManagers
# ---------------------------------------------------------------------------

class FakeNetwork:
    """Entrega mensagens de handshake diretamente entre dois
    HandshakeManagers, com um ponto de interceptação opcional para
    simular um relay/atacante ativo adulterando payloads em trânsito."""

    def __init__(self):
        self._managers: dict[str, HandshakeManager] = {}
        self.intercept = None  # fn(sender, target, session_id, payload) -> payload | None (None = derruba)
        self.sent: list[tuple[str, str, str, dict]] = []  # (sender, target, session_id, payload original)

    def register(self, username: str, manager: HandshakeManager) -> None:
        self._managers[username] = manager

    def sender_for(self, username: str):
        def _send(target: str, session_id: str, payload: dict) -> bool:
            self.sent.append((username, target, session_id, dict(payload)))
            effective = payload
            if self.intercept is not None:
                effective = self.intercept(username, target, session_id, dict(payload))
                if effective is None:
                    return True  # atacante descartou a mensagem — do ponto de vista do remetente, "entregue"
            manager = self._managers.get(target)
            if manager is None:
                return False
            manager.handle_message(username, session_id, effective)
            return True

        return _send


@pytest.fixture()
def isolated_store(tmp_path, monkeypatch):
    import client.identity_store as store_module

    monkeypatch.setattr(store_module, "_store_dir", lambda: tmp_path)
    return PlaintextIdentityStore()


def _identity(username: str, store) -> CryptographicIdentity:
    identity, _ = load_or_create(username, store)
    return identity


def _new_session_id() -> str:
    return uuid.uuid4().hex


class Harness:
    """Junta duas identidades + dois HandshakeManagers + a rede falsa,
    com um "diretório" simples de chaves públicas (equivalente ao que o
    relay serviria via GET /users/{username}/public-key)."""

    def __init__(self, isolated_store, timeout_seconds: float = 15.0):
        self.morningstar = _identity("morningstar", isolated_store)
        self.sofia = _identity("sofia", isolated_store)
        self.network = FakeNetwork()

        self.directory = {
            "morningstar": self.morningstar.public_key_bytes(),
            "sofia": self.sofia.public_key_bytes(),
        }

        self.established: dict[str, object] = {}
        self.failed: dict[str, list[tuple[str, str, str]]] = {"morningstar": [], "sofia": []}

        self.hm_m = HandshakeManager(
            identity=self.morningstar,
            send_relay=self.network.sender_for("morningstar"),
            fetch_public_key=lambda u: self.directory.get(u),
            timeout_seconds=timeout_seconds,
        )
        self.hm_s = HandshakeManager(
            identity=self.sofia,
            send_relay=self.network.sender_for("sofia"),
            fetch_public_key=lambda u: self.directory.get(u),
            timeout_seconds=timeout_seconds,
        )
        self.network.register("morningstar", self.hm_m)
        self.network.register("sofia", self.hm_s)

        self.hm_m.on_established = lambda s: self.established.__setitem__("morningstar", s)
        self.hm_s.on_established = lambda s: self.established.__setitem__("sofia", s)
        self.hm_m.on_failed = lambda sid, peer, reason: self.failed["morningstar"].append((sid, peer, reason))
        self.hm_s.on_failed = lambda sid, peer, reason: self.failed["sofia"].append((sid, peer, reason))


@pytest.fixture()
def harness(isolated_store) -> Harness:
    return Harness(isolated_store)


# ---------------------------------------------------------------------------
# Caminho feliz
# ---------------------------------------------------------------------------

def test_happy_path_both_sides_establish_matching_keys(harness: Harness):
    session_id = _new_session_id()
    harness.hm_m.initiate("sofia", session_id)

    assert "morningstar" in harness.established
    assert "sofia" in harness.established
    session_m = harness.established["morningstar"]
    session_s = harness.established["sofia"]

    assert session_m.session_id == session_id == session_s.session_id
    assert session_m.peer_username == "sofia"
    assert session_s.peer_username == "morningstar"

    # chaves de direção cruzadas: o que M usa para ENVIAR é o que S usa para RECEBER
    assert session_m.k_send == session_s.k_recv
    assert session_m.k_recv == session_s.k_send
    assert session_m.k_send != session_m.k_recv  # direções nunca reusam a mesma chave

    assert harness.failed["morningstar"] == []
    assert harness.failed["sofia"] == []


def test_established_keys_differ_across_independent_sessions(harness: Harness):
    harness.hm_m.initiate("sofia", _new_session_id())
    first_key = harness.established["morningstar"].k_send

    harness2 = Harness.__new__(Harness)  # segunda rodada independente, mesmas identidades
    # (mais simples: gera uma nova sessão na MESMA harness — chaves efêmeras são novas a cada initiate)
    harness.established.clear()
    harness.hm_m.initiate("sofia", _new_session_id())
    second_key = harness.established["morningstar"].k_send

    assert first_key != second_key  # forward secrecy: cada sessão deriva chaves novas


# ---------------------------------------------------------------------------
# MITM / alteração de transcript
# ---------------------------------------------------------------------------

def test_mitm_tampering_ephemeral_key_in_init_is_detected(harness: Harness):
    """Um atacante on-path troca a eph_pub do msg1 (handshake_init) pela
    própria. O respondente assina o que recebeu (sem saber que foi
    adulterado); quando a resposta volta, o iniciador monta o transcript
    com a SUA chave efêmera real (nunca a que foi adulterada em trânsito)
    — a verificação da assinatura do respondente falha."""
    attacker_priv, attacker_pub = x25519.generate_ephemeral_keypair()

    def intercept(sender, target, session_id, payload):
        if sender == "morningstar" and payload.get("kind") == hs.KIND_INIT:
            payload = dict(payload)
            payload["eph_pub"] = crypto.encode_public_key(attacker_pub)
        return payload

    harness.network.intercept = intercept
    harness.hm_m.initiate("sofia", _new_session_id())

    assert "morningstar" not in harness.established
    assert "sofia" not in harness.established  # sofia nem chega a ESTABLISHED sem o confirm
    assert len(harness.failed["morningstar"]) == 1
    assert harness.failed["morningstar"][0][2] == "signature_verification_failed"


def test_mitm_tampering_ephemeral_key_in_response_is_detected(harness: Harness):
    attacker_priv, attacker_pub = x25519.generate_ephemeral_keypair()

    def intercept(sender, target, session_id, payload):
        if sender == "sofia" and payload.get("kind") == hs.KIND_RESPONSE:
            payload = dict(payload)
            payload["eph_pub"] = crypto.encode_public_key(attacker_pub)
        return payload

    harness.network.intercept = intercept
    harness.hm_m.initiate("sofia", _new_session_id())

    assert "morningstar" not in harness.established
    assert harness.failed["morningstar"][0][2] == "signature_verification_failed"


def test_mitm_tampering_signature_in_response_is_detected(harness: Harness):
    def intercept(sender, target, session_id, payload):
        if sender == "sofia" and payload.get("kind") == hs.KIND_RESPONSE:
            payload = dict(payload)
            sig = bytearray(__import__("base64").b64decode(payload["signature"]))
            sig[0] ^= 0xFF
            payload["signature"] = __import__("base64").b64encode(bytes(sig)).decode("ascii")
        return payload

    harness.network.intercept = intercept
    harness.hm_m.initiate("sofia", _new_session_id())

    assert harness.failed["morningstar"][0][2] == "signature_verification_failed"


def test_mitm_tampering_signature_in_confirm_is_detected(harness: Harness):
    def intercept(sender, target, session_id, payload):
        if sender == "morningstar" and payload.get("kind") == hs.KIND_CONFIRM:
            payload = dict(payload)
            sig = bytearray(__import__("base64").b64decode(payload["signature"]))
            sig[0] ^= 0xFF
            payload["signature"] = __import__("base64").b64encode(bytes(sig)).decode("ascii")
        return payload

    harness.network.intercept = intercept
    harness.hm_m.initiate("sofia", _new_session_id())

    # morningstar acha que terminou (ele só verifica a assinatura de sofia
    # no msg2, não a própria) — mas sofia detecta a adulteração do confirm.
    assert "morningstar" in harness.established
    assert "sofia" not in harness.established
    assert harness.failed["sofia"][0][2] == "signature_verification_failed"


def test_mitm_tampering_session_id_field_is_detected(harness: Harness):
    """Um atacante troca o "session" do envelope L1 no meio do caminho
    (não o session_id dentro do transcript assinado, que o payload nem
    carrega — ele vem do parâmetro separado de handle_message, refletindo
    o campo 'session' do envelope). Isso quebra a correlação com a sessão
    pendente correta: a mensagem cai numa sessão diferente (ou
    inexistente) e é descartada, sem nunca chegar a verificar assinatura
    contra o transcript errado."""
    real_session_id = _new_session_id()
    wrong_session_id = _new_session_id()

    def intercept(sender, target, session_id, payload):
        if sender == "sofia" and payload.get("kind") == hs.KIND_RESPONSE:
            # Simula o relay entregando a resposta sob um session_id ERRADO.
            harness.hm_m.handle_message(sender, wrong_session_id, payload)
            return None  # não entrega também pelo caminho normal
        return payload

    harness.network.intercept = intercept
    harness.hm_m.initiate("sofia", real_session_id)

    # a mensagem foi entregue sob o session_id errado -> não corresponde a
    # nenhuma sessão pendente do iniciador -> ignorada silenciosamente.
    assert "morningstar" not in harness.established
    assert harness.failed["morningstar"] == []  # nem chegou a tentar verificar/falhar — foi descartada antes disso
    assert real_session_id in harness.hm_m.pending_session_ids()  # a sessão real continua esperando (nunca recebeu a resposta de verdade)


def test_tampered_transcript_fails_signature_verification():
    priv, pub = None, None
    from client.crypto import generate_keypair, sign, verify

    priv, pub = generate_keypair()
    eph1 = b"\x01" * 32
    eph2 = b"\x02" * 32
    good = hs.transcript("session-a", "morningstar", "sofia", eph1, eph2)
    signature = sign(priv, good)
    assert verify(pub, good, signature) is True

    tampered_session = hs.transcript("session-b", "morningstar", "sofia", eph1, eph2)
    assert verify(pub, tampered_session, signature) is False

    tampered_key = hs.transcript("session-a", "morningstar", "sofia", eph1, b"\x03" * 32)
    assert verify(pub, tampered_key, signature) is False


def test_transcript_length_prefixing_prevents_concatenation_ambiguity():
    """Sem length-prefix, session_id='ab'+initiator='cd' colidiria (nos
    bytes concatenados) com session_id='a'+initiator='bcd'. Com
    length-prefix, os transcripts são diferentes."""
    eph1, eph2 = b"\x11" * 32, b"\x22" * 32
    t1 = hs.transcript("ab", "cd", "e", eph1, eph2)
    t2 = hs.transcript("a", "bcd", "e", eph1, eph2)
    assert t1 != t2


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------

def test_replaying_response_into_a_new_session_fails(harness: Harness):
    """Um handshake completo é feito; a mensagem de resposta (msg2)
    capturada é reinjetada numa sessão NOVA e diferente — o session_id
    novo não bate com o que foi assinado, então falha."""
    captured = {}

    def capture(sender, target, session_id, payload):
        if sender == "sofia" and payload.get("kind") == hs.KIND_RESPONSE:
            captured["payload"] = dict(payload)
        return payload

    harness.network.intercept = capture
    harness.hm_m.initiate("sofia", _new_session_id())
    assert "morningstar" in harness.established  # sessão original completou normalmente

    # nova tentativa: outra sessão, morningstar gera uma NOVA eph_pub própria
    harness.established.clear()
    harness.failed["morningstar"].clear()
    new_session_id = _new_session_id()

    def drop_real_response_and_replay_old(sender, target, session_id, payload):
        if sender == "sofia" and payload.get("kind") == hs.KIND_RESPONSE:
            return captured["payload"]  # substitui pela resposta CAPTURADA da sessão antiga
        return payload

    harness.network.intercept = drop_real_response_and_replay_old
    harness.hm_m.initiate("sofia", new_session_id)

    assert "morningstar" not in harness.established
    assert harness.failed["morningstar"][-1][2] == "signature_verification_failed"


def test_duplicate_message_within_same_session_is_ignored(harness: Harness):
    """Depois que a sessão já estabeleceu (e saiu do dicionário de
    pendentes), reentregar a mesma mensagem de novo não deve fazer nada —
    nem crash, nem re-disparar callbacks."""
    established_count = {"morningstar": 0}
    harness.hm_m.on_established = lambda s: established_count.__setitem__(
        "morningstar", established_count["morningstar"] + 1
    )

    captured = {}

    def capture(sender, target, session_id, payload):
        if sender == "sofia" and payload.get("kind") == hs.KIND_RESPONSE:
            captured["args"] = (sender, session_id, dict(payload))
        return payload

    harness.network.intercept = capture
    session_id = _new_session_id()
    harness.hm_m.initiate("sofia", session_id)
    assert established_count["morningstar"] == 1

    # reentrega a MESMA mensagem de resposta de novo, na sessão já concluída
    sender, sid, payload = captured["args"]
    harness.hm_m.handle_message(sender, sid, payload)

    assert established_count["morningstar"] == 1  # não disparou de novo


# ---------------------------------------------------------------------------
# Mensagens fora de ordem
# ---------------------------------------------------------------------------

def test_response_for_unknown_session_is_ignored(harness: Harness):
    harness.hm_m.handle_message("sofia", _new_session_id(), {"kind": hs.KIND_RESPONSE, "eph_pub": "x", "signature": "y"})
    assert harness.failed["morningstar"] == []
    assert "morningstar" not in harness.established


def test_confirm_before_response_is_ignored(harness: Harness):
    """O iniciador nunca deveria receber um 'confirm' antes de mandar um
    'init' — mensagem fora de ordem, ignorada sem crash."""
    harness.hm_m.handle_message("sofia", _new_session_id(), {"kind": hs.KIND_CONFIRM, "signature": "y"})
    assert harness.failed["morningstar"] == []


def test_second_init_for_same_session_is_ignored(harness: Harness):
    session_id = _new_session_id()
    harness.hm_s.handle_message(
        "morningstar", session_id, {"kind": hs.KIND_INIT, "eph_pub": crypto.encode_public_key(x25519.generate_ephemeral_keypair()[1])}
    )
    assert len(harness.network.sent) == 1  # só a resposta ao primeiro init

    harness.hm_s.handle_message(
        "morningstar", session_id, {"kind": hs.KIND_INIT, "eph_pub": crypto.encode_public_key(x25519.generate_ephemeral_keypair()[1])}
    )
    assert len(harness.network.sent) == 1  # segundo init ignorado — nenhuma resposta nova


def test_wrong_role_message_is_ignored(harness: Harness):
    """Um 'confirm' chegando para uma sessão onde EU sou o iniciador (não
    o respondente) é papel errado — ignorado."""
    session_id = _new_session_id()
    harness.hm_m.initiate("sofia", session_id)  # completa a sessão inteira
    # agora tenta mandar um "confirm" pra ela mesma como se sofia fosse iniciadora
    harness.hm_m.handle_message("sofia", _new_session_id(), {"kind": hs.KIND_CONFIRM, "signature": "y"})
    assert len(harness.failed["morningstar"]) == 0


# ---------------------------------------------------------------------------
# Timeout
# ---------------------------------------------------------------------------

def test_handshake_times_out_when_peer_never_responds(isolated_store):
    harness = Harness(isolated_store, timeout_seconds=0.2)
    harness.network.intercept = lambda sender, target, session_id, payload: None  # descarta tudo

    session_id = _new_session_id()
    harness.hm_m.initiate("sofia", session_id)

    deadline = time.monotonic() + 3
    while not harness.failed["morningstar"] and time.monotonic() < deadline:
        time.sleep(0.05)

    assert harness.failed["morningstar"], "esperava on_failed por timeout"
    assert harness.failed["morningstar"][0][2] == "timeout"
    assert session_id not in harness.hm_m.pending_session_ids()


def test_established_session_is_not_affected_by_timeout(harness: Harness):
    """Prazo curto, mas a resposta chega a tempo — não deve falhar."""
    harness.hm_m._timeout_seconds = 5.0
    session_id = _new_session_id()
    harness.hm_m.initiate("sofia", session_id)
    time.sleep(0.3)
    assert "morningstar" in harness.established
    assert harness.failed["morningstar"] == []


# ---------------------------------------------------------------------------
# Rejeição de chave X25519 degenerada (ordem baixa)
# ---------------------------------------------------------------------------

def test_all_zero_ephemeral_key_is_rejected_as_invalid():
    assert x25519.is_valid_public_point(b"\x00" * 32) is False


def test_compute_shared_secret_raises_on_degenerate_point():
    priv, _ = x25519.generate_ephemeral_keypair()
    with pytest.raises(ValueError):
        x25519.compute_shared_secret(priv, b"\x00" * 32)


def test_handshake_init_with_all_zero_key_is_ignored_not_crashed(harness: Harness):
    session_id = _new_session_id()
    harness.hm_s.handle_message("morningstar", session_id, {"kind": hs.KIND_INIT, "eph_pub": crypto.encode_public_key(b"\x00" * 32)})
    assert harness.failed["sofia"] == []
    assert session_id not in harness.hm_s.pending_session_ids()

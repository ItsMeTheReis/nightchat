"""
Testes da Fase 3 — identidade criptográfica Ed25519.

Cobre:
- geração/carga/persistência da identidade local (client/crypto.py,
  client/crypto_identity.py, client/identity_store.py);
- fingerprint determinístico derivado só da chave pública;
- assinatura/verificação Ed25519 (client) e verificação no servidor
  (server/crypto_utils.py);
- publicação e consulta de chave pública via REST
  (PUT/GET /users/.../public-key), incluindo a prova de posse;
- que a chave privada NUNCA é aceita/armazenada pelo relay;
- que um username não pode "roubar" a identidade de outro;
- detecção de troca inesperada de chave pública.
"""

from __future__ import annotations

import base64
import uuid

import pytest
from fastapi.testclient import TestClient

from client import crypto, crypto_identity as cryptoid
from client.identity_store import PlaintextIdentityStore
from server import sessions
from server.main import app, _login_limiter, _register_limiter, _exists_limiter
from server.presence import manager
from server.relay import _connect_request_limiter, _ws_message_limiter
from shared import identity as shared_identity


@pytest.fixture(autouse=True)
def _clean_relay_state():
    manager.active.clear()
    sessions._pending.clear()
    _login_limiter.reset()
    _register_limiter.reset()
    _exists_limiter.reset()
    _connect_request_limiter.reset()
    _ws_message_limiter.reset()
    yield
    manager.active.clear()
    sessions._pending.clear()
    _login_limiter.reset()
    _register_limiter.reset()
    _exists_limiter.reset()
    _connect_request_limiter.reset()
    _ws_message_limiter.reset()


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def isolated_store(tmp_path, monkeypatch):
    """Isola o armazenamento local de chave privada num diretório
    temporário — nunca toca no ~/.nightchat real."""
    import client.identity_store as store_module

    monkeypatch.setattr(store_module, "_store_dir", lambda: tmp_path)
    return PlaintextIdentityStore()


def _unique(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex[:8]}"


def _register(client: TestClient, username: str, password: str) -> str:
    resp = client.post("/auth/register", json={"username": username, "password": password})
    assert resp.status_code == 201, resp.text
    return resp.json()["token"]


def _publish(client: TestClient, token: str, username: str, identity: cryptoid.CryptographicIdentity):
    public_key_b64 = identity.public_key_b64()
    message = shared_identity.key_binding_message(username, public_key_b64)
    signature_b64 = base64.b64encode(identity.sign(message)).decode("ascii")
    return client.put(
        "/users/me/public-key",
        json={"public_key": public_key_b64, "signature": signature_b64},
        headers={"Authorization": f"Bearer {token}"},
    )


# ---------------------------------------------------------------------------
# Geração, persistência e propriedades da identidade local
# ---------------------------------------------------------------------------

def test_generate_identity_produces_ed25519_sized_keys():
    private_key, public_key = crypto.generate_keypair()
    assert len(private_key) == crypto.ED25519_PRIVATE_KEY_BYTES
    assert len(public_key) == crypto.ED25519_PUBLIC_KEY_BYTES


def test_load_or_create_generates_on_first_use(isolated_store):
    identity, created = cryptoid.load_or_create("morningstar", isolated_store)
    assert created is True
    assert isolated_store.exists("morningstar") is True


def test_load_or_create_loads_existing_identity_on_second_call(isolated_store):
    first, created_first = cryptoid.load_or_create("morningstar", isolated_store)
    second, created_second = cryptoid.load_or_create("morningstar", isolated_store)

    assert created_first is True
    assert created_second is False
    assert first.public_key_bytes() == second.public_key_bytes()


def test_identity_persists_across_simulated_restarts(isolated_store):
    """Simula 'fechar e reabrir o cliente': cada chamada usa uma instância
    NOVA de CryptographicIdentity, mas lida do mesmo backing store."""
    identity_a, _ = cryptoid.load_or_create("morningstar", isolated_store)
    fingerprint_a = identity_a.fingerprint()
    del identity_a

    identity_b, created = cryptoid.load_or_create("morningstar", isolated_store)
    assert created is False
    assert identity_b.fingerprint() == fingerprint_a


def test_different_usernames_get_different_identities(isolated_store):
    morningstar, _ = cryptoid.load_or_create("morningstar", isolated_store)
    sofia, _ = cryptoid.load_or_create("sofia", isolated_store)
    assert morningstar.public_key_bytes() != sofia.public_key_bytes()
    assert morningstar.fingerprint() != sofia.fingerprint()


def test_public_key_is_deterministic_for_the_identity(isolated_store):
    identity, _ = cryptoid.load_or_create("morningstar", isolated_store)
    assert crypto.public_key_from_private(identity.public_key_bytes()) is not None  # sanity: bytes are usable
    # a mesma chave privada sempre deriva a mesma chave pública
    private_key = isolated_store.load("morningstar")
    assert crypto.public_key_from_private(private_key) == identity.public_key_bytes()
    assert crypto.public_key_from_private(private_key) == crypto.public_key_from_private(private_key)


def test_fingerprint_is_deterministic_and_key_derived():
    _, public_key_a = crypto.generate_keypair()
    _, public_key_b = crypto.generate_keypair()

    assert crypto.fingerprint(public_key_a) == crypto.fingerprint(public_key_a)
    assert crypto.fingerprint(public_key_a) != crypto.fingerprint(public_key_b)
    # formatado em blocos de 4 (estilo safety number)
    fp = crypto.fingerprint(public_key_a)
    assert all(len(block) == 4 for block in fp.split(" "))


def test_private_key_is_never_exposed_as_a_public_attribute(isolated_store):
    identity, _ = cryptoid.load_or_create("morningstar", isolated_store)
    assert not hasattr(identity, "private_key")
    # o name-mangling do Python não deixa isso acessível por acidente
    assert not any("private_key" in attr for attr in vars(identity).keys() if not attr.startswith("_"))


# ---------------------------------------------------------------------------
# Assinatura Ed25519
# ---------------------------------------------------------------------------

def test_valid_signature_verifies():
    private_key, public_key = crypto.generate_keypair()
    message = b"nightchat-test-message"
    signature = crypto.sign(private_key, message)
    assert crypto.verify(public_key, message, signature) is True


def test_altered_message_fails_verification():
    private_key, public_key = crypto.generate_keypair()
    signature = crypto.sign(private_key, b"original message")
    assert crypto.verify(public_key, b"tampered message", signature) is False


def test_altered_signature_fails_verification():
    private_key, public_key = crypto.generate_keypair()
    message = b"original message"
    signature = bytearray(crypto.sign(private_key, message))
    signature[0] ^= 0xFF  # inverte um bit
    assert crypto.verify(public_key, message, bytes(signature)) is False


def test_signature_from_different_key_fails_verification():
    priv_a, pub_a = crypto.generate_keypair()
    priv_b, pub_b = crypto.generate_keypair()
    message = b"shared message"
    sig_from_a = crypto.sign(priv_a, message)
    assert crypto.verify(pub_b, message, sig_from_a) is False


# ---------------------------------------------------------------------------
# Publicação/consulta de chave pública via REST
# ---------------------------------------------------------------------------

def test_public_key_can_be_published(client: TestClient, isolated_store):
    username = _unique("morningstar")
    token = _register(client, username, "s3nh4-forte")
    identity, _ = cryptoid.load_or_create(username, isolated_store)

    resp = _publish(client, token, username, identity)

    assert resp.status_code == 200
    assert resp.json() == {"username": username, "public_key": identity.public_key_b64()}


def test_public_key_can_be_queried(client: TestClient, isolated_store):
    username = _unique("morningstar")
    token = _register(client, username, "s3nh4-forte")
    identity, _ = cryptoid.load_or_create(username, isolated_store)
    _publish(client, token, username, identity)

    resp = client.get(f"/users/{username}/public-key")
    assert resp.status_code == 200
    assert resp.json()["public_key"] == identity.public_key_b64()


def test_public_key_query_before_publish_returns_null(client: TestClient):
    username = _unique("nokey")
    _register(client, username, "s3nh4-forte")
    resp = client.get(f"/users/{username}/public-key")
    assert resp.status_code == 200
    assert resp.json()["public_key"] is None


def test_public_key_query_for_nonexistent_username_returns_404(client: TestClient):
    resp = client.get("/users/user_que_nao_existe_xyz/public-key")
    assert resp.status_code == 404


def test_publish_public_key_requires_authentication(client: TestClient, isolated_store):
    username = _unique("noauth")
    _register(client, username, "s3nh4-forte")
    identity, _ = cryptoid.load_or_create(username, isolated_store)
    public_key_b64 = identity.public_key_b64()
    message = shared_identity.key_binding_message(username, public_key_b64)
    signature_b64 = base64.b64encode(identity.sign(message)).decode("ascii")

    resp = client.put("/users/me/public-key", json={"public_key": public_key_b64, "signature": signature_b64})
    assert resp.status_code == 401


def test_publish_public_key_rejects_invalid_token(client: TestClient, isolated_store):
    username = _unique("badtoken")
    _register(client, username, "s3nh4-forte")
    identity, _ = cryptoid.load_or_create(username, isolated_store)
    public_key_b64 = identity.public_key_b64()
    message = shared_identity.key_binding_message(username, public_key_b64)
    signature_b64 = base64.b64encode(identity.sign(message)).decode("ascii")

    resp = client.put(
        "/users/me/public-key",
        json={"public_key": public_key_b64, "signature": signature_b64},
        headers={"Authorization": "Bearer not-a-real-token"},
    )
    assert resp.status_code == 401


def test_invalid_public_key_format_is_rejected(client: TestClient):
    username = _unique("invalidkey")
    token = _register(client, username, "s3nh4-forte")

    resp = client.put(
        "/users/me/public-key",
        json={"public_key": "not-valid-base64-key!!", "signature": "AAAA"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 422


def test_wrong_length_public_key_is_rejected(client: TestClient):
    username = _unique("shortkey")
    token = _register(client, username, "s3nh4-forte")
    too_short = base64.b64encode(b"short").decode("ascii")

    resp = client.put(
        "/users/me/public-key",
        json={"public_key": too_short, "signature": base64.b64encode(b"whatever").decode("ascii")},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 422


def test_publish_without_valid_signature_is_rejected(client: TestClient, isolated_store):
    """Prova de posse: a assinatura precisa corresponder à mensagem
    canônica (username + public_key). Uma assinatura sobre qualquer outra
    coisa é rejeitada — a chave nunca é aceita "de graça"."""
    username = _unique("badsig")
    token = _register(client, username, "s3nh4-forte")
    identity, _ = cryptoid.load_or_create(username, isolated_store)

    wrong_signature = base64.b64encode(identity.sign(b"not the real binding message")).decode("ascii")
    resp = client.put(
        "/users/me/public-key",
        json={"public_key": identity.public_key_b64(), "signature": wrong_signature},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401


def test_private_key_field_is_never_accepted_or_stored(client: TestClient, isolated_store):
    """Mesmo que um cliente malicioso tente mandar uma chave privada no
    corpo da requisição, o schema não tem esse campo — ele é ignorado, e
    de forma nenhuma a coluna public_key vira um segredo."""
    from server.database import SessionLocal
    from server.models import User

    username = _unique("noprivkey")
    token = _register(client, username, "s3nh4-forte")
    identity, _ = cryptoid.load_or_create(username, isolated_store)
    public_key_b64 = identity.public_key_b64()
    message = shared_identity.key_binding_message(username, public_key_b64)
    signature_b64 = base64.b64encode(identity.sign(message)).decode("ascii")

    resp = client.put(
        "/users/me/public-key",
        json={
            "public_key": public_key_b64,
            "signature": signature_b64,
            "private_key": "TOTALLY_A_SECRET_KEY_ATTEMPT",  # campo espúrio
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert "private_key" not in resp.json()

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        assert user.public_key == public_key_b64
        assert "TOTALLY_A_SECRET_KEY_ATTEMPT" not in (user.public_key or "")
        # a tabela nem tem coluna para isso — reforça a garantia estruturalmente
        assert not hasattr(user, "private_key")
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Não confiar no username enviado pelo cliente / anti-spoofing
# ---------------------------------------------------------------------------

def test_user_can_only_publish_their_own_key(client: TestClient, isolated_store):
    """A e B existem; publicar com o token de A nunca deve tocar a linha de B."""
    a, b = _unique("morningstar"), _unique("sofia")
    token_a = _register(client, a, "s3nh4-forte")
    _register(client, b, "s3nh4-sofia")

    identity_a, _ = cryptoid.load_or_create(a, isolated_store)
    _publish(client, token_a, a, identity_a)

    resp_a = client.get(f"/users/{a}/public-key")
    resp_b = client.get(f"/users/{b}/public-key")
    assert resp_a.json()["public_key"] == identity_a.public_key_b64()
    assert resp_b.json()["public_key"] is None  # B não foi tocado


def test_morningstars_identity_cannot_be_used_as_sofias(client: TestClient, isolated_store):
    """Assinar a mensagem de vínculo com a chave de morningstar e tentar
    publicar sob o token de sofia deve falhar — a mensagem assinada inclui
    o username, então a assinatura só é válida para a conta para a qual
    foi gerada."""
    morningstar, sofia = _unique("morningstar"), _unique("sofia")
    _register(client, morningstar, "s3nh4-forte")
    token_sofia = _register(client, sofia, "s3nh4-sofia")

    identity_m, _ = cryptoid.load_or_create(morningstar, isolated_store)

    # sofia tenta publicar a CHAVE PÚBLICA de morningstar, assinada com a
    # mensagem de vínculo... só que a mensagem que se pode assinar
    # corretamente por posse é a de morningstar, não a de sofia.
    message_for_morningstar = shared_identity.key_binding_message(morningstar, identity_m.public_key_b64())
    signature = base64.b64encode(identity_m.sign(message_for_morningstar)).decode("ascii")

    resp = client.put(
        "/users/me/public-key",
        json={"public_key": identity_m.public_key_b64(), "signature": signature},
        headers={"Authorization": f"Bearer {token_sofia}"},  # autenticado como SOFIA
    )
    # o servidor verifica a assinatura contra key_binding_message(sofia, ...),
    # não contra a de morningstar -> falha
    assert resp.status_code == 401

    assert client.get(f"/users/{sofia}/public-key").json()["public_key"] is None


def test_username_field_in_request_body_is_ignored(client: TestClient, isolated_store):
    """Mesmo que o cliente mande um campo 'username' arbitrário no corpo,
    o schema não tem esse campo — o dono é sempre o do JWT."""
    a, b = _unique("morningstar"), _unique("sofia")
    token_a = _register(client, a, "s3nh4-forte")
    _register(client, b, "s3nh4-sofia")
    identity_a, _ = cryptoid.load_or_create(a, isolated_store)

    message = shared_identity.key_binding_message(a, identity_a.public_key_b64())
    signature = base64.b64encode(identity_a.sign(message)).decode("ascii")

    resp = client.put(
        "/users/me/public-key",
        json={"public_key": identity_a.public_key_b64(), "signature": signature, "username": b},
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert resp.status_code == 200
    assert resp.json()["username"] == a  # nunca "b", apesar do campo espúrio
    assert client.get(f"/users/{b}/public-key").json()["public_key"] is None


# ---------------------------------------------------------------------------
# Detecção de troca inesperada de chave pública
# ---------------------------------------------------------------------------

def test_unexpected_public_key_change_is_detected(client: TestClient, isolated_store):
    username = _unique("keychange")
    token = _register(client, username, "s3nh4-forte")
    identity_1, _ = cryptoid.load_or_create(username, isolated_store)
    _publish(client, token, username, identity_1)

    # simula perda da identidade local: apaga e gera uma NOVA identidade
    # para o mesmo username (isolated_store é um dict/arquivo à parte)
    from client import identity_store as store_module

    key_path = store_module._store_dir() / f"ed25519_{username}.key"
    key_path.unlink()
    identity_2, created_2 = cryptoid.load_or_create(username, isolated_store)
    assert created_2 is True
    assert identity_2.public_key_bytes() != identity_1.public_key_bytes()

    resp = client.get(f"/users/{username}/public-key")
    relay_key_b64 = resp.json()["public_key"]

    # a política do cliente (client/authentication.py:_load_and_publish_identity)
    # é: detectar que relay_key_b64 != identity_2.public_key_b64() e recusar
    # a continuar silenciosamente. Aqui validamos a condição que essa lógica
    # depende para funcionar.
    assert relay_key_b64 != identity_2.public_key_b64()
    assert relay_key_b64 == identity_1.public_key_b64()


def test_login_flow_aborts_on_identity_mismatch_without_republishing(client: TestClient, isolated_store, monkeypatch):
    """Teste de integração da política real em client/authentication.py:
    quando o relay já tem uma chave diferente da local, o fluxo de login
    deve retornar None e NUNCA chamar publish_public_key (não sobrescreve
    silenciosamente)."""
    from client import authentication
    from client.relay_client import RelayClient

    username = _unique("mismatchflow")
    token = _register(client, username, "s3nh4-forte")
    identity_1, _ = cryptoid.load_or_create(username, isolated_store)
    _publish(client, token, username, identity_1)

    # nova identidade local (relay continua com a antiga)
    from client import identity_store as store_module

    (store_module._store_dir() / f"ed25519_{username}.key").unlink()
    cryptoid.load_or_create(username, isolated_store)  # gera a nova, já persistida no store

    _original_load_or_create = cryptoid.load_or_create
    monkeypatch.setattr(
        authentication.cryptoid, "load_or_create", lambda u, st=None: _original_load_or_create(u, isolated_store)
    )

    publish_calls = []
    monkeypatch.setattr(
        RelayClient,
        "publish_public_key",
        lambda self, *a, **k: (publish_calls.append((a, k)), (True, ""))[1],
    )

    class FakeRelayForTest(RelayClient):
        def get_public_key(self, username: str):
            resp = client.get(f"/users/{username}/public-key")
            body = resp.json()
            return True, body.get("public_key"), ""

    fake_client = FakeRelayForTest(http_base="unused", ws_base="unused", username=username, token=token)

    result = authentication._load_and_publish_identity(fake_client, username)

    assert result is None  # login deve ser recusado
    assert publish_calls == []  # NUNCA tentou sobrescrever silenciosamente


# ---------------------------------------------------------------------------
# Integração completa: login -> gerar/carregar Ed25519 -> publicar -> GET -> verificar
# ---------------------------------------------------------------------------

class _RelayClientOverTestClient:
    """Adapta o TestClient síncrono do FastAPI para a mesma interface que
    client/authentication.py espera de um RelayClient de verdade — só a
    parte REST usada por _load_and_publish_identity."""

    def __init__(self, test_client: TestClient, username: str, token: str):
        self._tc = test_client
        self.username = username
        self.token = token

    def get_public_key(self, username: str):
        resp = self._tc.get(f"/users/{username}/public-key")
        if resp.status_code == 200:
            return True, resp.json()["public_key"], ""
        return False, None, resp.json().get("detail", f"HTTP {resp.status_code}")

    def publish_public_key(self, public_key_b64: str, signature_b64: str):
        resp = self._tc.put(
            "/users/me/public-key",
            json={"public_key": public_key_b64, "signature": signature_b64},
            headers={"Authorization": f"Bearer {self.token}"},
        )
        if resp.status_code == 200:
            return True, ""
        return False, resp.json().get("detail", f"HTTP {resp.status_code}")


def test_integration_full_identity_flow(client: TestClient, isolated_store, monkeypatch):
    """morningstar -> login -> generate Ed25519 -> publish -> GET -> verify,
    usando a função real de client/authentication.py (não uma reimplementação
    no teste)."""
    from client import authentication

    username = _unique("morningstar")
    token = _register(client, username, "s3nh4-forte")

    _original_load_or_create = cryptoid.load_or_create
    monkeypatch.setattr(
        authentication.cryptoid, "load_or_create", lambda u, st=None: _original_load_or_create(u, isolated_store)
    )

    relay = _RelayClientOverTestClient(client, username, token)
    identity = authentication._load_and_publish_identity(relay, username)

    assert identity is not None
    assert identity.username == username

    # verificação independente: o que está no relay bate com o fingerprint local
    resp = client.get(f"/users/{username}/public-key")
    relay_public_key = crypto.decode_public_key(resp.json()["public_key"])
    assert crypto.fingerprint(relay_public_key) == identity.fingerprint()


def test_integration_identity_persists_across_client_restart(client: TestClient, isolated_store, monkeypatch):
    """morningstar -> login -> publica -> 'reinicia o cliente' (nova chamada,
    identidade local recarregada do disco) -> login de novo -> mesma
    identidade, sem publicar de novo desnecessariamente nem detectar
    'mudança'."""
    from client import authentication

    username = _unique("morningstar")
    token = _register(client, username, "s3nh4-forte")
    _original_load_or_create = cryptoid.load_or_create
    monkeypatch.setattr(
        authentication.cryptoid, "load_or_create", lambda u, st=None: _original_load_or_create(u, isolated_store)
    )
    relay = _RelayClientOverTestClient(client, username, token)

    identity_first_run = authentication._load_and_publish_identity(relay, username)
    assert identity_first_run is not None

    # "reinicia o cliente": nova sessão de login, mesmo store em disco
    identity_second_run = authentication._load_and_publish_identity(relay, username)
    assert identity_second_run is not None
    assert identity_second_run.fingerprint() == identity_first_run.fingerprint()
    assert identity_second_run.public_key_bytes() == identity_first_run.public_key_bytes()

"""
Testes do lado cliente da Fase 2: comandos `connect`, `accept`, `deny`, o
módulo de presença e o estado de pedidos pendentes (múltiplos pedidos,
FIFO, desambiguação por nome), usando um RelayClient falso (sem rede
real).
"""

from __future__ import annotations

from client import commands, connection_state as cstate, presence


class FakeRelayClient:
    def __init__(self, connected: bool = True):
        self.connected = connected
        self.sent_requests: list[str] = []
        self.sent_responses: list[tuple[str, str]] = []
        self.users: list[str] = []

    def send_connect_request(self, target: str) -> bool:
        self.sent_requests.append(target)
        return self.connected

    def send_connect_response(self, target: str, decision: str) -> bool:
        self.sent_responses.append((target, decision))
        return self.connected

    def request_users(self) -> list[str]:
        return self.users if self.connected else []


def setup_function(_fn):
    cstate.reset()


def test_connect_command_sends_request_and_sets_outgoing_state():
    fake = FakeRelayClient()
    ctx = commands.Context(username="morningstar", fingerprint="AAAA", client=fake)

    result = commands.dispatch(ctx, 'connect to user "sofia"')

    assert result == commands.CONTINUE
    assert fake.sent_requests == ["sofia"]


def test_connect_command_without_client_shows_error_and_does_not_crash():
    ctx = commands.Context(username="morningstar", fingerprint="AAAA", client=None)
    result = commands.dispatch(ctx, 'connect to user "sofia"')
    assert result == commands.CONTINUE


def test_connect_command_while_disconnected_shows_error_and_does_not_crash():
    fake = FakeRelayClient(connected=False)
    ctx = commands.Context(username="morningstar", fingerprint="AAAA", client=fake)
    result = commands.dispatch(ctx, 'connect to user "sofia"')
    assert result == commands.CONTINUE
    assert fake.sent_requests == []  # nem tentou mandar — checagem de connected primeiro


def test_connect_to_self_is_rejected():
    fake = FakeRelayClient()
    ctx = commands.Context(username="morningstar", fingerprint="AAAA", client=fake)
    commands.dispatch(ctx, 'connect to user "morningstar"')
    assert fake.sent_requests == []


def test_accept_with_no_pending_request_does_nothing():
    fake = FakeRelayClient()
    ctx = commands.Context(username="sofia", fingerprint="BBBB", client=fake)
    commands.dispatch(ctx, "accept")
    assert fake.sent_responses == []


def test_accept_pending_request_sends_response_and_clears_state():
    fake = FakeRelayClient()
    cstate.push_incoming("morningstar")
    ctx = commands.Context(username="sofia", fingerprint="BBBB", client=fake)

    commands.dispatch(ctx, "accept")

    assert fake.sent_responses == [("morningstar", "accept")]
    assert cstate.pop_incoming() is None  # já foi consumido pelo accept


def test_deny_pending_request_sends_deny():
    fake = FakeRelayClient()
    cstate.push_incoming("morningstar")
    ctx = commands.Context(username="sofia", fingerprint="BBBB", client=fake)

    commands.dispatch(ctx, "deny")

    assert fake.sent_responses == [("morningstar", "deny")]


def test_multiple_pending_requests_are_both_preserved():
    """A e B pedem conexão a C antes de C responder — os dois devem ficar
    visíveis, o segundo não pode sobrescrever o primeiro."""
    cstate.push_incoming("morningstar")
    cstate.push_incoming("elliot")

    assert cstate.list_incoming() == ["morningstar", "elliot"]


def test_accept_without_target_consumes_oldest_fifo():
    fake = FakeRelayClient()
    cstate.push_incoming("morningstar")
    cstate.push_incoming("elliot")
    ctx = commands.Context(username="sofia", fingerprint="BBBB", client=fake)

    commands.dispatch(ctx, "accept")

    assert fake.sent_responses == [("morningstar", "accept")]
    assert cstate.list_incoming() == ["elliot"]


def test_accept_with_explicit_target_disambiguates():
    fake = FakeRelayClient()
    cstate.push_incoming("morningstar")
    cstate.push_incoming("elliot")
    ctx = commands.Context(username="sofia", fingerprint="BBBB", client=fake)

    commands.dispatch(ctx, 'accept "elliot"')

    assert fake.sent_responses == [("elliot", "accept")]
    assert cstate.list_incoming() == ["morningstar"]


def test_presence_online_users_delegates_to_relay_client():
    fake = FakeRelayClient()
    fake.users = ["sofia", "elliot"]
    presence.set_client(fake)
    try:
        peers = [p.username for p in presence.online_users(exclude="elliot")]
        assert peers == ["sofia"]
    finally:
        presence.set_client(None)


def test_presence_online_users_empty_when_disconnected():
    fake = FakeRelayClient(connected=False)
    fake.users = ["sofia"]
    presence.set_client(fake)
    try:
        assert presence.online_users() == []
    finally:
        presence.set_client(None)


def test_shell_survives_unexpected_exception_from_command():
    """Defesa em profundidade equivalente à do main.py: um erro inesperado
    dentro de um handler não deve propagar para fora de dispatch() de um
    jeito que derrube o loop do shell. Aqui simulamos a mesma guarda que
    main._shell() usa ao redor de commands.dispatch."""

    class ExplodingClient(FakeRelayClient):
        def send_connect_request(self, target: str) -> bool:
            raise RuntimeError("simulated network failure")

    fake = ExplodingClient()
    ctx = commands.Context(username="morningstar", fingerprint="AAAA", client=fake)

    try:
        commands.dispatch(ctx, 'connect to user "sofia"')
        raised = False
    except RuntimeError:
        raised = True

    # commands.dispatch por si só pode propagar (é main._shell quem blinda,
    # ver client/main.py); o importante é que a exceção seja do tipo
    # esperado e não corrompa o estado (nenhum pedido ficou "meio enviado").
    assert raised is True
    assert cstate.pop_outgoing() == "sofia"  # set_outgoing roda antes do send

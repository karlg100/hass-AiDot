"""Transport-layer tests for ble_gateway_client.

These exercise the per-hub session: a shared lock (serialises the 8 entities
that share one hub), connection reuse (login once, reuse the socket), and retry
on transient connection errors. The socket layer is faked; the AES framing is
real (round-tripped through the installed ``aidot`` library).
"""

import asyncio
import json

import pytest

import ble_gateway_client as bgc


# --- fakes -----------------------------------------------------------------


class _Tracker:
    """Counts max concurrent entries to detect interleaving."""

    def __init__(self) -> None:
        self.active = 0
        self.max = 0

    def enter(self) -> None:
        self.active += 1
        self.max = max(self.max, self.active)

    def exit(self) -> None:
        self.active -= 1


class FakeWriter:
    def __init__(self, tracker: _Tracker | None = None) -> None:
        self.tracker = tracker
        self.writes: list[bytes] = []
        self._closed = False

    def write(self, data: bytes) -> None:
        self.writes.append(data)

    async def drain(self) -> None:
        # Yield control so a second, unsynchronised command could interleave.
        if self.tracker is not None:
            self.tracker.enter()
            await asyncio.sleep(0)
            self.tracker.exit()
        else:
            await asyncio.sleep(0)

    def close(self) -> None:
        self._closed = True

    def is_closing(self) -> bool:
        return self._closed

    async def wait_closed(self) -> None:
        pass


class FakeReader:
    """Serves pre-framed bytes; raises ``exc`` once the buffer is exhausted."""

    def __init__(self, frames: list[bytes], exc: Exception | None = None) -> None:
        self._buf = b"".join(frames)
        self._pos = 0
        self._exc = exc or ConnectionResetError(104, "reset")

    async def readexactly(self, n: int) -> bytes:
        if len(self._buf) - self._pos < n:
            raise self._exc
        chunk = self._buf[self._pos : self._pos + n]
        self._pos += n
        return chunk


class FakeServer:
    """Hands out one (reader, writer) per ``open_connection`` call."""

    def __init__(self, conn_specs: list[dict]) -> None:
        # Each spec: {"frames": [...], "exc": Exception|None, "tracker": Tracker|None}
        self._specs = conn_specs
        self.connect_count = 0
        self.writers: list[FakeWriter] = []
        self.readers: list[FakeReader] = []

    async def open_connection(self, host, port):
        spec = self._specs[min(self.connect_count, len(self._specs) - 1)]
        self.connect_count += 1
        reader = FakeReader(spec.get("frames", []), spec.get("exc"))
        writer = FakeWriter(spec.get("tracker"))
        self.readers.append(reader)
        self.writers.append(writer)
        return reader, writer


# --- helpers ---------------------------------------------------------------

KEY = bgc._make_aes_key("testkey")


def _frame_obj(obj: dict) -> bytes:
    return bgc._frame(json.dumps(obj).encode(), KEY)


def _login_frame(asc: int = 5) -> bytes:
    return _frame_obj({"payload": {"ascNumber": asc}})


def _ack_frame() -> bytes:
    return _frame_obj({"payload": {}})


def _attr_frame(attr: dict) -> bytes:
    return _frame_obj({"payload": {"attr": attr}})


def _session() -> "bgc._HubSession":
    return bgc._HubSession(
        hub_id="hub1",
        hub_ip="10.0.0.5",
        aes_key=KEY,
        user_id="user1",
        hub_password="pw",
    )


def _count_logins(writer: FakeWriter) -> int:
    """Decode written frames and count loginReq messages."""
    count = 0
    for data in writer.writes:
        body = data[8:]  # strip 8-byte header
        try:
            msg = json.loads(bgc._aes_decrypt(body, KEY))
        except Exception:
            continue
        if msg.get("method") == "loginReq":
            count += 1
    return count


@pytest.fixture(autouse=True)
def _clear_registry():
    bgc._HUB_SESSIONS.clear()
    yield
    bgc._HUB_SESSIONS.clear()


# --- tests -----------------------------------------------------------------


async def test_concurrent_commands_serialise(monkeypatch):
    """Two commands racing on the same hub must not interleave (shared lock)."""
    tracker = _Tracker()
    # One connection, reused; enough acks for both commands.
    server = FakeServer(
        [{"frames": [_login_frame(), _ack_frame(), _ack_frame()], "tracker": tracker}]
    )
    monkeypatch.setattr(bgc.asyncio, "open_connection", server.open_connection)

    sess = _session()
    await asyncio.gather(
        sess.send_command("devA", {"OnOff": 1}),
        sess.send_command("devB", {"OnOff": 0}),
    )

    assert tracker.max == 1, "commands interleaved — lock not held across the call"


async def test_connection_is_reused_login_once(monkeypatch):
    """Sequential commands reuse the socket and log in exactly once."""
    server = FakeServer(
        [{"frames": [_login_frame(), _ack_frame(), _ack_frame()]}]
    )
    monkeypatch.setattr(bgc.asyncio, "open_connection", server.open_connection)

    sess = _session()
    await sess.send_command("devA", {"OnOff": 1})
    await sess.send_command("devA", {"OnOff": 0})

    assert server.connect_count == 1, "opened a new connection instead of reusing"
    assert _count_logins(server.writers[0]) == 1, "logged in more than once"


async def test_ascnumber_increments_per_command(monkeypatch):
    """Reused connection bumps ascNumber per command (login asc was 5)."""
    server = FakeServer(
        [{"frames": [_login_frame(asc=5), _ack_frame(), _ack_frame()]}]
    )
    monkeypatch.setattr(bgc.asyncio, "open_connection", server.open_connection)

    sess = _session()
    await sess.send_command("devA", {"OnOff": 1})
    await sess.send_command("devA", {"OnOff": 0})

    ascs = []
    for data in server.writers[0].writes:
        msg = json.loads(bgc._aes_decrypt(data[8:], KEY))
        if msg.get("method") == "setDevAttrReq":
            ascs.append(msg["payload"]["ascNumber"])
    assert ascs == [6, 7], f"expected ascNumber 6,7 got {ascs}"


async def test_get_attributes_uses_ble_channel_and_returns_telemetry(monkeypatch):
    """A diagnostic read sends getDevAttrReq and returns the attribute payload."""
    server = FakeServer(
        [{"frames": [_login_frame(), _attr_frame({"Battery": 87, "RSSI": -61})]}]
    )
    monkeypatch.setattr(bgc.asyncio, "open_connection", server.open_connection)

    sess = _session()
    responses = await sess.get_attributes("devA", ["Battery", "RSSI"])

    messages = [
        json.loads(bgc._aes_decrypt(data[8:], KEY))
        for data in server.writers[0].writes
    ]
    request = next(msg for msg in messages if msg.get("method") == "getDevAttrReq")
    assert request["payload"]["channel"] == "ble"
    assert request["payload"]["attr"] == ["Battery", "RSSI"]
    assert responses[0]["payload"]["attr"] == {"Battery": 87, "RSSI": -61}
    assert server.writers[0].is_closing()


async def test_get_attributes_collects_ack_and_followup_telemetry(monkeypatch):
    """The hub may acknowledge first and send the attribute payload second."""
    server = FakeServer(
        [
            {
                "frames": [
                    _login_frame(),
                    _ack_frame(),
                    _attr_frame({"Battery": 54}),
                ]
            }
        ]
    )
    monkeypatch.setattr(bgc.asyncio, "open_connection", server.open_connection)

    responses = await _session().get_attributes("devA", ["Battery"])

    assert len(responses) == 2
    assert responses[1]["payload"]["attr"]["Battery"] == 54


async def test_retry_reconnects_after_reset(monkeypatch):
    """A transient reset on the first attempt triggers reconnect + relogin."""
    monkeypatch.setattr(bgc, "_BACKOFF", 0)
    server = FakeServer(
        [
            {"frames": [_login_frame()], "exc": ConnectionResetError(104, "reset")},
            {"frames": [_login_frame(), _ack_frame()]},
        ]
    )
    monkeypatch.setattr(bgc.asyncio, "open_connection", server.open_connection)

    sess = _session()
    await sess.send_command("devA", {"OnOff": 1})

    assert server.connect_count == 2, "did not reconnect after reset"


async def test_retry_gives_up_after_max_attempts(monkeypatch):
    """Persistent failure raises after _MAX_RETRIES attempts."""
    monkeypatch.setattr(bgc, "_BACKOFF", 0)
    server = FakeServer(
        [{"frames": [_login_frame()], "exc": ConnectionResetError(104, "reset")}]
    )
    monkeypatch.setattr(bgc.asyncio, "open_connection", server.open_connection)

    sess = _session()
    with pytest.raises(ConnectionResetError):
        await sess.send_command("devA", {"OnOff": 1})

    assert server.connect_count == bgc._MAX_RETRIES


async def test_close_all_hub_sessions_clears_registry(monkeypatch):
    """close_all_hub_sessions() closes live writers and empties the registry."""
    server = FakeServer([{"frames": [_login_frame(), _ack_frame()]}])
    monkeypatch.setattr(bgc.asyncio, "open_connection", server.open_connection)

    client = _make_client()
    await client.async_turn_on()
    assert bgc._HUB_SESSIONS  # session was created

    await bgc.close_all_hub_sessions()

    assert not bgc._HUB_SESSIONS
    assert server.writers[0].is_closing()


# --- behaviour preserved through the client (regression guard) -------------


def _make_client() -> "bgc.BleGatewayDeviceClient":
    device = {
        "id": "devA",
        "mac": "AA:BB",
        "name": "Spot 1",
        "product": {"serviceModules": []},
        "properties": {},
    }
    hub = {
        "id": "hub1",
        "password": "pw",
        "aesKey": ["testkey"],
        "properties": {"ipAddress": "10.0.0.5"},
    }
    return bgc.BleGatewayDeviceClient(device, hub, "user1")


def _make_diagnostic_client() -> "bgc.BleGatewayDeviceClient":
    device = {
        "id": "secret-device-id",
        "mac": "AA:BB:CC:DD:EE:FF",
        "name": "Back Garden",
        "modelId": "LK.A000181",
        "hardwareVersion": "1.0",
        "type": "light",
        "bleMeshDeviceKey": "secret-mesh-key",
        "product": {
            "serviceModules": [
                {
                    "identity": "sensor.battery",
                    "properties": [
                        {
                            "identity": "Battery",
                            "dataType": "int",
                            "minValue": 0,
                            "maxValue": 100,
                        }
                    ],
                },
                {
                    "identity": "diagnostic.signal",
                    "properties": [{"identity": "RSSI", "dataType": "int"}],
                },
            ]
        },
        "properties": {
            "OnOff": 0,
            "Battery": 86,
            "ipAddress": "192.0.2.10",
            "ssidName": "Private WiFi",
        },
    }
    hub = {
        "id": "secret-hub-id",
        "password": "secret-password",
        "aesKey": ["testkey"],
        "properties": {"ipAddress": "10.0.0.5"},
    }
    return bgc.BleGatewayDeviceClient(device, hub, "secret-user-id")


async def test_diagnostics_are_redacted_and_probe_advertised_attributes(monkeypatch):
    """Diagnostics retain telemetry while removing credentials and identifiers."""
    server = FakeServer(
        [
            {
                "frames": [
                    _login_frame(),
                    _attr_frame(
                        {
                            "Battery": 87,
                            "RSSI": -61,
                            "password": "response-secret",
                            "AESKey": "response-aes-secret",
                            "houseId": "response-house-id",
                            "echo": "secret-password",
                        }
                    ),
                ]
            }
        ]
    )
    monkeypatch.setattr(bgc.asyncio, "open_connection", server.open_connection)

    diagnostics = await _make_diagnostic_client().async_get_diagnostics()
    encoded = json.dumps(diagnostics)

    assert diagnostics["requestedAttributes"] == ["Battery", "OnOff", "RSSI"]
    assert diagnostics["cloud"]["properties"]["Battery"] == 86
    assert diagnostics["cloud"]["properties"]["ipAddress"] == bgc._REDACTED
    assert diagnostics["probe"]["responses"][0]["payload"]["attr"]["Battery"] == 87
    response_attr = diagnostics["probe"]["responses"][0]["payload"]["attr"]
    assert response_attr["password"] == bgc._REDACTED
    assert response_attr["AESKey"] == bgc._REDACTED
    assert response_attr["houseId"] == bgc._REDACTED
    assert response_attr["echo"] == bgc._REDACTED
    for secret in (
        "secret-device-id",
        "AA:BB:CC:DD:EE:FF",
        "Back Garden",
        "secret-mesh-key",
        "Private WiFi",
        "secret-hub-id",
        "secret-password",
        "testkey",
        "secret-user-id",
        "response-secret",
        "response-aes-secret",
        "response-house-id",
    ):
        assert secret not in encoded


async def test_optimistic_status_updates_after_command(monkeypatch):
    """async_set_brightness still updates cached status and fires the callback."""
    server = FakeServer([{"frames": [_login_frame(), _ack_frame()]}])
    monkeypatch.setattr(bgc.asyncio, "open_connection", server.open_connection)

    client = _make_client()
    seen = []
    client.on_status_update = seen.append

    await client.async_set_brightness(255)

    assert client.status.on is True
    assert client.status.dimming == 255
    assert seen and seen[-1] is client.status

"""Transport-layer tests for ble_gateway_client.

These exercise the per-hub session: a shared lock (serialises the 8 entities
that share one hub), connection reuse (login once, reuse the socket), and retry
on transient connection errors. The socket layer is faked; the AES framing is
real (round-tripped through the installed ``aidot`` library).
"""

import asyncio
import json
import struct

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
    """Serve framed bytes, then remain open unless an error was requested."""

    def __init__(self, frames: list[bytes], exc: Exception | None = None) -> None:
        self._buf = b"".join(frames)
        self._pos = 0
        self._exc = exc

    async def readexactly(self, n: int) -> bytes:
        if len(self._buf) - self._pos < n:
            if self._exc is not None:
                raise self._exc
            await asyncio.Future()
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


def _ack_frame(seq: str = "ha9300001") -> bytes:
    return _frame_obj({"seq": seq, "payload": {}})


def _attr_frame(
    attr: dict,
    *,
    dev_id: str = "devA",
    method: str = "devAttrNotify",
    seq: str | None = None,
) -> bytes:
    response = {
        "method": method,
        "deviceId": dev_id,
        "payload": {"devId": dev_id, "attr": attr},
    }
    if seq is not None:
        response["seq"] = seq
    return _frame_obj(response)


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
async def _clear_registry():
    bgc._HUB_SESSIONS.clear()
    bgc._seq = 0
    yield
    await bgc.close_all_hub_sessions()


# --- tests -----------------------------------------------------------------


async def test_concurrent_commands_serialise(monkeypatch):
    """Two commands racing on the same hub must not interleave (shared lock)."""
    tracker = _Tracker()
    # One connection, reused; enough acks for both commands.
    server = FakeServer(
        [{
            "frames": [
                _login_frame(),
                _ack_frame("ha9300001"),
                _ack_frame("ha9300002"),
            ],
            "tracker": tracker,
        }]
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
        [{
            "frames": [
                _login_frame(),
                _ack_frame("ha9300001"),
                _ack_frame("ha9300002"),
            ]
        }]
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
        [{
            "frames": [
                _login_frame(asc=5),
                _ack_frame("ha9300001"),
                _ack_frame("ha9300002"),
            ]
        }]
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
    """An explicit read is correlated while the passive connection stays open."""
    server = FakeServer(
        [{
            "frames": [
                _login_frame(),
                _attr_frame(
                    {"Battery": 87, "RSSI": -61}, seq="ha9300001"
                ),
            ]
        }]
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
    assert not server.writers[0].is_closing()


async def test_get_attributes_collects_ack_and_followup_telemetry(monkeypatch):
    """The hub may acknowledge first and send the attribute payload second."""
    server = FakeServer(
        [
            {
                "frames": [
                    _login_frame(),
                    _ack_frame("ha9300001"),
                    _attr_frame({"Battery": 54}, seq="ha9300001"),
                ]
            }
        ]
    )
    monkeypatch.setattr(bgc.asyncio, "open_connection", server.open_connection)

    responses = await _session().get_attributes("devA", ["Battery"])

    assert len(responses) == 2
    assert responses[1]["payload"]["attr"]["Battery"] == 54


async def test_unsolicited_update_does_not_complete_another_device_request(
    monkeypatch,
):
    """An interleaved push is routed without stealing a command response."""
    server = FakeServer([
        {
            "frames": [
                _login_frame(),
                _attr_frame({"OnOff": 1}, dev_id="devB"),
                _ack_frame("ha9300001"),
            ]
        }
    ])
    monkeypatch.setattr(bgc.asyncio, "open_connection", server.open_connection)

    client_a = _make_client("devA", "Spot A")
    client_b = _make_client("devB", "Spot B")
    await client_a.async_turn_on()

    assert client_a.status.on is True
    assert client_b.status.on is True


async def test_retry_reconnects_after_reset(monkeypatch):
    """A transient reset on the first attempt triggers reconnect + relogin."""
    monkeypatch.setattr(bgc, "_BACKOFF", 0)
    server = FakeServer(
        [
            {"frames": [_login_frame()], "exc": ConnectionResetError(104, "reset")},
            {"frames": [_login_frame(), _ack_frame("ha9300002")]},
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
    with pytest.raises(ConnectionError):
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


async def test_passive_listener_reconnects_and_resumes_routing(monkeypatch):
    """A dropped hub socket reconnects without polling any BLE device."""
    monkeypatch.setattr(bgc, "_BACKOFF", 0)
    server = FakeServer([
        {
            "frames": [_login_frame(), _attr_frame({"OnOff": 1})],
            "exc": ConnectionResetError(104, "reset"),
        },
        {"frames": [_login_frame(), _attr_frame({"OnOff": 0})]},
    ])
    monkeypatch.setattr(bgc.asyncio, "open_connection", server.open_connection)

    client = _make_client()
    await bgc.start_all_hub_sessions()
    for _ in range(20):
        diagnostics = client._hub_session.device_diagnostics("devA")
        if diagnostics["deviceUpdateCount"] == 2:
            break
        await asyncio.sleep(0)

    assert server.connect_count == 2
    assert diagnostics["deviceUpdateCount"] == 2
    assert client.status.on is False
    assert all(
        json.loads(bgc._aes_decrypt(data[8:], KEY))["method"] == "loginReq"
        for writer in server.writers
        for data in writer.writes
    )


async def test_keepalive_targets_only_the_powered_hub(monkeypatch):
    """The listener keepalive contains no BLE device query or identifier."""
    monkeypatch.setattr(bgc, "_HUB_KEEPALIVE_INTERVAL", 0.001)
    server = FakeServer([{"frames": [_login_frame()]}])
    monkeypatch.setattr(bgc.asyncio, "open_connection", server.open_connection)

    _make_client()
    await bgc.start_all_hub_sessions()
    await asyncio.sleep(0.005)

    framed_messages = [
        (
            struct.unpack(">HhI", data[:8])[1],
            json.loads(bgc._aes_decrypt(data[8:], KEY)),
        )
        for data in server.writers[0].writes
    ]
    pings = [message for message_type, message in framed_messages if message_type == 2]
    assert pings
    assert all(ping["method"] == "pingreq" for ping in pings)
    assert all(ping["service"] == "test" for ping in pings)
    assert all(ping["payload"] == {} for ping in pings)
    assert all("deviceId" not in ping for ping in pings)
    assert all(
        message["method"] != "getDevAttrReq"
        for _, message in framed_messages
    )


def test_response_device_id_prefers_light_source_over_hub_device_id() -> None:
    """A source address can route a notification whose deviceId is the hub."""
    assert (
        bgc._HubSession._response_device_id(
            {"srcAddr": "1.devA", "deviceId": "hub1"}, {}
        )
        == "devA"
    )


# --- behaviour preserved through the client (regression guard) -------------


def _make_client(
    dev_id: str = "devA", name: str = "Spot 1"
) -> "bgc.BleGatewayDeviceClient":
    device = {
        "id": dev_id,
        "mac": "AA:BB",
        "name": name,
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
                    "name": "1",
                    "properties": [
                        {
                            "identity": "Battery_remaining",
                            "dataType": "int",
                            "minValue": 0,
                            "maxValue": 100,
                        }
                    ],
                },
                {
                    "identity": "diagnostic.signal",
                    "properties": [
                        {"identity": "meshNetRssi", "dataType": "int"}
                    ],
                },
            ]
        },
        "properties": {
            "OnOff": 0,
            "Battery_remaining": 86,
            "chargeState": "1",
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


async def test_diagnostics_are_redacted_without_active_probe():
    """Diagnostics expose listener health without waking a BLE light."""
    diagnostics = await _make_diagnostic_client().async_get_diagnostics()
    encoded = json.dumps(diagnostics)

    assert diagnostics["requestedAttributes"] == [
        "Battery_remaining",
        "OnOff",
        "chargeState",
        "meshNetRssi",
    ]
    assert len(diagnostics["anonymousDeviceId"]) == 12
    assert diagnostics["cloud"]["properties"]["Battery_remaining"] == 86
    assert diagnostics["cloud"]["properties"]["chargeState"] == "1"
    assert diagnostics["cloud"]["serviceModules"][0]["identity"] == "sensor.battery"
    assert diagnostics["cloud"]["serviceModules"][0]["name"] == "1"
    assert diagnostics["cloud"]["properties"]["ipAddress"] == bgc._REDACTED
    assert diagnostics["probe"]["status"] == "disabled_passive_mode"
    assert diagnostics["listener"]["mode"] == "passive_hub_listener"
    assert diagnostics["listener"]["registered"] is True
    assert diagnostics["listener"]["deviceUpdateCount"] == 0
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
    ):
        assert secret not in encoded


def test_cloud_telemetry_initializes_and_refreshes() -> None:
    """Battery, mesh RSSI, and charge state follow refreshed cloud properties."""
    device = {
        "id": "devA",
        "mac": "AA:BB",
        "name": "Spot 1",
        "product": {
            "serviceModules": [
                {
                    "identity": "control.light.effect.mode",
                    "properties": [
                        {
                            "identity": "EffectMode",
                            "allowedValues": [
                                {"description": "party", "value": 5},
                                {"description": "bonfire", "value": 10},
                            ],
                        }
                    ],
                }
            ]
        },
        "properties": {
            "Battery_remaining": "65",
            "meshNetRssi": "-40",
            "chargeState": "1",
            "energySavingEnable": "1",
            "energySavingFactor": "0.8",
            "lightDuration": "30",
            "SecurityAlarm": "2",
            "alarmStatus": "0",
            "EffectMode": "5",
        },
    }
    hub = {
        "id": "hub1",
        "password": "pw",
        "aesKey": ["testkey"],
        "properties": {"ipAddress": "10.0.0.5"},
    }
    client = bgc.BleGatewayDeviceClient(device, hub, "user1")
    seen = []
    client.on_status_update = seen.append

    assert client.status.battery == 65
    assert client.status.mesh_rssi == -40
    assert client.status.charging is True
    assert client.status.energy_saving_enabled is True
    assert client.status.energy_saving_factor == 80
    assert client.status.light_duration == 30
    assert client.status.security_alarm is True
    assert client.status.alarm_status is False
    assert client.status.effect_mode == 5
    assert client.info.effects == {"Party": 5, "Bonfire": 10}

    client.update_cloud_properties(
        {
            **device,
            "properties": {
                "Battery_remaining": "54",
                "meshNetRssi": "-67",
                "chargeState": "0",
                "OnOff": "1",
                "Dimming": "20",
                "CCT": "3000",
                "RGBW": str(0x10203040),
            },
        }
    )

    assert client.status.battery == 54
    assert client.status.mesh_rssi == -67
    assert client.status.charging is False
    assert client.status.on is True
    assert client.status.dimming == 51
    assert client.status.cct == 3000
    assert client.status.rgbw == (0x10, 0x20, 0x30, 0x40)
    assert client.status.energy_saving_enabled is True
    assert client.status.energy_saving_factor == 80
    assert seen and seen[-1] is client.status


async def test_passive_update_refreshes_light_and_telemetry(monkeypatch) -> None:
    """An unsolicited hub frame updates state without querying the BLE light."""
    server = FakeServer([
        {
            "frames": [
                _login_frame(),
                _attr_frame(
                    {
                        "OnOff": 1,
                        "Dimming": 40,
                        "CCT": 3200,
                        "RGBW": 0x11223344,
                        "Battery_remaining": 34,
                    },
                    dev_id="secret-device-id",
                ),
            ]
        }
    ])
    monkeypatch.setattr(bgc.asyncio, "open_connection", server.open_connection)

    client = _make_diagnostic_client()
    seen: list[bool] = []
    client.on_status_update = lambda status: seen.append(status.on)
    await bgc.start_all_hub_sessions()
    await asyncio.sleep(0)

    assert client.status.on is True
    assert client.status.dimming == 102
    assert client.status.cct == 3200
    assert client.status.rgbw == (0x11, 0x22, 0x33, 0x44)
    assert client.status.battery == 34
    assert client.status.telemetry_connected is True
    assert client.status.last_telemetry_update is not None
    assert seen == [False, True]

    messages = [
        json.loads(bgc._aes_decrypt(data[8:], KEY))
        for data in server.writers[0].writes
    ]
    assert [message["method"] for message in messages] == ["loginReq"]


async def test_passive_updates_are_routed_to_the_correct_device(monkeypatch) -> None:
    """One shared hub reader must never apply one light's update to another."""
    server = FakeServer([
        {
            "frames": [
                _login_frame(),
                _attr_frame({"OnOff": 1}, dev_id="devA"),
                _attr_frame(
                    {"OnOff": 0, "Battery_remaining": 72}, dev_id="devB"
                ),
            ]
        }
    ])
    monkeypatch.setattr(bgc.asyncio, "open_connection", server.open_connection)

    client_a = _make_client("devA", "Spot A")
    client_b = _make_client("devB", "Spot B")
    await bgc.start_all_hub_sessions()
    await asyncio.sleep(0)

    assert client_a.status.on is True
    assert client_a.status.battery is None
    assert client_b.status.on is False
    assert client_b.status.battery == 72


async def test_passive_autonomous_off_is_forwarded(monkeypatch) -> None:
    """A fixture's timer-driven off update reaches Home Assistant callbacks."""
    server = FakeServer([
        {
            "frames": [
                _login_frame(),
                _attr_frame({"OnOff": 1}, dev_id="devA"),
                _attr_frame({"OnOff": 0}, dev_id="devA"),
            ]
        }
    ])
    monkeypatch.setattr(bgc.asyncio, "open_connection", server.open_connection)

    client = _make_client()
    states: list[bool] = []
    client.on_status_update = lambda status: states.append(status.on)
    await bgc.start_all_hub_sessions()
    await asyncio.sleep(0)

    assert states == [False, True, False]
    assert client.status.on is False


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


async def test_effect_command_updates_cached_mode(monkeypatch):
    """BLE effect commands use EffectMode and update coordinator memory."""
    server = FakeServer([{"frames": [_login_frame(), _ack_frame()]}])
    monkeypatch.setattr(bgc.asyncio, "open_connection", server.open_connection)

    client = _make_client()
    await client.async_set_effect(10)

    request = next(
        json.loads(bgc._aes_decrypt(data[8:], KEY))
        for data in server.writers[0].writes
        if json.loads(bgc._aes_decrypt(data[8:], KEY)).get("method")
        == "setDevAttrReq"
    )
    assert request["payload"]["attr"] == {"OnOff": 1, "EffectMode": 10}
    assert client.status.effect_mode == 10

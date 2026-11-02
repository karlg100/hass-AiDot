"""Discover real firmware mode IDs without a fixed list of scene names."""

from copy import deepcopy
from unittest.mock import AsyncMock

import pytest
from scene_catalogue import SceneCatalogue, parse_scenes


def row(name="Meteor", mode=130, **changes):
    return {
        "name": name, "id": mode, "type": "BLE RGBW", "jsonType": "hex",
        "params": [], "isFixed": 1, "visible": True, **changes,
    }


def device(**changes):
    return {
        "modelId": "LK.A000181", "firmwareVersion": "3.6.36",
        "properties": {"lightScriptFlags": "capabilities"}, **changes,
    }


def test_legacy_catalogue_and_future_names_are_discovered_without_a_limit():
    entries = [row(f"Vendor scene {index}", 100 + index) for index in range(39)]
    assert len(parse_scenes({"data": entries, "primitive": []})) == 39
    entries.append(row("A newly published scene", 900))
    assert parse_scenes({"data": entries})["A newly published scene"] == 900


@pytest.mark.parametrize("changes", [
    {"visible": False}, {"type": "WiFi RGBW"}, {"jsonType": "script"},
    {"isFixed": 0}, {"params": [{"arbitrary": "command"}]}, {"id": True},
    {"id": 1.5}, {"id": 0}, {"id": 65536}, {"name": ""},
])
def test_only_supported_builtin_modes_become_light_commands(changes):
    assert parse_scenes({"data": [row(), {**row("Invalid", 131), **changes}]}) == {
        "Meteor": 130
    }


def test_numeric_string_ids_and_duplicate_display_names():
    assert parse_scenes({"data": [row(mode="130"), row(mode=131)]}) == {
        "Meteor": 130, "Meteor (2)": 131,
    }


@pytest.mark.parametrize("response", [None, {}, {"data": {}}, {"data": [row(params=None)]}])
def test_unrecognized_responses_are_failures_not_empty_catalogues(response):
    with pytest.raises((TypeError, ValueError)):
        parse_scenes(response)


async def test_one_request_per_variant_and_new_scenes_appear_on_refresh():
    get = AsyncMock(return_value={"data": [row()]})
    catalogue = SceneCatalogue(get)
    d = device()
    await catalogue.async_refresh([d, deepcopy(d)])
    get.assert_awaited_once_with(
        "/models/LK.A000181/v3.0/effectModes?libraryId=aidot.preset"
        "&version=3.6.36&lightScriptFlags=capabilities"
    )
    assert catalogue.for_device(d) == {"Meteor": 130}
    get.return_value = {"data": [row(), row("New vendor scene", 999)]}
    await catalogue.async_refresh([d])
    assert catalogue.for_device(d)["New vendor scene"] == 999
    assert catalogue.diagnostics[0]["sceneCount"] == 2


@pytest.mark.parametrize("failure", [ConnectionError(), {"unexpected": []}])
async def test_failed_refresh_retains_good_catalogue_and_recovers(failure):
    get = AsyncMock(return_value={"data": [row()]})
    catalogue = SceneCatalogue(get)
    d = device()
    await catalogue.async_refresh([d])
    if isinstance(failure, Exception):
        get.side_effect = failure
    else:
        get.return_value = failure
    await catalogue.async_refresh([d])
    assert catalogue.for_device(d) == {"Meteor": 130}
    assert catalogue.diagnostics[0]["lastErrorType"] is not None
    get.side_effect = None
    get.return_value = {"data": [row("Replacement", 131)]}
    await catalogue.async_refresh([d])
    assert catalogue.for_device(d) == {"Replacement": 131}
    assert catalogue.diagnostics[0]["lastErrorType"] is None


async def test_capability_variants_never_reuse_incompatible_cached_modes():
    get = AsyncMock(return_value={"data": [row()]})
    catalogue = SceneCatalogue(get)
    d = device()
    await catalogue.async_refresh([d])
    newer = device(firmwareVersion="4.0.0")
    get.side_effect = ConnectionError()
    await catalogue.async_refresh([newer])
    assert catalogue.for_device(newer) == {}
    assert catalogue.for_device(d) == {"Meteor": 130}
    assert catalogue.for_device({}) == {}


async def test_explicit_empty_catalogue_removes_retired_scenes_and_copies_are_isolated():
    get = AsyncMock(return_value={"data": [row()]})
    catalogue = SceneCatalogue(get)
    d = device()
    await catalogue.async_refresh([d])
    catalogue.for_device(d).clear()
    assert catalogue.for_device(d) == {"Meteor": 130}
    get.return_value = {"data": []}
    await catalogue.async_refresh([d])
    assert catalogue.for_device(d) == {}

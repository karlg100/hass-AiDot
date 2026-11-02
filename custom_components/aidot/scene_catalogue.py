"""Discover firmware-backed BLE scenes from AiDot's model catalogue."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Iterable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, urlencode

_LOGGER = logging.getLogger(__name__)
type CatalogueKey = tuple[str, str, str]


def catalogue_key(device: dict) -> CatalogueKey:
    """Keep firmware and script capabilities isolated between models."""
    return (
        str(device.get("modelId") or ""),
        str(device.get("firmwareVersion") or ""),
        str(device.get("properties", {}).get("lightScriptFlags") or ""),
    )


def parse_scenes(response: Any) -> dict[str, int]:
    """Read built-in BLE mode IDs, not the newer primitive script format.

    The legacy ``data`` array carries the app's scene names and firmware mode
    IDs. Empty params are normal for these built-ins. Parameterized/custom
    scripts require a different execution path and must not become mode writes.
    """
    if not isinstance(response, dict) or not isinstance(response.get("data"), list):
        raise TypeError("Missing BLE scene catalogue")
    scenes: dict[str, int] = {}
    for row in response["data"]:
        if not isinstance(row, dict) or row.get("visible") is False:
            continue
        if (
            row.get("type") != "BLE RGBW"
            or row.get("jsonType") != "hex"
            or row.get("params") != []
        ):
            continue
        # Some factory catalogue modes have isFixed=0 but use the same
        # parameter-free hex representation. That flag is not a mode filter.
        name, mode = row.get("name"), row.get("id")
        if isinstance(mode, str) and mode.isascii() and mode.isdecimal():
            mode = int(mode)
        if (
            not isinstance(name, str) or not name.strip() or len(name) > 128
            or type(mode) is not int or not 1 <= mode <= 65535
        ):
            continue
        name = name.strip()
        label, duplicate = name, 2
        while label in scenes and scenes[label] != mode:
            label = f"{name} ({duplicate})"
            duplicate += 1
        scenes[label] = mode
    if response["data"] and not scenes:
        raise ValueError("No supported built-in BLE scenes in catalogue")
    return scenes


class SceneCatalogue:
    """Refresh once per model/firmware/capability variant, retaining good data."""

    def __init__(self, get: Callable[[str], Awaitable[dict]]) -> None:
        self._get = get
        self._cache: dict[CatalogueKey, dict[str, int]] = {}
        self._health: dict[CatalogueKey, dict] = {}
        self._slots = asyncio.Semaphore(3)

    async def async_refresh(self, devices: Iterable[dict]) -> None:
        keys = {
            catalogue_key(device) for device in devices
            if isinstance(device.get("modelId"), str) and device["modelId"]
        }
        await asyncio.gather(*(self._refresh(key) for key in sorted(keys)))

    async def _refresh(self, key: CatalogueKey) -> None:
        model, firmware, flags = key
        query = {"libraryId": "aidot.preset"}
        if flags:
            query.update(version=firmware, lightScriptFlags=flags)
        path = f"/models/{quote(model, safe='')}/v3.0/effectModes?{urlencode(query)}"
        health = self._health.setdefault(key, {"lastSuccess": None})
        try:
            async with self._slots, asyncio.timeout(15):
                scenes = parse_scenes(await self._get(path))
        except Exception as error:  # noqa: BLE001 - optional catalogue must not disable local lights
            health["lastErrorType"] = type(error).__name__
            _LOGGER.debug("AiDot scene catalogue refresh failed (%s)", type(error).__name__)
            return
        self._cache[key] = scenes
        health.update(lastSuccess=datetime.now(UTC).isoformat(), lastErrorType=None)

    def for_device(self, device: dict) -> dict[str, int]:
        """Return a copy so light clients cannot mutate the shared catalogue."""
        return self._cache.get(catalogue_key(device), {}).copy()

    @property
    def diagnostics(self) -> list[dict]:
        """Describe discovery without device, account or group identifiers."""
        return [
            {
                "model": key[0], "firmware": key[1],
                "scriptCapabilitiesPresent": bool(key[2]),
                "sceneCount": len(self._cache.get(key, {})), **health,
            }
            for key, health in sorted(self._health.items())
        ]

"""Helpers for reading AiDot credentials from config entries."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any

from aidot.const import CONF_COUNTRY, DEFAULT_COUNTRY_CODE, SUPPORTED_COUNTRYS
from aidot.exceptions import AidotAuthFailed

if TYPE_CHECKING:
    from aidot.client import AidotClient

_CONF_COUNTRY_CODE = "country_code"
_LEGACY_LOGIN_INFO_KEYS = ("login_info", "loginInfo")


async def async_get_devices_with_relogin(
    client: AidotClient, on_login: Callable[[], None]
) -> dict[str, Any]:
    """Recover one invalid cloud session using the saved account credentials."""
    try:
        return await client.async_get_all_device()
    except AidotAuthFailed:
        # A session can be invalidated even while the stored password is valid.
        # Retry only once; invalid credentials still enter HA's reauth flow.
        await client.async_post_login()
        on_login()
        return await client.async_get_all_device()


def get_login_data(entry_data: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return login data from either a flat or legacy nested config entry."""
    for key in _LEGACY_LOGIN_INFO_KEYS:
        nested_data = entry_data.get(key)
        if isinstance(nested_data, Mapping):
            return nested_data
    return entry_data


def get_country_code(entry_data: Mapping[str, Any]) -> str:
    """Return the stored country code, deriving it for older config entries."""
    login_data = get_login_data(entry_data)

    for data in (entry_data, login_data):
        country_code = data.get(_CONF_COUNTRY_CODE)
        if isinstance(country_code, str) and country_code:
            return country_code

    country_name = login_data.get(CONF_COUNTRY) or entry_data.get(CONF_COUNTRY)
    if isinstance(country_name, str):
        normalized_name = country_name.casefold()
        for country in SUPPORTED_COUNTRYS:
            if country["name"].casefold() == normalized_name:
                return country["id"]

    return DEFAULT_COUNTRY_CODE

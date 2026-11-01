"""Home Assistant integration for explicit rbw field reads."""

from __future__ import annotations

import hashlib
import logging
import ssl

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import RbwApiClient, RbwApiError
from .const import (
    CONF_BASE_URL,
    CONF_CA_CERT,
    CONF_CLIENT_CERT,
    CONF_CLIENT_KEY,
    DOMAIN,
    ISSUE_API_UNAVAILABLE,
    ISSUE_CLIENT_CERT,
    ISSUE_REAUTHENTICATION_REQUIRED,
)

_LOGGER = logging.getLogger(__name__)
__all__ = ["async_get_field"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Create an API client without making network calls during startup."""
    try:
        base_url = RbwApiClient.validate_base_url(entry.data[CONF_BASE_URL])
        context = RbwApiClient.create_ssl_context(
            entry.data[CONF_CA_CERT],
            entry.data[CONF_CLIENT_CERT],
            entry.data[CONF_CLIENT_KEY],
        )
    except (KeyError, ValueError, OSError, ssl.SSLError):
        base_url = entry.data.get(CONF_BASE_URL, "https://invalid.local")
        context = None
        _create_issue(hass, entry.entry_id, ISSUE_CLIENT_CERT)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = RbwApiClient(
        async_get_clientsession(hass),
        base_url,
        context,
    )
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Drop the client when its config entry unloads."""
    hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
    return True


async def async_get_field(
    hass: HomeAssistant,
    entry_id: str,
    item_id: str,
    field_id: str,
) -> dict[str, str | bool | None]:
    """Fetch one rbw field through a configured mTLS client.

    This is the integration API for other Home Assistant integrations. It
    performs a fresh request on every call, never caches the returned value,
    and raises ``HomeAssistantError`` on any denial or transport failure.
    The result includes the server's ``sensitive`` flag for caller handling.
    """
    client: RbwApiClient | None = hass.data.get(DOMAIN, {}).get(entry_id)
    if client is None:
        raise HomeAssistantError("The selected rbw config entry is not loaded")

    try:
        result = await client.async_get_field(item_id, field_id)
    except RbwApiError as err:
        _LOGGER.warning("rbw API request failed (code=%s, retryable=%s)", err.code, err.retryable)
        if err.authentication_error:
            _create_issue(hass, entry_id, ISSUE_CLIENT_CERT)
            ir.async_delete_issue(hass, DOMAIN, _request_issue_id(entry_id, item_id, field_id))
        elif err.code == ISSUE_REAUTHENTICATION_REQUIRED:
            ir.async_delete_issue(hass, DOMAIN, _request_issue_id(entry_id, item_id, field_id))
            _create_issue(
                hass,
                entry_id,
                ISSUE_REAUTHENTICATION_REQUIRED,
                issue_id=_request_issue_id(
                    entry_id, item_id, field_id, ISSUE_REAUTHENTICATION_REQUIRED
                ),
                request={"item_id": item_id, "field_id": field_id},
            )
        elif err.retryable:
            _create_issue(
                hass,
                entry_id,
                ISSUE_API_UNAVAILABLE,
                issue_id=_request_issue_id(entry_id, item_id, field_id),
                request={"item_id": item_id, "field_id": field_id},
            )
        else:
            # Denials and missing fields are request-specific. Surface them to
            # the caller; changing the integration connection cannot fix them.
            ir.async_delete_issue(hass, DOMAIN, _request_issue_id(entry_id, item_id, field_id))
            ir.async_delete_issue(
                hass,
                DOMAIN,
                _request_issue_id(entry_id, item_id, field_id, ISSUE_REAUTHENTICATION_REQUIRED),
            )
        raise HomeAssistantError(f"rbw request failed ({err.code})") from None

    ir.async_delete_issue(hass, DOMAIN, _request_issue_id(entry_id, item_id, field_id))
    ir.async_delete_issue(
        hass,
        DOMAIN,
        _request_issue_id(entry_id, item_id, field_id, ISSUE_REAUTHENTICATION_REQUIRED),
    )
    ir.async_delete_issue(hass, DOMAIN, _issue_id(entry_id, ISSUE_CLIENT_CERT))
    return result


def _issue_id(entry_id: str, issue: str) -> str:
    return f"{issue}_{entry_id}"


def _request_issue_id(
    entry_id: str,
    item_id: str,
    field_id: str,
    issue: str = ISSUE_API_UNAVAILABLE,
) -> str:
    request_key = hashlib.sha256(f"{item_id}\0{field_id}".encode()).hexdigest()[:12]
    return f"{_issue_id(entry_id, issue)}_{request_key}"


def _create_issue(
    hass: HomeAssistant,
    entry_id: str,
    issue: str,
    *,
    issue_id: str | None = None,
    request: dict[str, str] | None = None,
) -> None:
    """Create a persistent repair issue without including secret values."""
    ir.async_create_issue(
        hass,
        DOMAIN,
        issue_id or _issue_id(entry_id, issue),
        is_fixable=True,
        is_persistent=True,
        severity=ir.IssueSeverity.ERROR,
        translation_key=issue,
        data={"entry_id": entry_id, **(request or {})},
    )

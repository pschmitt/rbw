"""Config flow for the rbw integration."""

from __future__ import annotations

import ssl
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResult

from .api import RbwApiClient
from .const import (
    CONF_BASE_URL,
    CONF_CA_CERT,
    CONF_CLIENT_CERT,
    CONF_CLIENT_KEY,
    DOMAIN,
)


def _schema(data: dict[str, Any] | None = None) -> vol.Schema:
    """Build the form schema for API connection details."""
    data = data or {}
    return vol.Schema(
        {
            vol.Required(CONF_BASE_URL, default=data.get(CONF_BASE_URL, "")): str,
            vol.Required(CONF_CA_CERT, default=data.get(CONF_CA_CERT, "")): str,
            vol.Required(CONF_CLIENT_CERT, default=data.get(CONF_CLIENT_CERT, "")): str,
            vol.Required(CONF_CLIENT_KEY, default=data.get(CONF_CLIENT_KEY, "")): str,
        }
    )


def _validate_input(user_input: dict[str, Any]) -> dict[str, str]:
    """Validate the HTTPS URL and local certificate/key files."""
    values = {
        CONF_BASE_URL: RbwApiClient.validate_base_url(user_input[CONF_BASE_URL]),
        CONF_CA_CERT: user_input[CONF_CA_CERT].strip(),
        CONF_CLIENT_CERT: user_input[CONF_CLIENT_CERT].strip(),
        CONF_CLIENT_KEY: user_input[CONF_CLIENT_KEY].strip(),
    }
    RbwApiClient.create_ssl_context(
        values[CONF_CA_CERT], values[CONF_CLIENT_CERT], values[CONF_CLIENT_KEY]
    )
    return values


class RbwConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Set up an mTLS connection to rbw."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Collect the API endpoint and paths to provisioned PEM files."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                validated = _validate_input(user_input)
            except (ValueError, OSError, ssl.SSLError):
                errors["base"] = "invalid_connection"
            else:
                await self.async_set_unique_id(validated[CONF_BASE_URL])
                self._abort_if_unique_id_configured()
                return self.async_create_entry(title="rbw", data=validated)

        return self.async_show_form(step_id="user", data_schema=_schema(user_input), errors=errors)

    async def async_step_reconfigure(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Update endpoint or certificate paths from a repair flow."""
        entry = self._get_reconfigure_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                validated = _validate_input(user_input)
            except (ValueError, OSError, ssl.SSLError):
                errors["base"] = "invalid_connection"
            else:
                return self.async_update_reload_and_abort(entry, data_updates=validated)

        return self.async_show_form(
            step_id="reconfigure",
            data_schema=_schema({**entry.data, **(user_input or {})}),
            errors=errors,
        )

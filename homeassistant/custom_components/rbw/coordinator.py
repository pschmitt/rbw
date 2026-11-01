"""Polling and safe status tracking for the rbw API device."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .api import RbwApiClient, RbwApiError, RbwApiStatus
from .const import (
    DOMAIN,
    ISSUE_CLIENT_CERT,
    ISSUE_STATUS_PERMISSION,
    ISSUE_STATUS_UNAVAILABLE,
)

_LOGGER = logging.getLogger(__name__)
STATUS_UPDATE_INTERVAL = timedelta(seconds=60)


@dataclass(frozen=True, slots=True)
class RbwStatusData:
    """A poll result with no item fields, account names, or credentials."""

    connected: bool
    status: RbwApiStatus | None = None
    error_code: str | None = None

    @property
    def vault_status(self) -> str:
        """Return the vault state or a clear reason it is not known."""
        if self.status is not None:
            return self.status.vault_state
        if self.error_code == ISSUE_STATUS_PERMISSION:
            return "status_permission_required"
        if self.error_code == ISSUE_CLIENT_CERT:
            return "authentication_failed"
        return "unavailable"

    @property
    def vault_locked(self) -> bool | None:
        """Return lock state only when the server could confirm it."""
        if self.status is None or self.status.vault_state == "unconfigured":
            return None
        return self.status.vault_state == "locked"


class RbwStatusCoordinator(DataUpdateCoordinator[RbwStatusData]):
    """Poll the non-secret API status endpoint at a bounded interval."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        client: RbwApiClient,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=f"{DOMAIN} status {entry.entry_id}",
            update_interval=STATUS_UPDATE_INTERVAL,
            always_update=False,
        )
        self.entry = entry
        self.client = client

    async def _async_update_data(self) -> RbwStatusData:
        """Fetch only API version, agent version, and scoped lock state."""
        try:
            status = await self.client.async_get_status()
        except RbwApiError as err:
            _LOGGER.debug(
                "rbw status check failed (code=%s, http_status=%s)",
                err.code,
                err.http_status,
            )
            if err.authentication_error:
                _create_status_issue(
                    self.hass, self.entry.entry_id, ISSUE_CLIENT_CERT, is_fixable=True
                )
                ir.async_delete_issue(
                    self.hass, DOMAIN, _issue_id(self.entry.entry_id, ISSUE_STATUS_PERMISSION)
                )
                ir.async_delete_issue(
                    self.hass, DOMAIN, _issue_id(self.entry.entry_id, ISSUE_STATUS_UNAVAILABLE)
                )
            elif err.http_status == 403:
                _create_status_issue(self.hass, self.entry.entry_id, ISSUE_STATUS_PERMISSION)
                ir.async_delete_issue(
                    self.hass, DOMAIN, _issue_id(self.entry.entry_id, ISSUE_STATUS_UNAVAILABLE)
                )
                ir.async_delete_issue(
                    self.hass, DOMAIN, _issue_id(self.entry.entry_id, ISSUE_CLIENT_CERT)
                )
            elif err.retryable or err.http_status is not None:
                _create_status_issue(self.hass, self.entry.entry_id, ISSUE_STATUS_UNAVAILABLE)
                ir.async_delete_issue(
                    self.hass, DOMAIN, _issue_id(self.entry.entry_id, ISSUE_STATUS_PERMISSION)
                )
                ir.async_delete_issue(
                    self.hass, DOMAIN, _issue_id(self.entry.entry_id, ISSUE_CLIENT_CERT)
                )
            else:
                ir.async_delete_issue(
                    self.hass, DOMAIN, _issue_id(self.entry.entry_id, ISSUE_STATUS_PERMISSION)
                )
                ir.async_delete_issue(
                    self.hass, DOMAIN, _issue_id(self.entry.entry_id, ISSUE_STATUS_UNAVAILABLE)
                )
                ir.async_delete_issue(
                    self.hass, DOMAIN, _issue_id(self.entry.entry_id, ISSUE_CLIENT_CERT)
                )
            return RbwStatusData(
                connected=err.http_status is not None,
                error_code=(
                    ISSUE_STATUS_PERMISSION
                    if err.http_status == 403
                    else ISSUE_CLIENT_CERT
                    if err.authentication_error
                    else err.code
                ),
            )

        ir.async_delete_issue(
            self.hass, DOMAIN, _issue_id(self.entry.entry_id, ISSUE_STATUS_PERMISSION)
        )
        ir.async_delete_issue(
            self.hass, DOMAIN, _issue_id(self.entry.entry_id, ISSUE_STATUS_UNAVAILABLE)
        )
        ir.async_delete_issue(self.hass, DOMAIN, _issue_id(self.entry.entry_id, ISSUE_CLIENT_CERT))
        return RbwStatusData(connected=True, status=status)


def _issue_id(entry_id: str, issue: str) -> str:
    return f"{issue}_{entry_id}"


def _create_status_issue(
    hass: HomeAssistant,
    entry_id: str,
    issue: str,
    *,
    is_fixable: bool = False,
) -> None:
    """Create a repair issue that contains no endpoint or credential values."""
    ir.async_create_issue(
        hass,
        DOMAIN,
        _issue_id(entry_id, issue),
        is_fixable=is_fixable,
        is_persistent=True,
        severity=ir.IssueSeverity.WARNING,
        translation_key=issue,
        data={"entry_id": entry_id},
    )

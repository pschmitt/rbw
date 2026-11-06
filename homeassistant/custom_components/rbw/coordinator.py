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
    DEFAULT_ACCOUNT,
    DOMAIN,
    ISSUE_CLIENT_CERT,
    ISSUE_DEFAULT_ACCOUNT_LOCKED,
    ISSUE_STATUS_PERMISSION,
    ISSUE_STATUS_UNAVAILABLE,
)

_LOGGER = logging.getLogger(__name__)
STATUS_UPDATE_INTERVAL = timedelta(seconds=60)


@dataclass(frozen=True, slots=True)
class RbwStatusData:
    """A poll result with only explicitly granted account lock states."""

    connected: bool
    status: RbwApiStatus | None = None
    error_code: str | None = None

    def account_status(self, account: str) -> str:
        """Return an account state or a safe reason it is unknown."""
        if self.status is not None:
            for account_status in self.status.accounts:
                if account_status.account == account:
                    return account_status.state
            return "unavailable"
        if self.error_code == ISSUE_STATUS_PERMISSION:
            return "status_permission_required"
        if self.error_code == ISSUE_CLIENT_CERT:
            return "authentication_failed"
        return "unavailable"

    def account_locked(self, account: str) -> bool | None:
        """Return lock state only when the server could confirm it."""
        state = self.account_status(account)
        if state not in ("locked", "unlocked"):
            return None
        return state == "locked"


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
        """Fetch only API version, agent version, and granted lock states."""
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
        if any(
            account.account == DEFAULT_ACCOUNT and account.state == "locked"
            for account in status.accounts
        ):
            _create_status_issue(
                self.hass,
                self.entry.entry_id,
                ISSUE_DEFAULT_ACCOUNT_LOCKED,
                is_fixable=True,
                data={"entry_id": self.entry.entry_id, "account": DEFAULT_ACCOUNT},
            )
        else:
            ir.async_delete_issue(
                self.hass, DOMAIN, _issue_id(self.entry.entry_id, ISSUE_DEFAULT_ACCOUNT_LOCKED)
            )
        return RbwStatusData(connected=True, status=status)


def _issue_id(entry_id: str, issue: str) -> str:
    return f"{issue}_{entry_id}"


def _create_status_issue(
    hass: HomeAssistant,
    entry_id: str,
    issue: str,
    *,
    is_fixable: bool = False,
    data: dict[str, str] | None = None,
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
        data=data or {"entry_id": entry_id},
    )

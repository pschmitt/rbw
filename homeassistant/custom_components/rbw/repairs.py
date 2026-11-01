"""Repair flows for rbw API failures."""

from __future__ import annotations

import hashlib
from typing import Any

import voluptuous as vol
from homeassistant.components.repairs import FlowType, RepairsFlow
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers import issue_registry as ir

from .api import RbwApiError
from .const import (
    DOMAIN,
    ISSUE_API_UNAVAILABLE,
    ISSUE_CLIENT_CERT,
    ISSUE_REAUTHENTICATION_REQUIRED,
)


class RbwRepairFlow(RepairsFlow):
    """Retry a failed request or reconfigure the mTLS client."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Offer a request retry or certificate reconfiguration."""
        if self.issue_id.startswith(f"{ISSUE_CLIENT_CERT}_"):
            return self.async_show_menu(step_id="init", menu_options=["reconfigure"])
        if self.issue_id.startswith(f"{ISSUE_REAUTHENTICATION_REQUIRED}_"):
            return self.async_show_menu(step_id="init", menu_options=["manual_action"])
        return self.async_show_menu(step_id="init", menu_options=["retry", "reconfigure"])

    async def async_step_reconfigure(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Start the integration's reconfigure flow."""
        entry_id = self.data.get("entry_id")
        if not entry_id or not self.hass.config_entries.async_get_entry(entry_id):
            return self.async_abort(reason="entry_not_found")
        result = await self.hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": "reconfigure", "entry_id": entry_id},
        )
        return self.async_abort(
            reason="reconfigure_started",
            next_flow=(FlowType.CONFIG_FLOW, result["flow_id"]),
        )

    async def async_step_retry(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        """Retry the exact request and discard its value if it succeeds."""
        entry_id = self.data.get("entry_id")
        item_id = self.data.get("item_id")
        field_id = self.data.get("field_id")
        if not entry_id or not item_id or not field_id:
            return self.async_abort(reason="request_not_available")

        if user_input is not None:
            runtime = self.hass.data.get(DOMAIN, {}).get(entry_id)
            client = getattr(runtime, "client", runtime)
            if client is None:
                return self.async_show_form(
                    step_id="retry",
                    data_schema=vol.Schema({}),
                    errors={"base": "integration_unavailable"},
                )
            try:
                await client.async_get_field(item_id, field_id)
            except RbwApiError as err:
                if err.code == ISSUE_REAUTHENTICATION_REQUIRED:
                    ir.async_delete_issue(self.hass, DOMAIN, self.issue_id)
                    self._create_request_issue(
                        entry_id,
                        item_id,
                        field_id,
                        ISSUE_REAUTHENTICATION_REQUIRED,
                    )
                    return self.async_abort(reason="reauthentication_required")
                if err.authentication_error:
                    ir.async_delete_issue(self.hass, DOMAIN, self.issue_id)
                    ir.async_create_issue(
                        self.hass,
                        DOMAIN,
                        f"{ISSUE_CLIENT_CERT}_{entry_id}",
                        is_fixable=True,
                        is_persistent=True,
                        severity=ir.IssueSeverity.ERROR,
                        translation_key=ISSUE_CLIENT_CERT,
                        data={"entry_id": entry_id},
                    )
                    return self.async_abort(reason="credentials_need_update")
                if not err.retryable:
                    ir.async_delete_issue(self.hass, DOMAIN, self.issue_id)
                    return self.async_abort(reason="request_not_retryable")
                if self.issue_id.startswith(f"{ISSUE_REAUTHENTICATION_REQUIRED}_"):
                    ir.async_delete_issue(self.hass, DOMAIN, self.issue_id)
                    self._create_request_issue(entry_id, item_id, field_id, ISSUE_API_UNAVAILABLE)
                return self.async_show_form(
                    step_id="retry",
                    data_schema=vol.Schema({}),
                    errors={"base": "still_unavailable"},
                )

            ir.async_delete_issue(self.hass, DOMAIN, self.issue_id)
            return self.async_create_entry(title="", data={})

        return self.async_show_form(step_id="retry", data_schema=vol.Schema({}))

    async def async_step_manual_action(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Retry after the user handled the interactive-reprompt policy."""
        if user_input is None:
            return self.async_show_form(step_id="manual_action", data_schema=vol.Schema({}))
        return await self.async_step_retry(user_input)

    def _create_request_issue(
        self,
        entry_id: str,
        item_id: str,
        field_id: str,
        issue: str,
    ) -> None:
        """Replace a request-specific issue without persisting field values."""
        request_hash = hashlib.sha256(f"{item_id}\0{field_id}".encode()).hexdigest()[:12]
        ir.async_create_issue(
            self.hass,
            DOMAIN,
            f"{issue}_{entry_id}_{request_hash}",
            is_fixable=True,
            is_persistent=True,
            severity=ir.IssueSeverity.ERROR,
            translation_key=issue,
            data={"entry_id": entry_id, "item_id": item_id, "field_id": field_id},
        )


async def async_create_fix_flow(
    hass: HomeAssistant,
    issue_id: str,
    data: dict[str, Any] | None,
) -> RepairsFlow:
    """Create a repair flow for an rbw issue."""
    return RbwRepairFlow()

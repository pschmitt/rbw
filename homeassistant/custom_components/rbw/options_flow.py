"""Choose which integrations may read which vault items."""

from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant.config_entries import OptionsFlow
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.selector import (
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
)
from homeassistant.loader import async_get_integrations

from .access import configured_items, request_issue_id, with_items
from .api import RbwApiError
from .const import CONF_ACCESS, DOMAIN

CONF_ADD_INTEGRATION = "add_integration"


class RbwOptionsFlow(OptionsFlow):
    """One form: a row of allowed items per integration. An empty row means no access."""

    def __init__(self) -> None:
        self._rows: dict[str, list[str]] | None = None

    def _access(self) -> dict[str, list[str]]:
        return self.config_entry.options.get(CONF_ACCESS, {})

    async def _names(self, domains: set[str]) -> dict[str, str]:
        """Integration names, which also label the rows: the names are not translatable keys."""
        found = await async_get_integrations(self.hass, domains)
        names = {
            domain: integration.name if not isinstance(integration, Exception) else domain
            for domain, integration in found.items()
        }
        # Two integrations could share a name, and a row needs a unique label.
        return {
            domain: name if list(names.values()).count(name) == 1 else f"{name} ({domain})"
            for domain, name in names.items()
        }

    async def _granted_items(self) -> dict[str, str]:
        """Item IDs and readable labels of what the rbw API grants this client."""
        runtime = self.hass.data.get(DOMAIN, {}).get(self.config_entry.entry_id)
        try:
            items = await runtime.client.async_list_items()
        except (AttributeError, RbwApiError):
            return {}  # IDs can still be entered: the form keeps working.
        return {item["id"]: item["name"] or item["id"] for item in items}

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        configured = configured_items(
            self.hass.config_entries.async_entries(), self.config_entry.entry_id
        )
        if self._rows is None:
            self._rows = {domain: [] for domain in configured} | {
                domain: list(items) for domain, items in self._access().items()
            }
        installed = {entry.domain for entry in self.hass.config_entries.async_entries()} - {DOMAIN}
        names = await self._names({*installed, *self._rows})
        if user_input is not None:
            self._rows = {domain: user_input.get(names[domain], []) for domain in self._rows}
            if added := user_input.get(CONF_ADD_INTEGRATION):
                self._rows.setdefault(added, [])
            else:
                return self._save()

        known = {item: item for items in self._rows.values() for item in items}
        known.update(await self._granted_items())
        item_options = [
            {"value": item, "label": label}
            for item, label in sorted(known.items(), key=lambda pair: pair[1].lower())
        ]
        rows = {
            vol.Optional(names[domain], description={"suggested_value": items}): SelectSelector(
                SelectSelectorConfig(
                    options=item_options,
                    multiple=True,
                    custom_value=True,
                    mode=SelectSelectorMode.DROPDOWN,
                )
            )
            for domain, items in sorted(self._rows.items(), key=lambda row: names[row[0]].lower())
        }
        addable = [
            {"value": domain, "label": names[domain]}
            for domain in sorted(installed - set(self._rows), key=lambda d: names[d].lower())
        ]
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    **rows,
                    vol.Optional(CONF_ADD_INTEGRATION): SelectSelector(
                        SelectSelectorConfig(options=addable, mode=SelectSelectorMode.DROPDOWN)
                    ),
                }
            ),
        )

    def _save(self) -> FlowResult:
        options = dict(self.config_entry.options)
        for domain, items in (self._rows or {}).items():
            for item in items:
                ir.async_delete_issue(
                    self.hass,
                    DOMAIN,
                    request_issue_id(self.config_entry.entry_id, domain, item),
                )
            options = with_items(options, domain, items)
        return self.async_create_entry(title="", data=options)

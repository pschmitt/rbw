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

from .access import configured_items, request_issue_id, with_items
from .const import CONF_ACCESS, DOMAIN

CONF_INTEGRATION = "integration"
CONF_ITEMS = "items"


class RbwOptionsFlow(OptionsFlow):
    """Pick an integration, then the items it may read. No items means no access."""

    def __init__(self) -> None:
        self._domain = ""

    def _access(self) -> dict[str, list[str]]:
        return self.config_entry.options.get(CONF_ACCESS, {})

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        if user_input is not None:
            self._domain = user_input[CONF_INTEGRATION]
            return await self.async_step_items()
        entries = self.hass.config_entries.async_entries()
        titles: dict[str, str] = {}
        for entry in entries:
            if entry.domain != DOMAIN:
                titles.setdefault(entry.domain, entry.title)
        options = [
            {"value": domain, "label": f"{titles.get(domain, domain)} ({domain})"}
            for domain in sorted({*titles, *self._access()})
        ]
        allowed = ", ".join(f"{domain}: {len(items)}" for domain, items in self._access().items())
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_INTEGRATION): SelectSelector(
                        SelectSelectorConfig(options=options, mode=SelectSelectorMode.DROPDOWN)
                    )
                }
            ),
            description_placeholders={"allowed": allowed or "-"},
        )

    async def async_step_items(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        if user_input is not None:
            items = user_input.get(CONF_ITEMS, [])
            for item in items:
                ir.async_delete_issue(
                    self.hass,
                    DOMAIN,
                    request_issue_id(self.config_entry.entry_id, self._domain, item),
                )
            return self.async_create_entry(
                title="", data=with_items(self.config_entry.options, self._domain, items)
            )
        configured = configured_items(
            self.hass.config_entries.async_entries(), self.config_entry.entry_id
        )
        known = {item for items in self._access().values() for item in items}
        known.update(item for items in configured.values() for item in items)
        current = self._access().get(self._domain, [])
        return self.async_show_form(
            step_id="items",
            data_schema=vol.Schema(
                {
                    vol.Optional(CONF_ITEMS, default=current): SelectSelector(
                        SelectSelectorConfig(
                            options=sorted(known),
                            multiple=True,
                            custom_value=True,
                            mode=SelectSelectorMode.DROPDOWN,
                        )
                    )
                }
            ),
            description_placeholders={"integration": self._domain},
        )

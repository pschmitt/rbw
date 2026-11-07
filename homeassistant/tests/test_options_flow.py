"""Tests for the integration access form, on real Home Assistant when it is installed."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

try:
    from homeassistant.loader import async_get_integrations as _real_home_assistant
except ImportError:  # CI runs without it, and other test modules install stubs.
    _real_home_assistant = None


@unittest.skipUnless(_real_home_assistant, "needs Home Assistant")
class OptionsFlowTests(unittest.IsolatedAsyncioTestCase):
    def flow(self, access: dict[str, list[str]], consumers: dict[str, str]):
        from custom_components.rbw.options_flow import RbwOptionsFlow

        flow = RbwOptionsFlow()
        entry = SimpleNamespace(entry_id="rbw-entry", options={"access": access})
        flow.handler = "rbw-entry"
        flow.hass = MagicMock()
        flow.hass.config_entries.async_get_known_entry.return_value = entry
        flow.hass.config_entries.async_entries.return_value = [
            SimpleNamespace(
                domain=domain,
                data={"rbw_entry_id": "rbw-entry", "rbw_item_id": item} if item else {},
                options={},
            )
            for domain, item in consumers.items()
        ]
        client = SimpleNamespace(
            async_list_items=AsyncMock(
                return_value=[{"id": "item-1", "name": "Work login", "fields": []}]
            )
        )
        flow.hass.data = {"rbw": {"rbw-entry": SimpleNamespace(client=client)}}
        return flow

    @staticmethod
    def integrations(domains: set[str]) -> dict[str, object]:
        names = {"hrworks": "HR WORKS", "msteams": "Microsoft Teams", "aarlo": "Aarlo"}
        return {domain: SimpleNamespace(name=names.get(domain, domain)) for domain in domains}

    async def run_step(self, flow, user_input=None):
        async def found(_hass, domains):
            return self.integrations(set(domains))

        with (
            patch("custom_components.rbw.options_flow.async_get_integrations", found),
            patch("custom_components.rbw.options_flow.ir"),
        ):
            return await flow.async_step_init(user_input)

    async def test_one_form_has_a_row_per_integration_with_names(self):
        flow = self.flow({"hrworks": ["item-1"]}, {"hrworks": "item-1", "msteams": "", "aarlo": ""})
        form = await self.run_step(flow)
        self.assertEqual(form["step_id"], "init")
        keys = {str(key): key for key in form["data_schema"].schema}
        self.assertEqual(list(keys), ["HR WORKS", "add_integration"])
        self.assertEqual(keys["HR WORKS"].description, {"suggested_value": ["item-1"]})
        row = form["data_schema"].schema[keys["HR WORKS"]]
        self.assertEqual(row.config["options"], [{"value": "item-1", "label": "Work login"}])
        add = form["data_schema"].schema[keys["add_integration"]]
        self.assertEqual([o["label"] for o in add.config["options"]], ["Aarlo", "Microsoft Teams"])

    async def test_adding_keeps_the_form_open_and_saves_nothing_yet(self):
        flow = self.flow({"hrworks": ["item-1"]}, {"hrworks": "item-1", "msteams": ""})
        form = await self.run_step(flow, {"HR WORKS": ["item-1"], "add_integration": "msteams"})
        self.assertEqual(form["type"], "form")
        self.assertEqual(
            [str(key) for key in form["data_schema"].schema],
            ["HR WORKS", "Microsoft Teams", "add_integration"],
        )

    async def test_saving_applies_rows_and_an_empty_row_revokes(self):
        flow = self.flow(
            {"hrworks": ["item-1"], "msteams": ["item-1"]},
            {"hrworks": "item-1", "msteams": "item-1"},
        )
        result = await self.run_step(flow, {"HR WORKS": ["item-1"], "Microsoft Teams": []})
        self.assertEqual(result["type"], "create_entry")
        self.assertEqual(result["data"]["access"], {"hrworks": ["item-1"]})

    async def test_an_unconfigured_row_starts_empty(self):
        flow = self.flow({}, {"hrworks": "item-1"})
        form = await self.run_step(flow)
        keys = {str(key): key for key in form["data_schema"].schema}
        self.assertEqual(keys["HR WORKS"].description, {"suggested_value": []})

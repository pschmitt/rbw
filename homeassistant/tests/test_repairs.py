"""Tests for the rbw repair retry flow without booting Home Assistant."""

from __future__ import annotations

import importlib.util
import sys
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).parents[1] / "custom_components" / "rbw"
API_SPEC = importlib.util.spec_from_file_location("rbw_test_repair_api", ROOT / "api.py")
assert API_SPEC and API_SPEC.loader
api = importlib.util.module_from_spec(API_SPEC)
API_SPEC.loader.exec_module(api)


class FakeRepairsFlow:
    def async_show_form(
        self, *, step_id: str, data_schema: object, errors: dict[str, str] | None = None
    ):
        return {"type": "form", "step_id": step_id, "errors": errors or {}}

    def async_abort(self, *, reason: str):
        return {"type": "abort", "reason": reason}

    def async_create_entry(self, *, title: str, data: dict[str, object]):
        return {"type": "create_entry", "title": title, "data": data}

    def async_show_menu(self, *, step_id: str, menu_options: list[str]):
        return {"type": "menu", "step_id": step_id, "options": menu_options}


class FakeClient:
    def __init__(self, result: dict[str, object] | Exception) -> None:
        self.result = result
        self.requests: list[tuple[str, str]] = []

    async def async_get_field(self, item_id: str, field_id: str) -> dict[str, object]:
        self.requests.append((item_id, field_id))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def load_repair_module(issue_calls: list[tuple[object, ...]]) -> types.ModuleType:
    """Load repairs.py with a minimal fake Home Assistant API surface."""
    root_package = types.ModuleType("rbw_repair_test")
    root_package.__path__ = [str(ROOT)]
    const = types.ModuleType("rbw_repair_test.const")
    const.DOMAIN = "rbw"
    const.ISSUE_API_UNAVAILABLE = "api_unavailable"
    const.ISSUE_CLIENT_CERT = "client_certificate"
    const.ISSUE_REAUTHENTICATION_REQUIRED = "reauthentication_required"

    repairs_base = types.ModuleType("homeassistant.components.repairs")
    repairs_base.RepairsFlow = FakeRepairsFlow
    core = types.ModuleType("homeassistant.core")
    core.HomeAssistant = object
    data_entry_flow = types.ModuleType("homeassistant.data_entry_flow")
    data_entry_flow.FlowResult = dict
    issue_registry = types.ModuleType("homeassistant.helpers.issue_registry")
    issue_registry.IssueSeverity = SimpleNamespace(ERROR="error")
    issue_registry.async_delete_issue = lambda *args: issue_calls.append(("delete", *args))
    issue_registry.async_create_issue = lambda *args, **kwargs: issue_calls.append(
        ("create", *args, kwargs)
    )

    modules = {
        "rbw_repair_test": root_package,
        "rbw_repair_test.api": api,
        "rbw_repair_test.const": const,
        "homeassistant": types.ModuleType("homeassistant"),
        "homeassistant.components": types.ModuleType("homeassistant.components"),
        "homeassistant.components.repairs": repairs_base,
        "homeassistant.core": core,
        "homeassistant.data_entry_flow": data_entry_flow,
        "homeassistant.helpers": types.ModuleType("homeassistant.helpers"),
        "homeassistant.helpers.issue_registry": issue_registry,
    }
    spec = importlib.util.spec_from_file_location("rbw_repair_test.repairs", ROOT / "repairs.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, modules):
        spec.loader.exec_module(module)
    return module


class RepairRetryTests(unittest.IsolatedAsyncioTestCase):
    async def test_retry_success_discards_secret_and_clears_issue(self) -> None:
        issue_calls: list[tuple[object, ...]] = []
        repairs = load_repair_module(issue_calls)
        secret = "test-only-vault-value"
        client = FakeClient({"field": "password", "value": secret, "sensitive": True})
        hass = SimpleNamespace(data={"rbw": {"entry": client}})
        flow = repairs.RbwRepairFlow(
            "api_unavailable_entry_hash",
            {"entry_id": "entry", "item_id": "item", "field_id": "password"},
        )
        flow.hass = hass

        result = await flow.async_step_retry({})

        self.assertEqual(result, {"type": "create_entry", "title": "", "data": {}})
        self.assertEqual(client.requests, [("item", "password")])
        self.assertEqual(issue_calls[0][0], "delete")
        self.assertNotIn(secret, repr(result))
        self.assertNotIn(secret, repr(flow.data))

    async def test_retryable_failure_keeps_issue_and_shows_safe_error(self) -> None:
        issue_calls: list[tuple[object, ...]] = []
        repairs = load_repair_module(issue_calls)
        client = FakeClient(api.RbwApiError("vault_locked", "Vault is locked", retryable=True))
        hass = SimpleNamespace(data={"rbw": {"entry": client}})
        flow = repairs.RbwRepairFlow(
            "api_unavailable_entry_hash",
            {"entry_id": "entry", "item_id": "item", "field_id": "totp"},
        )
        flow.hass = hass

        result = await flow.async_step_retry({})

        self.assertEqual(result["errors"], {"base": "still_unavailable"})
        self.assertEqual(issue_calls, [])
        self.assertEqual(client.requests, [("item", "totp")])

    async def test_reprompt_issue_requires_manual_action_and_is_recreated(self) -> None:
        issue_calls: list[tuple[object, ...]] = []
        repairs = load_repair_module(issue_calls)
        client = FakeClient(
            api.RbwApiError(
                "reauthentication_required",
                "Interactive unlock is required",
                retryable=False,
            )
        )
        hass = SimpleNamespace(data={"rbw": {"entry": client}})
        flow = repairs.RbwRepairFlow(
            "reauthentication_required_entry_hash",
            {"entry_id": "entry", "item_id": "item", "field_id": "password"},
        )
        flow.hass = hass

        menu = await flow.async_step_init()
        retry_form = await flow.async_step_manual_action()
        result = await flow.async_step_manual_action({})

        self.assertEqual(menu["options"], ["manual_action"])
        self.assertEqual(retry_form["step_id"], "manual_action")
        self.assertEqual(result["reason"], "reauthentication_required")
        self.assertEqual(issue_calls[0][0], "delete")
        self.assertEqual(issue_calls[1][0], "create")
        self.assertEqual(issue_calls[1][4]["translation_key"], "reauthentication_required")
        self.assertEqual(client.requests, [("item", "password")])

    async def test_transient_repair_becomes_manual_reprompt_issue(self) -> None:
        issue_calls: list[tuple[object, ...]] = []
        repairs = load_repair_module(issue_calls)
        client = FakeClient(
            api.RbwApiError(
                "reauthentication_required",
                "Interactive unlock is required",
                retryable=False,
            )
        )
        hass = SimpleNamespace(data={"rbw": {"entry": client}})
        flow = repairs.RbwRepairFlow(
            "api_unavailable_entry_hash",
            {"entry_id": "entry", "item_id": "item", "field_id": "password"},
        )
        flow.hass = hass

        result = await flow.async_step_retry({})

        self.assertEqual(result, {"type": "abort", "reason": "reauthentication_required"})
        self.assertEqual(issue_calls[0][0], "delete")
        self.assertEqual(issue_calls[1][0], "create")
        self.assertEqual(issue_calls[1][4]["translation_key"], "reauthentication_required")
        self.assertEqual(client.requests, [("item", "password")])


if __name__ == "__main__":
    unittest.main()

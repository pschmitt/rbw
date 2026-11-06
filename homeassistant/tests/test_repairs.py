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
sys.modules[API_SPEC.name] = api
API_SPEC.loader.exec_module(api)


class FakeRepairsFlow:
    def async_show_form(
        self, *, step_id: str, data_schema: object, errors: dict[str, str] | None = None
    ):
        return {"type": "form", "step_id": step_id, "errors": errors or {}}

    def async_abort(self, *, reason: str, next_flow: object | None = None):
        result = {"type": "abort", "reason": reason}
        if next_flow is not None:
            result["next_flow"] = next_flow
        return result

    def async_create_entry(self, *, title: str, data: dict[str, object]):
        return {"type": "create_entry", "title": title, "data": data}

    def async_show_menu(self, *, step_id: str, menu_options: list[str]):
        return {"type": "menu", "step_id": step_id, "options": menu_options}


class FakeClient:
    def __init__(self, result: dict[str, object] | Exception) -> None:
        self.result = result
        self.requests: list[tuple[str, str]] = []
        self.unlock_requests: list[tuple[str, str, str | None]] = []

    async def async_get_field(self, item_id: str, field_id: str) -> dict[str, object]:
        self.requests.append((item_id, field_id))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result

    async def async_unlock(
        self,
        password: str,
        *,
        account: str = "default",
        consumer: str | None = None,
    ) -> object:
        self.unlock_requests.append((account, password, consumer))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def load_repair_module(issue_calls: list[tuple[object, ...]]) -> types.ModuleType:
    """Load repairs.py with a minimal fake Home Assistant API surface."""
    root_package = types.ModuleType("rbw_repair_test")
    root_package.__path__ = [str(ROOT)]
    const = types.ModuleType("rbw_repair_test.const")
    const.DEFAULT_ACCOUNT = "default"
    const.DOMAIN = "rbw"
    const.ISSUE_API_UNAVAILABLE = "api_unavailable"
    const.ISSUE_CLIENT_CERT = "client_certificate"
    const.ISSUE_DEFAULT_ACCOUNT_LOCKED = "default_account_locked"
    const.ISSUE_REAUTHENTICATION_REQUIRED = "reauthentication_required"

    repairs_base = types.ModuleType("homeassistant.components.repairs")
    repairs_base.RepairsFlow = FakeRepairsFlow
    repairs_base.FlowType = SimpleNamespace(CONFIG_FLOW="config_flow")
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
    async def test_reconfigure_hands_off_to_config_flow(self) -> None:
        issue_calls: list[tuple[object, ...]] = []
        repairs = load_repair_module(issue_calls)

        class FlowManager:
            async def async_init(self, domain: str, *, context: dict[str, str]):
                self.domain = domain
                self.context = context
                return {"flow_id": "reconfigure-flow"}

        entry = object()
        flow_manager = FlowManager()
        hass = SimpleNamespace(
            data={},
            config_entries=SimpleNamespace(
                async_get_entry=lambda entry_id: entry if entry_id == "entry" else None,
                flow=flow_manager,
            ),
        )
        flow = repairs.RbwRepairFlow()
        flow.data = {"entry_id": "entry"}
        flow.hass = hass

        result = await flow.async_step_reconfigure()

        self.assertEqual(
            result,
            {
                "type": "abort",
                "reason": "reconfigure_started",
                "next_flow": ("config_flow", "reconfigure-flow"),
            },
        )
        self.assertEqual(flow_manager.domain, "rbw")
        self.assertEqual(
            flow_manager.context,
            {"source": "reconfigure", "entry_id": "entry"},
        )

    async def test_retry_success_discards_secret_and_clears_issue(self) -> None:
        issue_calls: list[tuple[object, ...]] = []
        repairs = load_repair_module(issue_calls)
        secret = "test-only-vault-value"
        client = FakeClient({"field": "password", "value": secret, "sensitive": True})
        hass = SimpleNamespace(data={"rbw": {"entry": client}})
        flow = repairs.RbwRepairFlow()
        flow.issue_id = "api_unavailable_entry_hash"
        flow.data = {"entry_id": "entry", "item_id": "item", "field_id": "password"}
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
        flow = repairs.RbwRepairFlow()
        flow.issue_id = "api_unavailable_entry_hash"
        flow.data = {"entry_id": "entry", "item_id": "item", "field_id": "totp"}
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
        flow = repairs.RbwRepairFlow()
        flow.issue_id = "reauthentication_required_entry_hash"
        flow.data = {"entry_id": "entry", "item_id": "item", "field_id": "password"}
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
        flow = repairs.RbwRepairFlow()
        flow.issue_id = "api_unavailable_entry_hash"
        flow.data = {"entry_id": "entry", "item_id": "item", "field_id": "password"}
        flow.hass = hass

        result = await flow.async_step_retry({})

        self.assertEqual(result, {"type": "abort", "reason": "reauthentication_required"})
        self.assertEqual(issue_calls[0][0], "delete")
        self.assertEqual(issue_calls[1][0], "create")
        self.assertEqual(issue_calls[1][4]["translation_key"], "reauthentication_required")
        self.assertEqual(client.requests, [("item", "password")])

    async def test_default_account_locked_repair_unlocks_and_refreshes_coordinator(self) -> None:
        issue_calls: list[tuple[object, ...]] = []
        repairs = load_repair_module(issue_calls)
        master_pw = "never-persist-this-password"
        client = FakeClient({"account": "default", "state": "unlocked"})
        refreshed: list[bool] = []

        async def async_refresh() -> None:
            refreshed.append(True)

        runtime = SimpleNamespace(
            client=client,
            coordinator=SimpleNamespace(async_refresh=async_refresh),
        )
        hass = SimpleNamespace(data={"rbw": {"entry": runtime}})
        flow = repairs.RbwRepairFlow()
        flow.issue_id = "default_account_locked_entry"
        flow.data = {"entry_id": "entry", "account": "default"}
        flow.hass = hass

        form = await flow.async_step_init()
        self.assertEqual(form["step_id"], "unlock")

        result = await flow.async_step_unlock({"password": master_pw})
        self.assertEqual(result, {"type": "create_entry", "title": "", "data": {}})
        self.assertEqual(
            client.unlock_requests,
            [("default", master_pw, "homeassistant.repairs")],
        )
        self.assertEqual(issue_calls, [("delete", hass, "rbw", "default_account_locked_entry")])
        self.assertEqual(refreshed, [True])
        self.assertNotIn(master_pw, repr(result))
        self.assertNotIn(master_pw, repr(flow.data))

    async def test_default_account_locked_repair_handles_invalid_password(self) -> None:
        issue_calls: list[tuple[object, ...]] = []
        repairs = load_repair_module(issue_calls)
        client = FakeClient(
            api.RbwApiError("invalid_password", "bad password", retryable=False, http_status=422)
        )
        hass = SimpleNamespace(data={"rbw": {"entry": client}})
        flow = repairs.RbwRepairFlow()
        flow.issue_id = "default_account_locked_entry"
        flow.data = {"entry_id": "entry", "account": "default"}
        flow.hass = hass

        result = await flow.async_step_unlock({"password": "wrong"})
        self.assertEqual(result["step_id"], "unlock")
        self.assertEqual(result["errors"], {"password": "invalid_password"})
        self.assertEqual(issue_calls, [])


if __name__ == "__main__":
    unittest.main()

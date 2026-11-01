"""Tests for safe and useful rbw device status handling."""

from __future__ import annotations

import importlib.util
import logging
import sys
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).parents[1] / "custom_components" / "rbw"
API_SPEC = importlib.util.spec_from_file_location("rbw_coordinator_test_api", ROOT / "api.py")
assert API_SPEC and API_SPEC.loader
api = importlib.util.module_from_spec(API_SPEC)
sys.modules[API_SPEC.name] = api
API_SPEC.loader.exec_module(api)


class FakeDataUpdateCoordinator:
    def __class_getitem__(cls, item: object) -> type[FakeDataUpdateCoordinator]:
        return cls

    def __init__(self, hass: object, logger: logging.Logger, **kwargs: object) -> None:
        self.hass = hass
        self.logger = logger
        self.kwargs = kwargs
        self.data = None


def load_coordinator(issue_calls: list[tuple[object, ...]]) -> types.ModuleType:
    """Load coordinator.py with a minimal Home Assistant API surface."""
    package = types.ModuleType("rbw_coordinator_test")
    package.__path__ = [str(ROOT)]
    const = types.ModuleType("rbw_coordinator_test.const")
    for name, value in {
        "DOMAIN": "rbw",
        "ISSUE_CLIENT_CERT": "client_certificate",
        "ISSUE_STATUS_PERMISSION": "status_permission_required",
        "ISSUE_STATUS_UNAVAILABLE": "status_unavailable",
    }.items():
        setattr(const, name, value)

    config_entries = types.ModuleType("homeassistant.config_entries")
    config_entries.ConfigEntry = object
    core = types.ModuleType("homeassistant.core")
    core.HomeAssistant = object
    issue_registry = types.ModuleType("homeassistant.helpers.issue_registry")
    issue_registry.IssueSeverity = SimpleNamespace(WARNING="warning")
    issue_registry.async_create_issue = lambda *args, **kwargs: issue_calls.append(
        ("create", *args, kwargs)
    )
    issue_registry.async_delete_issue = lambda *args, **kwargs: issue_calls.append(
        ("delete", *args, kwargs)
    )
    update_coordinator = types.ModuleType("homeassistant.helpers.update_coordinator")
    update_coordinator.DataUpdateCoordinator = FakeDataUpdateCoordinator

    modules = {
        "rbw_coordinator_test": package,
        "rbw_coordinator_test.api": api,
        "rbw_coordinator_test.const": const,
        "homeassistant": types.ModuleType("homeassistant"),
        "homeassistant.config_entries": config_entries,
        "homeassistant.core": core,
        "homeassistant.helpers": types.ModuleType("homeassistant.helpers"),
        "homeassistant.helpers.issue_registry": issue_registry,
        "homeassistant.helpers.update_coordinator": update_coordinator,
    }
    spec = importlib.util.spec_from_file_location(
        "rbw_coordinator_test.coordinator", ROOT / "coordinator.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    with patch.dict(sys.modules, modules):
        spec.loader.exec_module(module)
    return module


class FakeClient:
    def __init__(self, result: api.RbwApiStatus | api.RbwApiError) -> None:
        self.result = result

    async def async_get_status(self) -> api.RbwApiStatus:
        if isinstance(self.result, api.RbwApiError):
            raise self.result
        return self.result


class RbwStatusDataTests(unittest.TestCase):
    def test_locked_and_unlocked_are_never_confused(self) -> None:
        coordinator = load_coordinator([])
        locked = coordinator.RbwStatusData(
            connected=True,
            status=api.RbwApiStatus(
                1, "2.40.0", (api.RbwAccountStatus("locked-account", "locked"),)
            ),
        )
        unlocked = coordinator.RbwStatusData(
            connected=True,
            status=api.RbwApiStatus(
                1, "2.40.0", (api.RbwAccountStatus("open-account", "unlocked"),)
            ),
        )
        unconfigured = coordinator.RbwStatusData(
            connected=True,
            status=api.RbwApiStatus(
                1, "2.40.0", (api.RbwAccountStatus("removed-account", "unconfigured"),)
            ),
        )

        self.assertTrue(locked.account_locked("locked-account"))
        self.assertFalse(unlocked.account_locked("open-account"))
        self.assertIsNone(unconfigured.account_locked("removed-account"))
        self.assertEqual(unconfigured.account_status("removed-account"), "unconfigured")

    def test_forbidden_status_is_connected_but_does_not_claim_vault_state(self) -> None:
        coordinator = load_coordinator([])
        data = coordinator.RbwStatusData(
            connected=True,
            error_code="status_permission_required",
        )

        self.assertTrue(data.connected)
        self.assertEqual(data.account_status("personal"), "status_permission_required")
        self.assertIsNone(data.account_locked("personal"))


class RbwStatusCoordinatorTests(unittest.IsolatedAsyncioTestCase):
    async def test_status_poll_is_bounded_and_only_creates_safe_permission_issue(self) -> None:
        issue_calls: list[tuple[object, ...]] = []
        module = load_coordinator(issue_calls)
        secret_message = "must not appear in logs or issue data"
        client = FakeClient(
            api.RbwApiError(
                "forbidden",
                secret_message,
                retryable=False,
                http_status=403,
            )
        )
        coordinator = module.RbwStatusCoordinator(
            SimpleNamespace(),
            SimpleNamespace(entry_id="entry"),
            client,
        )

        with self.assertLogs(module._LOGGER, level="DEBUG") as logs:
            result = await coordinator._async_update_data()

        self.assertTrue(result.connected)
        self.assertEqual(result.account_status("personal"), "status_permission_required")
        self.assertIsNone(result.account_locked("personal"))
        self.assertEqual(coordinator.kwargs["update_interval"].total_seconds(), 60)
        self.assertEqual(issue_calls[0][0], "create")
        self.assertEqual(issue_calls[0][4]["translation_key"], "status_permission_required")
        self.assertEqual(issue_calls[0][4]["data"], {"entry_id": "entry"})
        self.assertNotIn(secret_message, "\n".join(logs.output))
        self.assertNotIn(secret_message, repr(issue_calls))

    async def test_transport_failure_is_disconnected_and_retried_on_interval(self) -> None:
        issue_calls: list[tuple[object, ...]] = []
        module = load_coordinator(issue_calls)
        client = FakeClient(api.RbwApiError("connection_error", "safe", retryable=True))
        coordinator = module.RbwStatusCoordinator(
            SimpleNamespace(),
            SimpleNamespace(entry_id="entry"),
            client,
        )

        result = await coordinator._async_update_data()

        self.assertFalse(result.connected)
        self.assertEqual(result.account_status("personal"), "unavailable")
        self.assertIsNone(result.account_locked("personal"))
        self.assertEqual(issue_calls[0][0], "create")
        self.assertEqual(issue_calls[0][4]["translation_key"], "status_unavailable")

    async def test_success_clears_status_issues_and_returns_only_safe_metadata(self) -> None:
        issue_calls: list[tuple[object, ...]] = []
        module = load_coordinator(issue_calls)
        client = FakeClient(
            api.RbwApiStatus(1, "2.40.0", (api.RbwAccountStatus("personal", "unlocked"),))
        )
        coordinator = module.RbwStatusCoordinator(
            SimpleNamespace(),
            SimpleNamespace(entry_id="entry"),
            client,
        )

        result = await coordinator._async_update_data()

        self.assertTrue(result.connected)
        self.assertEqual(result.account_status("personal"), "unlocked")
        self.assertFalse(result.account_locked("personal"))
        self.assertEqual(result.status.agent_version, "2.40.0")
        self.assertTrue(all(call[0] == "delete" for call in issue_calls))


if __name__ == "__main__":
    unittest.main()

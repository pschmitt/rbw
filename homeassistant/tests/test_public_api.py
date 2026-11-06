"""Tests for the public HA integration-to-integration API."""

from __future__ import annotations

import importlib.util
import logging
import ssl
import sys
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from .test_api import FakeResponse, FakeSession

ROOT = Path(__file__).parents[1] / "custom_components" / "rbw"
API_SPEC = importlib.util.spec_from_file_location("rbw_public_test_api", ROOT / "api.py")
assert API_SPEC and API_SPEC.loader
api = importlib.util.module_from_spec(API_SPEC)
sys.modules[API_SPEC.name] = api
API_SPEC.loader.exec_module(api)


def load_integration() -> types.ModuleType:
    """Load the integration API using only mocked HA infrastructure."""
    package = types.ModuleType("rbw_public_test")
    package.__path__ = [str(ROOT)]
    const = types.ModuleType("rbw_public_test.const")
    for name, value in {
        "CONF_BASE_URL": "base_url",
        "CONF_CA_CERT": "ca_cert",
        "CONF_CLIENT_CERT": "client_cert",
        "CONF_CLIENT_KEY": "client_key",
        "DOMAIN": "rbw",
        "ISSUE_API_UNAVAILABLE": "api_unavailable",
        "ISSUE_CLIENT_CERT": "client_certificate",
        "ISSUE_REAUTHENTICATION_REQUIRED": "reauthentication_required",
    }.items():
        setattr(const, name, value)

    config_entries = types.ModuleType("homeassistant.config_entries")
    config_entries.ConfigEntry = object
    const_module = types.ModuleType("homeassistant.const")
    const_module.Platform = SimpleNamespace(BINARY_SENSOR="binary_sensor", SENSOR="sensor")
    core = types.ModuleType("homeassistant.core")
    core.HomeAssistant = object
    exceptions = types.ModuleType("homeassistant.exceptions")

    class HomeAssistantError(Exception):
        pass

    exceptions.HomeAssistantError = HomeAssistantError
    issue_registry = types.ModuleType("homeassistant.helpers.issue_registry")
    issue_registry.IssueSeverity = SimpleNamespace(ERROR="error")
    issue_registry.async_delete_issue = lambda *args: None
    issue_registry.async_create_issue = lambda *args, **kwargs: None
    aiohttp_client = types.ModuleType("homeassistant.helpers.aiohttp_client")
    aiohttp_client.async_get_clientsession = lambda hass: None
    coordinator = types.ModuleType("rbw_public_test.coordinator")

    class RbwStatusCoordinator:
        pass

    coordinator.RbwStatusCoordinator = RbwStatusCoordinator
    modules = {
        "rbw_public_test": package,
        "rbw_public_test.api": api,
        "rbw_public_test.coordinator": coordinator,
        "rbw_public_test.const": const,
        "homeassistant": types.ModuleType("homeassistant"),
        "homeassistant.config_entries": config_entries,
        "homeassistant.const": const_module,
        "homeassistant.core": core,
        "homeassistant.exceptions": exceptions,
        "homeassistant.helpers": types.ModuleType("homeassistant.helpers"),
        "homeassistant.helpers.issue_registry": issue_registry,
        "homeassistant.helpers.aiohttp_client": aiohttp_client,
    }
    spec = importlib.util.spec_from_file_location(
        "rbw_public_test",
        ROOT / "__init__.py",
        submodule_search_locations=[str(ROOT)],
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, modules):
        spec.loader.exec_module(module)
    return module


class PublicApiSecurityTests(unittest.IsolatedAsyncioTestCase):
    async def test_read_value_is_returned_to_caller_but_not_cached_or_logged(self) -> None:
        integration = load_integration()
        secret = "explicitly-requested-value"
        session = FakeSession(
            FakeResponse(
                200,
                {"field": "password", "value": secret, "sensitive": True},
            )
        )
        client = api.RbwApiClient(session, "https://vault.example", ssl.create_default_context())
        hass = SimpleNamespace(data={"rbw": {"entry": client}})
        logger = logging.getLogger(integration.__name__)

        with self.assertNoLogs(logger, level="INFO"):
            result = await integration.async_get_field(
                hass, "entry", "item-id", "password", consumer="custom_components.hrworks"
            )

        self.assertEqual(
            result,
            {"field": "password", "value": secret, "sensitive": True},
        )
        self.assertEqual(
            session.requests[0][1].get("headers"),
            {"X-Rbw-Consumer": "custom_components.hrworks"},
        )
        self.assertNotIn(secret, repr(client.__dict__))
        self.assertNotIn(secret, repr(hass.data))

    async def test_server_error_text_does_not_enter_logs_or_exception(self) -> None:
        integration = load_integration()
        secret = "must-not-appear-in-logs"
        session = FakeSession(
            FakeResponse(
                403,
                {"code": "policy_denied", "message": secret, "retryable": False},
            )
        )
        client = api.RbwApiClient(session, "https://vault.example", ssl.create_default_context())
        hass = SimpleNamespace(data={"rbw": {"entry": client}})
        logger = logging.getLogger(integration.__name__)

        with self.assertLogs(logger, level="WARNING") as captured:
            with self.assertRaises(integration.HomeAssistantError) as raised:
                await integration.async_get_field(hass, "entry", "item-id", "password")

        self.assertNotIn(secret, str(raised.exception))
        self.assertNotIn(secret, "\n".join(captured.output))
        self.assertIn("policy_denied", "\n".join(captured.output))


if __name__ == "__main__":
    unittest.main()

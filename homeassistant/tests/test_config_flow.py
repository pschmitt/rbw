"""Tests that HA config entries store certificate paths, not key material."""

from __future__ import annotations

import importlib.util
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import voluptuous as vol

ROOT = Path(__file__).parents[1] / "custom_components" / "rbw"
API_SPEC = importlib.util.spec_from_file_location("rbw_config_test_api", ROOT / "api.py")
assert API_SPEC and API_SPEC.loader
api = importlib.util.module_from_spec(API_SPEC)
sys.modules[API_SPEC.name] = api
API_SPEC.loader.exec_module(api)


class FakeConfigFlow:
    def __init_subclass__(cls, *, domain: str, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)

    async def async_set_unique_id(self, unique_id: str) -> None:
        self.unique_id = unique_id

    def _abort_if_unique_id_mismatch(self) -> None:
        self.checked_unique_id = True

    def _get_reconfigure_entry(self) -> object:
        return "existing-entry"

    def async_update_reload_and_abort(self, entry: object, *, data_updates: dict[str, str]):
        return {"entry": entry, "data_updates": data_updates}


def load_config_flow() -> types.ModuleType:
    """Import config_flow.py with only its base HA classes stubbed."""
    package = types.ModuleType("rbw_config_test")
    package.__path__ = [str(ROOT)]
    const = types.ModuleType("rbw_config_test.const")
    const.CONF_BASE_URL = "base_url"
    const.CONF_CA_CERT = "ca_cert"
    const.CONF_CLIENT_CERT = "client_cert"
    const.CONF_CLIENT_KEY = "client_key"
    const.DOMAIN = "rbw"

    config_entries = types.ModuleType("homeassistant.config_entries")
    config_entries.ConfigFlow = FakeConfigFlow
    data_entry_flow = types.ModuleType("homeassistant.data_entry_flow")
    data_entry_flow.FlowResult = dict
    modules = {
        "rbw_config_test": package,
        "rbw_config_test.api": api,
        "rbw_config_test.const": const,
        "homeassistant": types.ModuleType("homeassistant"),
        "homeassistant.config_entries": config_entries,
        "homeassistant.data_entry_flow": data_entry_flow,
    }
    spec = importlib.util.spec_from_file_location(
        "rbw_config_test.config_flow", ROOT / "config_flow.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, modules):
        spec.loader.exec_module(module)
    return module


class ConfigFlowSecretHandlingTests(unittest.TestCase):
    def test_config_entry_data_contains_only_certificate_file_paths(self) -> None:
        config_flow = load_config_flow()
        schema = config_flow._schema()
        self.assertEqual(
            {key.schema for key in schema.schema},
            {"base_url", "ca_cert", "client_cert", "client_key"},
        )
        with self.assertRaises(vol.Invalid):
            schema(
                {
                    "base_url": "https://vault.example",
                    "ca_cert": "/config/rbw/ca.pem",
                    "client_cert": "/config/rbw/client.pem",
                    "client_key": "/config/rbw/client-key.pem",
                    "client_key_pem": "private-key-contents",
                }
            )
        paths = {
            "base_url": "https://vault.example",
            "ca_cert": "/config/rbw/ca.pem",
            "client_cert": "/config/rbw/client.pem",
            "client_key": "/config/rbw/client-key.pem",
        }
        with patch.object(api.RbwApiClient, "create_ssl_context") as load_certificates:
            stored_data = config_flow._validate_input(paths)

        self.assertEqual(stored_data, paths)
        self.assertNotIn("private_key_pem", stored_data)
        load_certificates.assert_called_once_with(
            paths["ca_cert"], paths["client_cert"], paths["client_key"]
        )


class ConfigFlowReconfigureTests(unittest.IsolatedAsyncioTestCase):
    async def test_reconfigure_preserves_server_unique_id(self) -> None:
        config_flow = load_config_flow()
        flow = config_flow.RbwConfigFlow()
        flow.hass = object()
        entry = types.SimpleNamespace(
            data={
                "base_url": "https://vault.example",
                "ca_cert": "/config/rbw/ca.pem",
                "client_cert": "/config/rbw/client.pem",
                "client_key": "/config/rbw/client-key.pem",
            }
        )
        flow._get_reconfigure_entry = lambda: entry
        with patch.object(api.RbwApiClient, "create_ssl_context"):
            result = await flow.async_step_reconfigure(entry.data)

        self.assertEqual(flow.unique_id, "https://vault.example")
        self.assertTrue(flow.checked_unique_id)
        self.assertEqual(result["entry"], entry)
        self.assertEqual(result["data_updates"], entry.data)


if __name__ == "__main__":
    unittest.main()

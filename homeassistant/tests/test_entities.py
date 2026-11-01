"""Tests for rbw diagnostic entities and unknown lock states."""

from __future__ import annotations

import importlib.util
import sys
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).parents[1] / "custom_components" / "rbw"
COORDINATOR_SPEC = importlib.util.spec_from_file_location(
    "rbw_entity_test.coordinator", ROOT / "coordinator.py"
)
API_SPEC = importlib.util.spec_from_file_location("rbw_entity_test_api", ROOT / "api.py")
assert COORDINATOR_SPEC and COORDINATOR_SPEC.loader
assert API_SPEC and API_SPEC.loader
api = importlib.util.module_from_spec(API_SPEC)
sys.modules[API_SPEC.name] = api
API_SPEC.loader.exec_module(api)


class FakeCoordinatorEntity:
    def __class_getitem__(cls, item: object) -> type[FakeCoordinatorEntity]:
        return cls

    def __init__(self, coordinator: object) -> None:
        self.coordinator = coordinator


class FakeDataUpdateCoordinator:
    def __class_getitem__(cls, item: object) -> type[FakeDataUpdateCoordinator]:
        return cls


class FakeEntity:
    @property
    def entity_category(self) -> str | None:
        return getattr(self, "_attr_entity_category", None)

    @property
    def device_info(self) -> FakeDeviceInfo:
        return self._attr_device_info


class FakeDeviceInfo:
    def __init__(self, **values: object) -> None:
        self.values = values


def load_entities() -> tuple[types.ModuleType, types.ModuleType, types.ModuleType]:
    """Import entity platforms using a small fake Home Assistant API surface."""
    coordinator_module = importlib.util.module_from_spec(COORDINATOR_SPEC)
    package = types.ModuleType("rbw_entity_test")
    package.__path__ = [str(ROOT)]
    package.RbwRuntimeData = object
    const = types.ModuleType("rbw_entity_test.const")
    const.DOMAIN = "rbw"
    const.ISSUE_CLIENT_CERT = "client_certificate"
    const.ISSUE_STATUS_PERMISSION = "status_permission_required"
    const.ISSUE_STATUS_UNAVAILABLE = "status_unavailable"

    binary_sensor = types.ModuleType("homeassistant.components.binary_sensor")
    binary_sensor.BinarySensorDeviceClass = SimpleNamespace(
        CONNECTIVITY="connectivity", LOCK="lock"
    )
    binary_sensor.BinarySensorEntity = FakeEntity
    sensor = types.ModuleType("homeassistant.components.sensor")
    sensor.SensorDeviceClass = SimpleNamespace(ENUM="enum")
    sensor.SensorEntity = FakeEntity
    config_entries = types.ModuleType("homeassistant.config_entries")
    config_entries.ConfigEntry = object
    core = types.ModuleType("homeassistant.core")
    core.HomeAssistant = object
    device_registry = types.ModuleType("homeassistant.helpers.device_registry")
    device_registry.DeviceInfo = FakeDeviceInfo
    entity = types.ModuleType("homeassistant.helpers.entity")
    entity.EntityCategory = SimpleNamespace(DIAGNOSTIC="diagnostic")
    entity_platform = types.ModuleType("homeassistant.helpers.entity_platform")
    entity_platform.AddEntitiesCallback = object
    update_coordinator = types.ModuleType("homeassistant.helpers.update_coordinator")
    update_coordinator.CoordinatorEntity = FakeCoordinatorEntity
    update_coordinator.DataUpdateCoordinator = FakeDataUpdateCoordinator

    modules = {
        "rbw_entity_test": package,
        "rbw_entity_test.api": api,
        "rbw_entity_test.const": const,
        "rbw_entity_test.coordinator": coordinator_module,
        "homeassistant": types.ModuleType("homeassistant"),
        "homeassistant.components": types.ModuleType("homeassistant.components"),
        "homeassistant.components.binary_sensor": binary_sensor,
        "homeassistant.components.sensor": sensor,
        "homeassistant.config_entries": config_entries,
        "homeassistant.core": core,
        "homeassistant.helpers": types.ModuleType("homeassistant.helpers"),
        "homeassistant.helpers.device_registry": device_registry,
        "homeassistant.helpers.entity": entity,
        "homeassistant.helpers.entity_platform": entity_platform,
        "homeassistant.helpers.update_coordinator": update_coordinator,
        "homeassistant.helpers.issue_registry": types.ModuleType(
            "homeassistant.helpers.issue_registry"
        ),
    }
    with patch.dict(sys.modules, modules):
        sys.modules[COORDINATOR_SPEC.name] = coordinator_module
        COORDINATOR_SPEC.loader.exec_module(coordinator_module)
        binary_spec = importlib.util.spec_from_file_location(
            "rbw_entity_test.binary_sensor", ROOT / "binary_sensor.py"
        )
        sensor_spec = importlib.util.spec_from_file_location(
            "rbw_entity_test.sensor", ROOT / "sensor.py"
        )
        assert binary_spec and binary_spec.loader
        assert sensor_spec and sensor_spec.loader
        binary_module = importlib.util.module_from_spec(binary_spec)
        sensor_module = importlib.util.module_from_spec(sensor_spec)
        binary_spec.loader.exec_module(binary_module)
        sensor_spec.loader.exec_module(sensor_module)
    return coordinator_module, binary_module, sensor_module


class RbwDiagnosticEntityTests(unittest.IsolatedAsyncioTestCase):
    async def test_platforms_create_five_diagnostic_entities_for_one_device(self) -> None:
        coordinator_module, binary_module, sensor_module = load_entities()
        runtime = SimpleNamespace(
            coordinator=SimpleNamespace(
                data=coordinator_module.RbwStatusData(
                    connected=True,
                    status=api.RbwApiStatus(1, "2.39.0", "locked"),
                )
            )
        )
        hass = SimpleNamespace(data={"rbw": {"entry": runtime}})
        entry = SimpleNamespace(entry_id="entry")
        entities: list[object] = []

        await binary_module.async_setup_entry(hass, entry, entities.extend)
        await sensor_module.async_setup_entry(hass, entry, entities.extend)

        self.assertEqual(len(entities), 5)
        self.assertTrue(all(entity.entity_category == "diagnostic" for entity in entities))
        self.assertTrue(
            all(
                entity.device_info.values["identifiers"] == {("rbw", "entry")}
                for entity in entities
            )
        )
        connected, vault_locked = entities[:2]
        vault_status, api_version, agent_version = entities[2:]
        self.assertTrue(connected.is_on)
        self.assertTrue(vault_locked.is_on)
        self.assertEqual(vault_status.native_value, "locked")
        self.assertEqual(api_version.native_value, 1)
        self.assertEqual(agent_version.native_value, "2.39.0")

    async def test_status_permission_denial_is_connected_but_lock_remains_unknown(self) -> None:
        coordinator_module, binary_module, sensor_module = load_entities()
        runtime = SimpleNamespace(
            coordinator=SimpleNamespace(
                data=coordinator_module.RbwStatusData(
                    connected=True,
                    error_code="status_permission_required",
                )
            )
        )
        hass = SimpleNamespace(data={"rbw": {"entry": runtime}})
        entry = SimpleNamespace(entry_id="entry")
        binary_entities: list[object] = []
        sensor_entities: list[object] = []

        await binary_module.async_setup_entry(hass, entry, binary_entities.extend)
        await sensor_module.async_setup_entry(hass, entry, sensor_entities.extend)

        self.assertTrue(binary_entities[0].is_on)
        self.assertIsNone(binary_entities[1].is_on)
        self.assertEqual(sensor_entities[0].native_value, "status_permission_required")
        self.assertIsNone(sensor_entities[1].native_value)
        self.assertIsNone(sensor_entities[2].native_value)

    async def test_transport_failure_reports_unavailable_and_not_locked(self) -> None:
        coordinator_module, binary_module, _ = load_entities()
        runtime = SimpleNamespace(
            coordinator=SimpleNamespace(
                data=coordinator_module.RbwStatusData(connected=False, error_code="timeout")
            )
        )
        hass = SimpleNamespace(data={"rbw": {"entry": runtime}})
        entities: list[object] = []

        await binary_module.async_setup_entry(
            hass, SimpleNamespace(entry_id="entry"), entities.extend
        )

        self.assertFalse(entities[0].is_on)
        self.assertIsNone(entities[1].is_on)


if __name__ == "__main__":
    unittest.main()

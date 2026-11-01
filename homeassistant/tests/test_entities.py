"""Tests for rbw diagnostic entities and unknown lock states."""

from __future__ import annotations

import asyncio
import importlib.util
import json
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

    async def async_remove(self, *, force_remove: bool = False) -> None:
        self.removed = force_remove


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

    @property
    def available(self) -> bool:
        return True


class FakeCoordinator:
    def __init__(self, data: object) -> None:
        self.data = data
        self.listeners: list[object] = []

    def async_add_listener(self, listener: object) -> object:
        self.listeners.append(listener)
        return lambda: self.listeners.remove(listener)

    def notify(self) -> None:
        for listener in self.listeners:
            listener()


class FakeEntry:
    def __init__(self, entry_id: str) -> None:
        self.entry_id = entry_id
        self.unload_callbacks: list[object] = []

    def async_on_unload(self, callback: object) -> None:
        self.unload_callbacks.append(callback)


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
    async def test_custom_integration_translations_include_account_names_and_all_states(self) -> None:
        _, binary_module, sensor_module = load_entities()
        source = json.loads((ROOT / "strings.json").read_text())
        packaged = json.loads(
            (ROOT / "translations" / "en.json").read_text()
        )

        self.assertEqual(packaged, source)
        self.assertIn(
            "{account}",
            packaged["entity"]["binary_sensor"]["vault_locked"]["name"],
        )
        self.assertIn(
            "{account}",
            packaged["entity"]["sensor"]["vault_status"]["name"],
        )
        self.assertEqual(
            set(packaged["entity"]["sensor"]["vault_status"]["state"]),
            set(sensor_module.VAULT_STATUS_OPTIONS),
        )
        self.assertEqual(
            packaged["entity"]["binary_sensor"]["vault_locked"]["name"],
            "Vault locked ({account})",
        )
        self.assertEqual(
            packaged["entity"]["sensor"]["vault_status"]["name"],
            "Vault status ({account})",
        )

    async def test_platforms_create_shared_and_per_account_diagnostic_entities(self) -> None:
        coordinator_module, binary_module, sensor_module = load_entities()
        coordinator = FakeCoordinator(
            coordinator_module.RbwStatusData(
                connected=True,
                status=api.RbwApiStatus(
                    1,
                    "2.40.0",
                    (
                        api.RbwAccountStatus("ai", "locked"),
                        api.RbwAccountStatus("bw", "unlocked"),
                        api.RbwAccountStatus("default", "locked"),
                        api.RbwAccountStatus("wiit", "unlocked"),
                    ),
                ),
            )
        )
        runtime = SimpleNamespace(
            coordinator=coordinator,
        )
        hass = SimpleNamespace(
            data={"rbw": {"entry": runtime}},
            async_create_task=asyncio.create_task,
        )
        entry = FakeEntry("entry")
        binary_entities: list[object] = []
        sensor_entities: list[object] = []

        await binary_module.async_setup_entry(hass, entry, binary_entities.extend)
        await sensor_module.async_setup_entry(hass, entry, sensor_entities.extend)

        self.assertEqual(len(binary_entities), 5)
        self.assertEqual(len(sensor_entities), 6)
        entities = binary_entities + sensor_entities
        self.assertTrue(all(entity.entity_category == "diagnostic" for entity in entities))
        self.assertTrue(
            all(
                entity.device_info.values["identifiers"] == {("rbw", "entry")}
                for entity in entities
            )
        )
        connected = binary_entities[0]
        locked_by_account = {
            entity.account: entity for entity in binary_entities[1:]
        }
        api_version, agent_version = sensor_entities[:2]
        status_by_account = {
            entity.account: entity for entity in sensor_entities[2:]
        }
        self.assertTrue(connected.is_on)
        self.assertEqual(
            set(locked_by_account), {"ai", "bw", "default", "wiit"}
        )
        self.assertEqual(set(status_by_account), set(locked_by_account))
        for account, expected_state in {
            "ai": "locked",
            "bw": "unlocked",
            "default": "locked",
            "wiit": "unlocked",
        }.items():
            self.assertEqual(
                locked_by_account[account].is_on,
                expected_state == "locked",
            )
            self.assertEqual(
                status_by_account[account].native_value, expected_state
            )
            self.assertTrue(locked_by_account[account].available)
            self.assertEqual(
                locked_by_account[account]._attr_translation_placeholders,
                {"account": account},
            )
            self.assertEqual(
                status_by_account[account]._attr_translation_placeholders,
                {"account": account},
            )
        self.assertEqual(
            locked_by_account["ai"]._attr_unique_id,
            binary_module.RbwVaultLockedSensor(
                coordinator, "entry", locked_by_account["ai"].device_info, "ai"
            )._attr_unique_id,
        )
        self.assertEqual(
            len({entity._attr_unique_id for entity in locked_by_account.values()}),
            4,
        )
        self.assertEqual(
            len({entity._attr_unique_id for entity in status_by_account.values()}),
            4,
        )
        self.assertEqual(api_version.native_value, 1)
        self.assertEqual(agent_version.native_value, "2.40.0")

    async def test_status_permission_denial_is_connected_but_lock_remains_unknown(self) -> None:
        coordinator_module, binary_module, sensor_module = load_entities()
        coordinator = FakeCoordinator(
            coordinator_module.RbwStatusData(
                connected=True, error_code="status_permission_required"
            )
        )
        runtime = SimpleNamespace(coordinator=coordinator)
        hass = SimpleNamespace(
            data={"rbw": {"entry": runtime}}, async_create_task=asyncio.create_task
        )
        entry = FakeEntry("entry")
        binary_entities: list[object] = []
        sensor_entities: list[object] = []

        await binary_module.async_setup_entry(hass, entry, binary_entities.extend)
        await sensor_module.async_setup_entry(hass, entry, sensor_entities.extend)

        self.assertTrue(binary_entities[0].is_on)
        self.assertEqual(len(binary_entities), 1)
        self.assertEqual(len(sensor_entities), 2)
        self.assertIsNone(sensor_entities[0].native_value)
        self.assertIsNone(sensor_entities[1].native_value)

    async def test_transport_failure_reports_unavailable_and_not_locked(self) -> None:
        coordinator_module, binary_module, _ = load_entities()
        coordinator = FakeCoordinator(
            coordinator_module.RbwStatusData(connected=False, error_code="timeout")
        )
        runtime = SimpleNamespace(coordinator=coordinator)
        hass = SimpleNamespace(
            data={"rbw": {"entry": runtime}}, async_create_task=asyncio.create_task
        )
        entities: list[object] = []

        await binary_module.async_setup_entry(hass, FakeEntry("entry"), entities.extend)

        self.assertFalse(entities[0].is_on)
        self.assertEqual(len(entities), 1)

    async def test_account_entities_follow_grants_and_keep_unknown_on_transport_failure(
        self,
    ) -> None:
        coordinator_module, binary_module, sensor_module = load_entities()
        coordinator = FakeCoordinator(
            coordinator_module.RbwStatusData(
                connected=True,
                status=api.RbwApiStatus(
                    1,
                    "2.40.0",
                    (
                        api.RbwAccountStatus("personal", "locked"),
                        api.RbwAccountStatus("work", "unlocked"),
                    ),
                ),
            )
        )
        runtime = SimpleNamespace(coordinator=coordinator)
        hass = SimpleNamespace(
            data={"rbw": {"entry": runtime}}, async_create_task=asyncio.create_task
        )
        entry = FakeEntry("entry")
        binary_entities: list[object] = []
        sensor_entities: list[object] = []
        await binary_module.async_setup_entry(hass, entry, binary_entities.extend)
        await sensor_module.async_setup_entry(hass, entry, sensor_entities.extend)

        old_work_lock = next(
            entity for entity in binary_entities if getattr(entity, "account", None) == "work"
        )
        old_work_status = next(
            entity for entity in sensor_entities if getattr(entity, "account", None) == "work"
        )
        coordinator.data = coordinator_module.RbwStatusData(
            connected=False,
            error_code="timeout",
        )
        coordinator.notify()
        self.assertIsNone(old_work_lock.is_on)
        self.assertEqual(old_work_status.native_value, "unavailable")
        self.assertFalse(old_work_lock.available)
        self.assertFalse(old_work_status.available)
        self.assertFalse(getattr(old_work_lock, "removed", False))

        coordinator.data = coordinator_module.RbwStatusData(
            connected=True,
            status=api.RbwApiStatus(
                1,
                "2.40.0",
                (
                    api.RbwAccountStatus("personal", "unconfigured"),
                    api.RbwAccountStatus("new-account", "locked"),
                ),
            ),
        )
        coordinator.notify()
        await asyncio.sleep(0)
        self.assertTrue(old_work_lock.removed)
        self.assertTrue(old_work_status.removed)
        remaining_locks = [
            entity
            for entity in binary_entities
            if hasattr(entity, "account") and not getattr(entity, "removed", False)
        ]
        remaining_statuses = [
            entity
            for entity in sensor_entities
            if hasattr(entity, "account") and not getattr(entity, "removed", False)
        ]
        self.assertEqual(
            sorted(entity.account for entity in remaining_locks), ["new-account", "personal"]
        )
        self.assertEqual(
            sorted(entity.account for entity in remaining_statuses),
            ["new-account", "personal"],
        )
        personal_lock = next(entity for entity in remaining_locks if entity.account == "personal")
        personal_status = next(
            entity for entity in remaining_statuses if entity.account == "personal"
        )
        self.assertTrue(personal_lock.available)
        self.assertIsNone(personal_lock.is_on)
        self.assertTrue(personal_status.available)
        self.assertEqual(personal_status.native_value, "unconfigured")

        coordinator.data = coordinator_module.RbwStatusData(
            connected=True,
            error_code="status_permission_required",
        )
        coordinator.notify()
        await asyncio.sleep(0)
        self.assertTrue(all(getattr(entity, "removed", False) for entity in remaining_locks))
        self.assertTrue(all(getattr(entity, "removed", False) for entity in remaining_statuses))


if __name__ == "__main__":
    unittest.main()

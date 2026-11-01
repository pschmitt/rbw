"""Tests for rbw diagnostic entities and unknown lock states."""

from __future__ import annotations

import asyncio
import hashlib
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

    async def async_added_to_hass(self) -> None:
        pass


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
        self.data = {"base_url": "https://fnuc.example:24871"}
        self.unload_callbacks: list[object] = []

    def async_on_unload(self, callback: object) -> None:
        self.unload_callbacks.append(callback)


class FakeDeviceInfo:
    def __init__(self, **values: object) -> None:
        self.values = values

    def __getitem__(self, key: str) -> object:
        return self.values[key]


class FakeEntityRegistry:
    def __init__(self, entities: dict[str, object] | None = None) -> None:
        self.entities = entities or {}
        self.updates: list[tuple[str, dict[str, object]]] = []

    def async_get(self, entity_id: str) -> object | None:
        return self.entities.get(entity_id)

    def async_remove(self, entity_id: str) -> None:
        self.entities.pop(entity_id, None)

    def async_update_entity(self, entity_id: str, **kwargs: object) -> None:
        self.updates.append((entity_id, kwargs))


class FakeDeviceRegistry:
    def __init__(self, sw_version: str | None = None) -> None:
        self.device = SimpleNamespace(
            id="device", sw_version=sw_version, configuration_url=None
        )
        self.updates: list[tuple[str, dict[str, object]]] = []

    def async_get_device_by_identifier(
        self, identifier: tuple[str, str], config_entry_id: str
    ) -> object:
        self.lookup = (identifier, config_entry_id)
        return self.device

    def async_update_device(self, device_id: str, **kwargs: object) -> None:
        self.updates.append((device_id, kwargs))
        for key, value in kwargs.items():
            setattr(self.device, key, value)


def load_entities() -> tuple[types.ModuleType, types.ModuleType, types.ModuleType]:
    """Import entity platforms using a small fake Home Assistant API surface."""
    coordinator_module = importlib.util.module_from_spec(COORDINATOR_SPEC)
    package = types.ModuleType("rbw_entity_test")
    package.__path__ = [str(ROOT)]
    package.RbwRuntimeData = object
    const = types.ModuleType("rbw_entity_test.const")
    const.DOMAIN = "rbw"
    const.CONF_BASE_URL = "base_url"
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
    device_registry.async_get = lambda hass: hass.device_registry
    entity = types.ModuleType("homeassistant.helpers.entity")
    entity.EntityCategory = SimpleNamespace(DIAGNOSTIC="diagnostic")
    entity_platform = types.ModuleType("homeassistant.helpers.entity_platform")
    entity_platform.AddEntitiesCallback = object
    entity_registry = types.ModuleType("homeassistant.helpers.entity_registry")
    entity_registry.async_get = lambda hass: hass.entity_registry
    util = types.ModuleType("homeassistant.util")
    util.slugify = lambda value, separator="_": "_".join(
        "".join(char.lower() if char.isalnum() else " " for char in value).split()
    )
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
        "homeassistant.helpers.entity_registry": entity_registry,
        "homeassistant.helpers.update_coordinator": update_coordinator,
        "homeassistant.util": util,
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
    async def test_translation_parity_and_account_lock_name(self) -> None:
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
        self.assertEqual(
            packaged["entity"]["binary_sensor"]["vault_locked"]["name"],
            "Vault locked ({account})",
        )
        self.assertNotIn("vault_status", packaged["entity"]["sensor"])
        self.assertFalse(hasattr(sensor_module, "VAULT_STATUS_OPTIONS"))
        self.assertFalse(hasattr(sensor_module, "RbwAgentVersionSensor"))
        self.assertEqual(
            binary_module._account_object_ids({"ai", "bw"}),
            {"ai": "rbw_ai_locked", "bw": "rbw_bw_locked"},
        )
        self.assertEqual(
            len(set(binary_module._account_object_ids({"A B", "a-b"}).values())), 2
        )

    async def test_account_entity_renames_registry_id_without_replacing_customizations(self) -> None:
        coordinator_module, binary_module, _ = load_entities()
        coordinator = FakeCoordinator(
            coordinator_module.RbwStatusData(
                connected=True,
                status=api.RbwApiStatus(1, "2.40.0", (api.RbwAccountStatus("ai", "locked"),)),
            )
        )
        old = SimpleNamespace(
            entity_id="binary_sensor.rbw_vault_locked_ai",
            unique_id="stable",
            suggested_object_id="rbw_vault_locked_ai",
        )
        registry = FakeEntityRegistry({old.entity_id: old})
        entity = binary_module.RbwVaultLockedSensor(
            coordinator, "entry", FakeDeviceInfo(identifiers={("rbw", "entry")}), "ai", "rbw_ai_locked"
        )
        entity.hass = SimpleNamespace(entity_registry=registry)
        entity.entity_id = old.entity_id

        await entity.async_added_to_hass()

        self.assertEqual(
            registry.updates,
            [(old.entity_id, {"new_entity_id": "binary_sensor.rbw_ai_locked"})],
        )

        customized = SimpleNamespace(
            entity_id="binary_sensor.my_custom_lock_id",
            unique_id="stable",
            suggested_object_id="rbw_vault_locked_ai",
        )
        registry = FakeEntityRegistry({customized.entity_id: customized})
        entity.hass = SimpleNamespace(entity_registry=registry)
        entity.entity_id = customized.entity_id
        await entity.async_added_to_hass()
        self.assertEqual(registry.updates, [])

    async def test_obsolete_status_and_agent_sensors_are_removed_from_registry(self) -> None:
        _, _, sensor_module = load_entities()
        obsolete_status = SimpleNamespace(
            entity_id="sensor.rbw_status_ai",
            config_entry_id="entry",
            platform="rbw",
            unique_id="entry_account_abc_vault_status",
        )
        obsolete_agent = SimpleNamespace(
            entity_id="sensor.rbw_agent_version",
            config_entry_id="entry",
            platform="rbw",
            unique_id="entry_agent_version",
        )
        api_version = SimpleNamespace(
            entity_id="sensor.rbw_api_version",
            config_entry_id="entry",
            platform="rbw",
            unique_id="entry_api_version",
        )
        registry = FakeEntityRegistry(
            {item.entity_id: item for item in (obsolete_status, obsolete_agent, api_version)}
        )
        coordinator = FakeCoordinator(None)
        hass = SimpleNamespace(
            data={"rbw": {"entry": SimpleNamespace(coordinator=coordinator, configuration_url=None)}},
            entity_registry=registry,
        )
        entities: list[object] = []

        await sensor_module.async_setup_entry(hass, FakeEntry("entry"), entities.extend)

        self.assertEqual(list(registry.entities), [api_version.entity_id])
        self.assertEqual(len(entities), 1)

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
        runtime = SimpleNamespace(coordinator=coordinator, configuration_url="https://fnuc.example:24871")
        device_registry = FakeDeviceRegistry()
        hass = SimpleNamespace(
            data={"rbw": {"entry": runtime}},
            async_create_task=asyncio.create_task,
            entity_registry=FakeEntityRegistry(),
            device_registry=device_registry,
        )
        entry = FakeEntry("entry")
        binary_entities: list[object] = []
        sensor_entities: list[object] = []

        await binary_module.async_setup_entry(hass, entry, binary_entities.extend)
        await sensor_module.async_setup_entry(hass, entry, sensor_entities.extend)

        self.assertEqual(len(binary_entities), 5)
        self.assertEqual(len(sensor_entities), 1)
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
        (api_version,) = sensor_entities
        self.assertTrue(connected.is_on)
        self.assertEqual(
            set(locked_by_account), {"ai", "bw", "default", "wiit"}
        )
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
            self.assertTrue(locked_by_account[account].available)
            self.assertEqual(
                locked_by_account[account]._attr_translation_placeholders,
                {"account": account},
            )
        self.assertEqual(
            locked_by_account["ai"]._attr_unique_id,
            binary_module.RbwVaultLockedSensor(
                coordinator, "entry", locked_by_account["ai"].device_info, "ai", "rbw_ai_locked"
            )._attr_unique_id,
        )
        self.assertEqual(locked_by_account["ai"]._object_id, "rbw_ai_locked")
        self.assertEqual(connected.device_info.values["sw_version"], "2.40.0")
        self.assertEqual(api_version.device_info.values["sw_version"], "2.40.0")
        self.assertEqual(
            connected.device_info.values["configuration_url"],
            "https://fnuc.example:24871",
        )
        self.assertEqual(
            len({entity._attr_unique_id for entity in locked_by_account.values()}),
            4,
        )
        self.assertEqual(api_version.native_value, 1)
        self.assertEqual(device_registry.device.sw_version, "2.40.0")
        self.assertEqual(device_registry.device.configuration_url, "https://fnuc.example:24871")
        self.assertEqual(
            device_registry.updates[0],
            (
                "device",
                {
                    "sw_version": "2.40.0",
                    "configuration_url": "https://fnuc.example:24871",
                },
            ),
        )
        self.assertEqual(
            device_registry.lookup, (("rbw", "entry"), "entry")
        )

        coordinator.data = coordinator_module.RbwStatusData(
            connected=True,
            status=api.RbwApiStatus(1, "2.41.0", ()),
        )
        coordinator.notify()
        self.assertEqual(device_registry.device.sw_version, "2.41.0")
        self.assertEqual(
            device_registry.updates[-1], ("device", {"sw_version": "2.41.0"})
        )

    async def test_status_permission_denial_is_connected_but_lock_remains_unknown(self) -> None:
        coordinator_module, binary_module, sensor_module = load_entities()
        coordinator = FakeCoordinator(
            coordinator_module.RbwStatusData(
                connected=True, error_code="status_permission_required"
            )
        )
        runtime = SimpleNamespace(coordinator=coordinator, configuration_url=None)
        hass = SimpleNamespace(
            data={"rbw": {"entry": runtime}}, async_create_task=asyncio.create_task,
            entity_registry=FakeEntityRegistry(),
            device_registry=FakeDeviceRegistry(),
        )
        entry = FakeEntry("entry")
        binary_entities: list[object] = []
        sensor_entities: list[object] = []

        await binary_module.async_setup_entry(hass, entry, binary_entities.extend)
        await sensor_module.async_setup_entry(hass, entry, sensor_entities.extend)

        self.assertTrue(binary_entities[0].is_on)
        self.assertEqual(len(binary_entities), 1)
        self.assertEqual(len(sensor_entities), 1)
        self.assertIsNone(sensor_entities[0].native_value)
        self.assertIsNone(sensor_entities[0].device_info.values["sw_version"])
        self.assertIsNone(binary_entities[0].device_info.values["configuration_url"])

    async def test_transport_failure_reports_unavailable_and_not_locked(self) -> None:
        coordinator_module, binary_module, _ = load_entities()
        coordinator = FakeCoordinator(
            coordinator_module.RbwStatusData(connected=False, error_code="timeout")
        )
        runtime = SimpleNamespace(coordinator=coordinator, configuration_url=None)
        hass = SimpleNamespace(
            data={"rbw": {"entry": runtime}}, async_create_task=asyncio.create_task,
            entity_registry=FakeEntityRegistry(),
            device_registry=FakeDeviceRegistry(),
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
        runtime = SimpleNamespace(coordinator=coordinator, configuration_url="https://api.example:443")
        stale_account = SimpleNamespace(
            entity_id="binary_sensor.custom_revoked_lock",
            config_entry_id="entry",
            platform="rbw",
            unique_id=f"entry_account_{hashlib.sha256(b'revoked').hexdigest()}_vault_locked",
        )
        granted_account = SimpleNamespace(
            entity_id="binary_sensor.custom_personal_lock",
            config_entry_id="entry",
            platform="rbw",
            unique_id=f"entry_account_{hashlib.sha256(b'personal').hexdigest()}_vault_locked",
        )
        registry = FakeEntityRegistry(
            {item.entity_id: item for item in (stale_account, granted_account)}
        )
        hass = SimpleNamespace(
            data={"rbw": {"entry": runtime}}, async_create_task=asyncio.create_task,
            entity_registry=registry,
            device_registry=FakeDeviceRegistry(),
        )
        entry = FakeEntry("entry")
        binary_entities: list[object] = []
        await binary_module.async_setup_entry(hass, entry, binary_entities.extend)
        await sensor_module.async_setup_entry(hass, entry, lambda entities: None)

        old_work_lock = next(
            entity for entity in binary_entities if getattr(entity, "account", None) == "work"
        )
        self.assertNotIn(stale_account.entity_id, registry.entities)
        self.assertIn(granted_account.entity_id, registry.entities)
        coordinator.data = coordinator_module.RbwStatusData(
            connected=False,
            error_code="timeout",
        )
        coordinator.notify()
        self.assertIsNone(old_work_lock.is_on)
        self.assertFalse(old_work_lock.available)
        self.assertFalse(getattr(old_work_lock, "removed", False))
        self.assertIn(granted_account.entity_id, registry.entities)

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
        remaining_locks = [
            entity
            for entity in binary_entities
            if hasattr(entity, "account") and not getattr(entity, "removed", False)
        ]
        self.assertEqual(
            sorted(entity.account for entity in remaining_locks), ["new-account", "personal"]
        )
        personal_lock = next(entity for entity in remaining_locks if entity.account == "personal")
        self.assertTrue(personal_lock.available)
        self.assertIsNone(personal_lock.is_on)

        coordinator.data = coordinator_module.RbwStatusData(
            connected=True,
            error_code="status_permission_required",
        )
        coordinator.notify()
        await asyncio.sleep(0)
        self.assertTrue(all(not getattr(entity, "removed", False) for entity in remaining_locks))
        self.assertTrue(all(not entity.available for entity in remaining_locks))

        coordinator.data = coordinator_module.RbwStatusData(
            connected=True,
            status=api.RbwApiStatus(1, "2.40.0", ()),
        )
        coordinator.notify()
        await asyncio.sleep(0)
        self.assertTrue(all(getattr(entity, "removed", False) for entity in remaining_locks))


if __name__ == "__main__":
    unittest.main()

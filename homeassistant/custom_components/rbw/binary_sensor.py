"""Diagnostic connectivity and vault-lock entities for rbw."""

from __future__ import annotations

import hashlib

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import RbwRuntimeData
from .const import DOMAIN
from .coordinator import RbwStatusCoordinator

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up diagnostic binary sensors for one rbw API server."""
    runtime: RbwRuntimeData = hass.data[DOMAIN][entry.entry_id]
    device = DeviceInfo(
        identifiers={(DOMAIN, entry.entry_id)},
        name="rbw",
        manufacturer="rbw",
        model="Policy API",
    )
    async_add_entities([RbwConnectedSensor(runtime.coordinator, entry.entry_id, device)])

    entities: dict[str, RbwVaultLockedSensor] = {}

    def async_update_accounts() -> None:
        """Add newly granted account sensors and remove revoked ones."""
        data = runtime.coordinator.data
        if data is None:
            return
        if data.status is not None:
            accounts = {item.account for item in data.status.accounts}
        elif data.error_code == "status_permission_required":
            accounts = set()
        else:
            return

        removed = entities.keys() - accounts
        for account in removed:
            entity = entities.pop(account)
            hass.async_create_task(entity.async_remove(force_remove=True))

        added = accounts - entities.keys()
        new_entities = [
            RbwVaultLockedSensor(runtime.coordinator, entry.entry_id, device, account)
            for account in sorted(added)
        ]
        entities.update((entity.account, entity) for entity in new_entities)
        if new_entities:
            async_add_entities(new_entities)

    entry.async_on_unload(runtime.coordinator.async_add_listener(async_update_accounts))
    async_update_accounts()


class RbwStatusBinarySensor(CoordinatorEntity[RbwStatusCoordinator], BinarySensorEntity):
    """Base class for rbw diagnostic binary sensors."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: RbwStatusCoordinator,
        entry_id: str,
        device_info: DeviceInfo,
    ) -> None:
        """Initialize the entity with the shared server device."""
        super().__init__(coordinator)
        self._attr_device_info = device_info
        self._attr_unique_id = f"{entry_id}_{self._attr_translation_key}"

    @property
    def available(self) -> bool:
        """Keep connectivity visible after failed polls; show unknown initially."""
        return self.coordinator.data is not None


class RbwConnectedSensor(RbwStatusBinarySensor):
    """Whether the configured rbw API returned an HTTP response."""

    _attr_translation_key = "api_connected"
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_icon = "mdi:cloud-check-outline"

    @property
    def is_on(self) -> bool | None:
        """A denied status request still proves that the endpoint is reachable."""
        if self.coordinator.data is None:
            return None
        return self.coordinator.data.connected


class RbwVaultLockedSensor(RbwStatusBinarySensor):
    """Whether one explicitly granted account is locked."""

    _attr_translation_key = "vault_locked"
    _attr_device_class = BinarySensorDeviceClass.LOCK
    _attr_icon = "mdi:lock-outline"

    def __init__(
        self,
        coordinator: RbwStatusCoordinator,
        entry_id: str,
        device_info: DeviceInfo,
        account: str,
    ) -> None:
        """Initialize an account-specific lock entity."""
        super().__init__(coordinator, entry_id, device_info)
        self.account = account
        account_key = hashlib.sha256(account.encode()).hexdigest()
        self._attr_unique_id = f"{entry_id}_account_{account_key}_vault_locked"
        self._attr_translation_placeholders = {"account": account}

    @property
    def available(self) -> bool:
        """Report unavailable when the account state could not be polled."""
        data = self.coordinator.data
        return (
            data is not None
            and data.status is not None
            and any(status.account == self.account for status in data.status.accounts)
        )

    @property
    def is_on(self) -> bool | None:
        """Return unknown when lock state is not configured or unavailable."""
        if self.coordinator.data is None:
            return None
        return self.coordinator.data.account_locked(self.account)

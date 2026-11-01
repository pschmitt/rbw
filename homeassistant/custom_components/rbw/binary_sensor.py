"""Diagnostic connectivity and vault-lock entities for rbw."""

from __future__ import annotations

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
    async_add_entities(
        [
            RbwConnectedSensor(runtime.coordinator, entry.entry_id, device),
            RbwVaultLockedSensor(runtime.coordinator, entry.entry_id, device),
        ]
    )


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
    """Whether the account scoped to this status grant is locked."""

    _attr_translation_key = "vault_locked"
    _attr_device_class = BinarySensorDeviceClass.LOCK
    _attr_icon = "mdi:lock-outline"

    @property
    def is_on(self) -> bool | None:
        """Return unknown when lock state is not configured or unavailable."""
        if self.coordinator.data is None:
            return None
        return self.coordinator.data.vault_locked

"""Diagnostic API and vault status entities for rbw."""

from __future__ import annotations

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
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
VAULT_STATUS_OPTIONS = [
    "locked",
    "unlocked",
    "unconfigured",
    "status_permission_required",
    "authentication_failed",
    "unavailable",
]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up diagnostic sensors for one rbw API server."""
    runtime: RbwRuntimeData = hass.data[DOMAIN][entry.entry_id]
    device = DeviceInfo(
        identifiers={(DOMAIN, entry.entry_id)},
        name="rbw",
        manufacturer="rbw",
        model="Policy API",
    )
    async_add_entities(
        [
            RbwVaultStatusSensor(runtime.coordinator, entry.entry_id, device),
            RbwApiVersionSensor(runtime.coordinator, entry.entry_id, device),
            RbwAgentVersionSensor(runtime.coordinator, entry.entry_id, device),
        ]
    )


class RbwStatusSensor(CoordinatorEntity[RbwStatusCoordinator], SensorEntity):
    """Base class for rbw diagnostic sensors."""

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


class RbwVaultStatusSensor(RbwStatusSensor):
    """Expose the vault state or why it cannot currently be confirmed."""

    _attr_translation_key = "vault_status"
    _attr_icon = "mdi:shield-key-outline"
    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = VAULT_STATUS_OPTIONS

    @property
    def native_value(self) -> str:
        """Return a safe status value, never an item or account name."""
        if self.coordinator.data is None:
            return "unavailable"
        return self.coordinator.data.vault_status


class RbwApiVersionSensor(RbwStatusSensor):
    """Expose the remote API contract version."""

    _attr_translation_key = "api_version"
    _attr_icon = "mdi:api"

    @property
    def native_value(self) -> int | None:
        """Return the API version only after a permitted status response."""
        if self.coordinator.data is None or self.coordinator.data.status is None:
            return None
        return self.coordinator.data.status.api_version


class RbwAgentVersionSensor(RbwStatusSensor):
    """Expose the remote rbw agent version."""

    _attr_translation_key = "agent_version"
    _attr_icon = "mdi:package-variant"

    @property
    def native_value(self) -> str | None:
        """Return the agent version only after a permitted status response."""
        if self.coordinator.data is None or self.coordinator.data.status is None:
            return None
        return self.coordinator.data.status.agent_version

"""Diagnostic API and vault status entities for rbw."""

from __future__ import annotations

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
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
    """Set up diagnostic sensors for one rbw API server."""
    runtime: RbwRuntimeData = hass.data[DOMAIN][entry.entry_id]
    device = DeviceInfo(
        identifiers={(DOMAIN, entry.entry_id)},
        name="rbw",
        manufacturer="rbw",
        model="Policy API",
        configuration_url=runtime.configuration_url,
    )
    registry = er.async_get(hass)
    for entity in list(registry.entities.values()):
        if (
            entity.config_entry_id == entry.entry_id
            and entity.platform == DOMAIN
            and (
                (
                    entity.unique_id.startswith(f"{entry.entry_id}_account_")
                    and entity.unique_id.endswith("_vault_status")
                )
                or entity.unique_id == f"{entry.entry_id}_agent_version"
            )
        ):
            # The account status sensor is replaced by the lock binary_sensor;
            # the agent version is now shown on the shared device itself.
            registry.async_remove(entity.entity_id)

    async_add_entities(
        [
            RbwApiVersionSensor(runtime.coordinator, entry.entry_id, device),
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

    @property
    def device_info(self) -> DeviceInfo:
        """Expose the running agent version on the shared device."""
        data = self.coordinator.data
        return DeviceInfo(
            identifiers=self._attr_device_info["identifiers"],
            name="rbw",
            manufacturer="rbw",
            model="Policy API",
            configuration_url=self._attr_device_info["configuration_url"],
            sw_version=(
                data.status.agent_version
                if data is not None and data.status is not None
                else None
            ),
        )


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

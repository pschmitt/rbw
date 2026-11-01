"""Diagnostic connectivity and vault-lock entities for rbw."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import slugify

from . import RbwRuntimeData
from .const import DOMAIN
from .coordinator import RbwStatusCoordinator

PARALLEL_UPDATES = 0
_DEFAULT_LOCK_ENTITY_ID = re.compile(r"^binary_sensor\.rbw_lock(?:_[2-9]|_[1-9][0-9]+)?$")


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
        configuration_url=runtime.configuration_url,
    )
    def async_update_device_info() -> None:
        """Update registered device metadata from permitted status data."""
        data = runtime.coordinator.data
        if data is None or data.status is None:
            return
        device_registry = dr.async_get(hass)
        registered_device = device_registry.async_get_device_by_identifier(
            (DOMAIN, entry.entry_id), entry.entry_id
        )
        if registered_device is None:
            return
        updates: dict[str, str] = {}
        if registered_device.sw_version != data.status.agent_version:
            updates["sw_version"] = data.status.agent_version
        if (
            runtime.configuration_url is not None
            and registered_device.configuration_url != runtime.configuration_url
        ):
            updates["configuration_url"] = runtime.configuration_url
        if updates:
            device_registry.async_update_device(registered_device.id, **updates)

    entry.async_on_unload(runtime.coordinator.async_add_listener(async_update_device_info))
    async_update_device_info()
    async_add_entities(
        [
            RbwConnectedSensor(
                runtime.coordinator,
                entry.entry_id,
                device,
                async_update_device_info,
            )
        ]
    )

    entities: dict[str, RbwVaultLockedSensor] = {}

    def async_update_accounts() -> None:
        """Add newly granted account sensors and remove revoked ones."""
        data = runtime.coordinator.data
        if data is None:
            return
        if data.status is not None:
            accounts = {item.account for item in data.status.accounts}
        else:
            # Errors and missing status permission are not evidence that grants
            # were revoked. Keep registry entries until a successful status poll.
            return

        removed = entities.keys() - accounts
        for account in removed:
            entity = entities.pop(account)
            hass.async_create_task(entity.async_remove(force_remove=True))

        added = accounts - entities.keys()
        account_object_ids = _account_object_ids(accounts)
        new_entities = [
            RbwVaultLockedSensor(
                runtime.coordinator,
                entry.entry_id,
                device,
                account,
                account_object_ids[account],
            )
            for account in sorted(added)
        ]
        entities.update((entity.account, entity) for entity in new_entities)
        if new_entities:
            async_add_entities(new_entities)

        live_unique_ids = {
            f"{entry.entry_id}_account_{hashlib.sha256(account.encode()).hexdigest()}_vault_locked"
            for account in accounts
        }
        removed_unique_ids = {
            f"{entry.entry_id}_account_{hashlib.sha256(account.encode()).hexdigest()}_vault_locked"
            for account in removed
        }
        registry = er.async_get(hass)
        for registered in list(registry.entities.values()):
            if (
                registered.config_entry_id == entry.entry_id
                and registered.platform == DOMAIN
                and registered.entity_id.startswith("binary_sensor.")
                and registered.unique_id.startswith(f"{entry.entry_id}_account_")
                and registered.unique_id.endswith("_vault_locked")
                and registered.unique_id not in live_unique_ids
                and registered.unique_id not in removed_unique_ids
            ):
                # It may be absent from this runtime after a restart; only
                # prune it after a successful account list.
                registry.async_remove(registered.entity_id)

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

    @property
    def available(self) -> bool:
        """Keep connectivity visible after failed polls; show unknown initially."""
        return self.coordinator.data is not None


class RbwConnectedSensor(RbwStatusBinarySensor):
    """Whether the configured rbw API returned an HTTP response."""

    _attr_translation_key = "api_connected"
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_icon = "mdi:cloud-check-outline"

    def __init__(
        self,
        coordinator: RbwStatusCoordinator,
        entry_id: str,
        device_info: DeviceInfo,
        update_device_info: Callable[[], None],
    ) -> None:
        """Initialize the entity and metadata refresh callback."""
        super().__init__(coordinator, entry_id, device_info)
        self._update_device_info = update_device_info

    async def async_added_to_hass(self) -> None:
        """Apply metadata when the device registry entry actually exists."""
        await super().async_added_to_hass()
        self._update_device_info()

    def async_entity_id_changed(self, old_entity_id: str) -> None:
        """Handle in-place registry ID changes in current Home Assistant."""
        super().async_entity_id_changed(old_entity_id)

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
        object_id: str,
    ) -> None:
        """Initialize an account-specific lock entity."""
        super().__init__(coordinator, entry_id, device_info)
        self.account = account
        account_key = hashlib.sha256(account.encode()).hexdigest()
        self._attr_unique_id = f"{entry_id}_account_{account_key}_vault_locked"
        self._attr_translation_placeholders = {"account": account}
        self._object_id = object_id

    async def async_added_to_hass(self) -> None:
        """Use a readable account-specific ID and retain the registry entry."""
        await super().async_added_to_hass()
        registry = er.async_get(self.hass)
        current = registry.async_get(self.entity_id)
        target = f"binary_sensor.{self._object_id}"
        occupied = registry.async_get(target)
        if occupied is not None and occupied.unique_id != self.unique_id:
            target = (
                f"binary_sensor.{self._object_id}_"
                f"{hashlib.sha256(self.account.encode()).hexdigest()[:8]}"
            )
        if (
            current is not None
            and current.entity_id != target
            and _DEFAULT_LOCK_ENTITY_ID.fullmatch(current.entity_id)
        ):
            # Updating the existing registry entry preserves its name, area,
            # disabled/hidden state, labels, and other user customizations.
            registry.async_update_entity(current.entity_id, new_entity_id=target)

    def async_entity_id_changed(self, old_entity_id: str) -> None:
        """Handle in-place registry ID migration in current Home Assistant."""
        super().async_entity_id_changed(old_entity_id)

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


def _account_object_ids(accounts: set[str]) -> dict[str, str]:
    """Build readable stable IDs, adding a digest only for slug collisions."""
    slugs = {
        account: (slugify(account, separator="_") or "account")[:48].rstrip("_")
        for account in accounts
    }
    counts = {slug: list(slugs.values()).count(slug) for slug in set(slugs.values())}
    return {
        account: (
            f"rbw_{slug}_{hashlib.sha256(account.encode()).hexdigest()[:8]}_locked"
            if counts[slug] > 1 or len(slugify(account, separator="_") or "account") > 48
            else f"rbw_{slug}_locked"
        )
        for account, slug in slugs.items()
    }

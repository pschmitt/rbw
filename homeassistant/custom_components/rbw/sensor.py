"""Cleanup obsolete rbw diagnostic sensors after device metadata migration."""

from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Remove per-account and version sensors now represented elsewhere."""
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
                or entity.unique_id
                in {
                    f"{entry.entry_id}_agent_version",
                    f"{entry.entry_id}_api_version",
                }
            )
        ):
            registry.async_remove(entity.entity_id)

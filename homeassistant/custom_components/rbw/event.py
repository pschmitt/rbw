"""Audit event entity for rbw credential, passkey, and vault activity."""

from __future__ import annotations

from collections import deque
from typing import Any

from homeassistant.components.event import EventEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import RbwRuntimeData
from .api import RbwAuditEvent
from .const import DOMAIN
from .coordinator import RbwStatusCoordinator

PARALLEL_UPDATES = 0
_MAX_SEEN_EVENTS = 256

EVENT_CREDENTIAL_READ = "credential_read"
EVENT_TOTP_READ = "totp_read"
EVENT_PASSKEY_USED = "passkey_used"
EVENT_PASSKEY_CREATED = "passkey_created"
EVENT_SECRET_COPIED = "secret_copied"
EVENT_SSH_SIGNED = "ssh_signed"
EVENT_ATTACHMENT_READ = "attachment_read"
EVENT_VAULT_UNLOCKED = "vault_unlocked"
EVENT_VAULT_LOCKED = "vault_locked"
EVENT_ACCESS_DENIED = "access_denied"

AUDIT_EVENT_TYPES: list[str] = [
    EVENT_CREDENTIAL_READ,
    EVENT_TOTP_READ,
    EVENT_PASSKEY_USED,
    EVENT_PASSKEY_CREATED,
    EVENT_SECRET_COPIED,
    EVENT_SSH_SIGNED,
    EVENT_ATTACHMENT_READ,
    EVENT_VAULT_UNLOCKED,
    EVENT_VAULT_LOCKED,
    EVENT_ACCESS_DENIED,
]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the rbw audit event entity for one API server."""
    runtime: RbwRuntimeData = hass.data[DOMAIN][entry.entry_id]
    device = DeviceInfo(
        identifiers={(DOMAIN, entry.entry_id)},
        name="rbw",
        manufacturer="rbw",
        model="Policy API",
    )
    if runtime.configuration_url is not None:
        device["configuration_url"] = runtime.configuration_url
    async_add_entities([RbwAuditEventEntity(runtime.coordinator, entry.entry_id, device)])


class RbwAuditEventEntity(CoordinatorEntity[RbwStatusCoordinator], EventEntity):
    """Event entity that fires on notable rbw credential, passkey, and lock actions."""

    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_has_entity_name = True
    _attr_translation_key = "audit"
    _attr_icon = "mdi:shield-search"
    _attr_event_types = AUDIT_EVENT_TYPES

    def __init__(
        self,
        coordinator: RbwStatusCoordinator,
        entry_id: str,
        device_info: DeviceInfo,
    ) -> None:
        """Initialize the audit event entity."""
        super().__init__(coordinator)
        self._attr_device_info = device_info
        self._attr_unique_id = f"{entry_id}_audit"
        self.entity_id = "event.rbw_audit"
        self._initialized = False
        self._seen_order: deque[RbwAuditEvent] = deque()
        self._seen: set[RbwAuditEvent] = set()
        self._sync_from_coordinator(write_state=False)

    @property
    def device_info(self) -> DeviceInfo:
        """Expose the running agent version on the shared device."""
        data = self.coordinator.data
        values: dict[str, str | set[tuple[str, str]]] = {
            "identifiers": self._attr_device_info["identifiers"],
            "name": "rbw",
            "manufacturer": "rbw",
            "model": "Policy API",
        }
        if configuration_url := self._attr_device_info.get("configuration_url"):
            values["configuration_url"] = configuration_url
        if data is not None and data.status is not None:
            values["sw_version"] = data.status.agent_version
            values["model_id"] = f"API v{data.status.api_version}"
        return DeviceInfo(**values)

    @property
    def available(self) -> bool:
        """Report available whenever status polling has succeeded."""
        data = self.coordinator.data
        return data is not None and data.status is not None

    @callback
    def _handle_coordinator_update(self) -> None:
        """Emit newly observed audit events in chronological order."""
        self._sync_from_coordinator(write_state=True)
        super()._handle_coordinator_update()

    def _remember(self, event: RbwAuditEvent) -> None:
        if event in self._seen:
            return
        if len(self._seen_order) >= _MAX_SEEN_EVENTS:
            oldest = self._seen_order.popleft()
            self._seen.discard(oldest)
        self._seen_order.append(event)
        self._seen.add(event)

    def _sync_from_coordinator(self, *, write_state: bool) -> None:
        data = self.coordinator.data
        if data is None or data.status is None:
            return
        events = data.status.events
        if not self._initialized:
            self._initialized = True
            for event in events:
                self._remember(event)
            if events:
                self._emit_audit_event(events[-1], write_state=False)
            return

        new_events = [event for event in events if event not in self._seen]
        for index, event in enumerate(new_events):
            self._remember(event)
            # Intermediate events write immediately so Home Assistant records
            # every distinct event; the final state write is handled by
            # CoordinatorEntity._handle_coordinator_update.
            self._emit_audit_event(
                event,
                write_state=write_state and index < len(new_events) - 1,
            )

    def _emit_audit_event(self, event: RbwAuditEvent, *, write_state: bool) -> None:
        event_type, attributes = classify_audit_event(event)
        self._trigger_event(event_type, attributes)
        if write_state and getattr(self, "hass", None) is not None:
            self.async_write_ha_state()


def classify_audit_event(event: RbwAuditEvent) -> tuple[str, dict[str, Any]]:
    """Map one sanitized audit log record to an EventEntity type and attributes."""
    if event.outcome != "allowed" or event.operation in ("denied", "reprompt_denied"):
        event_type = EVENT_ACCESS_DENIED
    elif event.operation in ("code", "browser.totp"):
        event_type = EVENT_TOTP_READ
    elif event.operation in ("get", "api.field_read", "browser.credential"):
        event_type = EVENT_TOTP_READ if event.field == "totp" else EVENT_CREDENTIAL_READ
    elif event.operation in ("passkey assert", "passkey inject", "browser.passkey_get"):
        event_type = EVENT_PASSKEY_USED
    elif event.operation == "browser.passkey_create":
        event_type = EVENT_PASSKEY_CREATED
    elif event.operation in ("secret_to_file", "browser.copy"):
        event_type = EVENT_SECRET_COPIED
    elif event.operation == "ssh_agent.sign":
        event_type = EVENT_SSH_SIGNED
    elif event.operation == "attachment_download":
        event_type = EVENT_ATTACHMENT_READ
    elif event.operation in ("unlock", "api.unlock"):
        event_type = EVENT_VAULT_UNLOCKED
    elif event.operation in ("lock", "agent.lock"):
        event_type = EVENT_VAULT_LOCKED
    else:
        event_type = EVENT_CREDENTIAL_READ

    consumer = event.client or event.actor
    attributes: dict[str, Any] = {
        "timestamp": event.timestamp,
        "actor": event.actor,
        "consumer": consumer,
        "operation": event.operation,
        "outcome": event.outcome,
        "account": event.account,
        "item_id": event.item_id,
        "item_name": event.item_name,
        "field": event.field,
        "origin": event.origin,
        "reason": event.reason,
        "summary": _format_summary(event, event_type),
    }
    return event_type, attributes


def _format_summary(event: RbwAuditEvent, event_type: str) -> str:
    """Build a human-readable one-line summary without exposing any secret value."""
    who = (
        f"{event.actor} ({event.client})"
        if event.client and event.client != event.actor
        else (event.client or event.actor)
    )
    target = event.item_name or event.item_id
    account_suffix = f" [{event.account}]" if event.account else ""
    origin_suffix = f" on {event.origin}" if event.origin else ""

    if event_type == EVENT_ACCESS_DENIED:
        detail = f" ({event.reason})" if event.reason else ""
        target_part = f" on {target}" if target else ""
        return f"{who} denied {event.operation}{target_part}{origin_suffix}{account_suffix}{detail}"
    if event_type == EVENT_PASSKEY_USED:
        target_part = f" for {target}" if target else ""
        return f"{who} used passkey{target_part}{origin_suffix}{account_suffix}"
    if event_type == EVENT_PASSKEY_CREATED:
        target_part = f" for {target}" if target else ""
        return f"{who} registered passkey{target_part}{origin_suffix}{account_suffix}"
    if event_type == EVENT_TOTP_READ:
        target_part = f" for {target}" if target else ""
        return f"{who} read TOTP{target_part}{origin_suffix}{account_suffix}"
    if event_type == EVENT_SSH_SIGNED:
        target_part = f" {target}" if target else ""
        return f"{who} signed with SSH key{target_part}{account_suffix}"
    if event_type == EVENT_SECRET_COPIED:
        field_part = f" {event.field}" if event.field else " secret"
        target_part = f" from {target}" if target else ""
        return f"{who} copied{field_part}{target_part}{origin_suffix}{account_suffix}"
    if event_type == EVENT_ATTACHMENT_READ:
        target_part = f" from {target}" if target else ""
        return f"{who} downloaded attachment{target_part}{account_suffix}"
    if event_type == EVENT_VAULT_UNLOCKED:
        return f"{who} unlocked vault{account_suffix}"
    if event_type == EVENT_VAULT_LOCKED:
        return f"{who} locked vault{account_suffix}"

    field_part = event.field or "credentials"
    target_part = f" from {target}" if target else ""
    return f"{who} read {field_part}{target_part}{origin_suffix}{account_suffix}"

"""Which Home Assistant integrations may read which vault items through this client.

All integrations share one mTLS client, whose field grants the rbw API enforces. This adds
what the API cannot see: deny by default, per integration. Integrations share a process, so
it stops mistakes and overreach, not hostile code; the server-side grants remain the boundary.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from typing import Any

from .const import CONF_ACCESS, DOMAIN, ISSUE_ACCESS_REQUEST

CONF_RBW_ENTRY_ID = "rbw_entry_id"
CONF_RBW_ITEM_ID = "rbw_item_id"


def consumer_domain(consumer: str | None) -> str | None:
    """The integration's domain from a module-style consumer name."""
    return consumer.rsplit(".", 1)[-1] or None if consumer else None


def is_allowed(options: Mapping[str, Any], domain: str | None, item_id: str) -> bool:
    return bool(domain) and item_id in options.get(CONF_ACCESS, {}).get(domain, ())


def with_items(options: Mapping[str, Any], domain: str, items: Iterable[str]) -> dict[str, Any]:
    """New options with this integration's items replaced; no items removes it."""
    access = dict(options.get(CONF_ACCESS, {}))
    access.pop(domain, None)
    if chosen := sorted({item.strip() for item in items if item.strip()}):
        access[domain] = chosen
    return {**options, CONF_ACCESS: access}


def with_item(options: Mapping[str, Any], domain: str, item_id: str) -> dict[str, Any]:
    """New options that also allow this item for this integration."""
    return with_items(options, domain, [*options.get(CONF_ACCESS, {}).get(domain, ()), item_id])


def configured_items(entries: Iterable[Any], entry_id: str) -> dict[str, list[str]]:
    """The items other config entries were set up to read through this rbw entry."""
    found: dict[str, set[str]] = {}
    for entry in entries:
        if entry.domain == DOMAIN:
            continue
        settings = {**entry.data, **entry.options}
        item = settings.get(CONF_RBW_ITEM_ID)
        if item and settings.get(CONF_RBW_ENTRY_ID) == entry_id:
            found.setdefault(entry.domain, set()).add(item)
    return {domain: sorted(items) for domain, items in found.items()}


def request_issue_id(entry_id: str, domain: str, item_id: str) -> str:
    key = hashlib.sha256(f"{domain}\0{item_id}".encode()).hexdigest()[:12]
    return f"{ISSUE_ACCESS_REQUEST}_{entry_id}_{key}"

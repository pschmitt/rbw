"""mTLS client for rbw item reads and safe API status."""

from __future__ import annotations

import asyncio
import json
import os
import re
import ssl
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote, urlsplit

import aiohttp


class RbwApiError(Exception):
    """An API error safe to show in Home Assistant logs and repairs."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        retryable: bool,
        authentication_error: bool = False,
        retry_after_seconds: float | None = None,
        http_status: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable
        self.authentication_error = authentication_error
        self.retry_after_seconds = retry_after_seconds
        self.http_status = http_status


@dataclass(frozen=True, slots=True)
class RbwAccountStatus:
    """Lock state for one explicitly status-granted account."""

    account: str
    state: Literal["locked", "unlocked", "unconfigured"]


@dataclass(frozen=True, slots=True)
class RbwAuditEvent:
    """One non-secret security audit event returned by the rbw API."""

    timestamp: str
    actor: str
    operation: str
    outcome: str
    item_id: str | None = None
    item_name: str | None = None
    account: str | None = None
    field: str | None = None
    origin: str | None = None
    reason: str | None = None
    version: str | None = None
    client: str | None = None


@dataclass(frozen=True, slots=True)
class RbwApiStatus:
    """Safe, non-secret status returned by the API."""

    api_version: int
    agent_version: str
    accounts: tuple[RbwAccountStatus, ...]
    events: tuple[RbwAuditEvent, ...] = ()


class RbwApiClient:
    """Read individual item fields using a client certificate identity."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        ssl_context: ssl.SSLContext | None,
    ) -> None:
        self._session = session
        self._base_url = base_url.rstrip("/")
        self._ssl_context = ssl_context
        self._not_before_until = 0.0

    @staticmethod
    def validate_base_url(base_url: str) -> str:
        """Validate and normalize an HTTPS API origin."""
        parsed = urlsplit(base_url.strip())
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Enter an HTTPS origin without credentials, path, query, or fragment")
        return base_url.strip().rstrip("/")

    @staticmethod
    def create_ssl_context(
        ca_cert: str,
        client_cert: str,
        client_key: str,
    ) -> ssl.SSLContext:
        """Load the CA and mTLS identity from local PEM files."""
        for value, label in (
            (ca_cert, "CA certificate"),
            (client_cert, "client certificate"),
            (client_key, "client private key"),
        ):
            if not value or not Path(value).is_file():
                raise ValueError(f"The {label} file does not exist")

        if os.name == "posix" and stat.S_IMODE(Path(client_key).stat().st_mode) & 0o077:
            raise ValueError(
                "The client private key file must not be accessible by group or others"
            )

        context = ssl.create_default_context(cafile=ca_cert)
        context.load_cert_chain(certfile=client_cert, keyfile=client_key)
        return context

    async def async_get_field(
        self,
        item_id: str,
        field_id: str,
        *,
        consumer: str | None = None,
    ) -> dict[str, str | bool | None]:
        """Return one explicitly requested field without retaining it."""
        if not item_id or not field_id:
            raise RbwApiError("invalid_request", "Item and field IDs are required", retryable=False)
        if self._ssl_context is None:
            raise RbwApiError(
                "client_certificate",
                "The mTLS client certificate configuration needs attention",
                retryable=False,
                authentication_error=True,
            )

        await self._async_wait_for_retry_after()

        url = (
            f"{self._base_url}/v1/items/{quote(item_id, safe='')}"
            f"/fields/{'/'.join(quote(part, safe='') for part in field_id.split('/'))}"
        )
        request_kwargs: dict[str, object] = {"ssl": self._ssl_context}
        if consumer:
            request_kwargs["headers"] = {"X-Rbw-Consumer": consumer}
        try:
            async with asyncio.timeout(5):
                async with self._session.get(url, **request_kwargs) as response:
                    try:
                        payload = await response.json(content_type="application/json")
                    except (aiohttp.ContentTypeError, json.JSONDecodeError):
                        raise RbwApiError(
                            "invalid_response",
                            "The rbw API returned an invalid response",
                            retryable=True,
                        ) from None

                    if response.status >= 400:
                        code = payload.get("code") if isinstance(payload, dict) else None
                        if not isinstance(code, str) or not re.fullmatch(
                            r"[a-z][a-z0-9_]{0,63}", code
                        ):
                            code = f"http_{response.status}"
                        payload_retryable = (
                            payload.get("retryable") if isinstance(payload, dict) else None
                        )
                        retryable = (
                            payload_retryable
                            if isinstance(payload_retryable, bool)
                            else response.status in (423, 503)
                        )
                        if code == "reauthentication_required":
                            retryable = False
                        retry_after: float | None = None
                        if retryable:
                            try:
                                retry_after = min(
                                    60.0,
                                    max(
                                        0.0,
                                        float(response.headers.get("Retry-After", "0")),
                                    ),
                                )
                            except ValueError:
                                retry_after = None
                            if retry_after is not None:
                                self._not_before_until = max(
                                    self._not_before_until,
                                    time.monotonic() + retry_after,
                                )
                        raise RbwApiError(
                            code,
                            "The rbw API request failed",
                            retryable=retryable,
                            authentication_error=response.status == 401,
                            retry_after_seconds=retry_after,
                            http_status=response.status,
                        )

                    if (
                        not isinstance(payload, dict)
                        or payload.get("field") != field_id
                        or (
                            payload.get("value") is not None
                            and not isinstance(payload.get("value"), str)
                        )
                        or not isinstance(payload.get("sensitive"), bool)
                    ):
                        raise RbwApiError(
                            "invalid_response",
                            "The rbw API returned an invalid response",
                            retryable=True,
                        )
                    return {
                        "field": field_id,
                        "value": payload["value"],
                        "sensitive": payload["sensitive"],
                    }
        except TimeoutError:
            raise RbwApiError("timeout", "The rbw API request timed out", retryable=True) from None
        except aiohttp.ClientSSLError:
            raise RbwApiError(
                "tls_error",
                "TLS verification or client authentication failed",
                retryable=False,
                authentication_error=True,
            ) from None
        except aiohttp.ClientError:
            raise RbwApiError(
                "connection_error", "Could not connect to the rbw API", retryable=True
            ) from None

    async def async_list_items(self, *, consumer: str | None = None) -> list[dict[str, Any]]:
        """Return the items this client has grants for, without any field values."""
        if self._ssl_context is None:
            raise RbwApiError(
                "client_certificate",
                "The mTLS client certificate configuration needs attention",
                retryable=False,
                authentication_error=True,
            )
        await self._async_wait_for_retry_after()
        kwargs: dict[str, object] = {"ssl": self._ssl_context}
        if consumer:
            kwargs["headers"] = {"X-Rbw-Consumer": consumer}
        invalid = RbwApiError(
            "invalid_response", "The rbw API returned an invalid response", retryable=True
        )
        try:
            async with asyncio.timeout(5):
                async with self._session.get(f"{self._base_url}/v1/items", **kwargs) as response:
                    if response.status >= 400:
                        raise RbwApiError(
                            f"http_{response.status}",
                            "The rbw API request failed",
                            retryable=response.status in (423, 503),
                            authentication_error=response.status == 401,
                            http_status=response.status,
                        )
                    try:
                        payload = await response.json(content_type="application/json")
                    except (aiohttp.ContentTypeError, json.JSONDecodeError):
                        raise invalid from None
        except (TimeoutError, aiohttp.ClientError):
            raise RbwApiError("unavailable", "The rbw API is unavailable", retryable=True) from None
        items = payload.get("items") if isinstance(payload, dict) else None
        if not isinstance(items, list) or not all(
            isinstance(item, dict)
            and isinstance(item.get("id"), str)
            and isinstance(item.get("name"), str | None)
            and isinstance(item.get("fields"), list)
            for item in items
        ):
            raise invalid
        return [{"id": i["id"], "name": i["name"], "fields": i["fields"]} for i in items]

    async def async_get_status(self) -> RbwApiStatus:
        """Return safe API and vault status for a client with status permission."""
        if self._ssl_context is None:
            raise RbwApiError(
                "client_certificate",
                "The mTLS client certificate configuration needs attention",
                retryable=False,
                authentication_error=True,
            )

        await self._async_wait_for_retry_after()
        url = f"{self._base_url}/v1/status"
        try:
            async with asyncio.timeout(5):
                async with self._session.get(url, ssl=self._ssl_context) as response:
                    try:
                        payload = await response.json(content_type="application/json")
                    except (aiohttp.ContentTypeError, json.JSONDecodeError):
                        raise RbwApiError(
                            "invalid_response",
                            "The rbw API returned an invalid response",
                            retryable=True,
                            http_status=response.status,
                        ) from None

                    if response.status >= 400:
                        code = payload.get("code") if isinstance(payload, dict) else None
                        if not isinstance(code, str) or not re.fullmatch(
                            r"[a-z][a-z0-9_]{0,63}", code
                        ):
                            code = f"http_{response.status}"
                        payload_retryable = (
                            payload.get("retryable") if isinstance(payload, dict) else None
                        )
                        retryable = (
                            payload_retryable
                            if isinstance(payload_retryable, bool)
                            else response.status in (423, 503)
                        )
                        retry_after: float | None = None
                        if retryable:
                            try:
                                retry_after = min(
                                    60.0,
                                    max(0.0, float(response.headers.get("Retry-After", "0"))),
                                )
                            except ValueError:
                                retry_after = None
                            if retry_after is not None:
                                self._not_before_until = max(
                                    self._not_before_until,
                                    time.monotonic() + retry_after,
                                )
                        raise RbwApiError(
                            code,
                            "The rbw API request failed",
                            retryable=retryable,
                            authentication_error=response.status == 401,
                            retry_after_seconds=retry_after,
                            http_status=response.status,
                        )

                    if (
                        not isinstance(payload, dict)
                        or not {"apiVersion", "agentVersion", "accounts"}.issubset(payload)
                        or not set(payload).issubset(
                            {"apiVersion", "agentVersion", "accounts", "events"}
                        )
                    ):
                        raise RbwApiError(
                            "invalid_response",
                            "The rbw API returned an invalid status response",
                            retryable=True,
                            http_status=response.status,
                        )

                    api_version = payload.get("apiVersion")
                    agent_version = payload.get("agentVersion")
                    accounts_payload = payload.get("accounts")
                    accounts: list[RbwAccountStatus] = []
                    seen_accounts: set[str] = set()
                    if isinstance(accounts_payload, list):
                        for item in accounts_payload:
                            if not isinstance(item, dict) or set(item) != {"account", "state"}:
                                raise RbwApiError(
                                    "invalid_response",
                                    "The rbw API returned an invalid status response",
                                    retryable=True,
                                    http_status=response.status,
                                )
                            account = item["account"]
                            state = item["state"]
                            if (
                                not isinstance(account, str)
                                or not account
                                or len(account) > 128
                                or account != account.strip()
                                or any(ord(char) < 32 or ord(char) == 127 for char in account)
                                or account in seen_accounts
                                or state not in ("locked", "unlocked", "unconfigured")
                            ):
                                raise RbwApiError(
                                    "invalid_response",
                                    "The rbw API returned an invalid status response",
                                    retryable=True,
                                    http_status=response.status,
                                )
                            seen_accounts.add(account)
                            accounts.append(RbwAccountStatus(account, state))
                    events_payload = payload.get("events", [])
                    events: list[RbwAuditEvent] = []
                    if not isinstance(events_payload, list):
                        raise RbwApiError(
                            "invalid_response",
                            "The rbw API returned an invalid status response",
                            retryable=True,
                            http_status=response.status,
                        )
                    for raw_event in events_payload:
                        if not isinstance(raw_event, dict):
                            continue
                        timestamp = raw_event.get("timestamp")
                        actor = raw_event.get("actor")
                        operation = raw_event.get("operation")
                        outcome = raw_event.get("outcome")
                        if not all(
                            isinstance(val, str) and val
                            for val in (timestamp, actor, operation, outcome)
                        ):
                            continue
                        events.append(
                            RbwAuditEvent(
                                timestamp=timestamp,
                                actor=actor,
                                operation=operation,
                                outcome=outcome,
                                item_id=_optional_str(raw_event.get("item_id")),
                                item_name=_optional_str(raw_event.get("item_name")),
                                account=_optional_str(raw_event.get("account")),
                                field=_optional_str(raw_event.get("field")),
                                origin=_optional_str(raw_event.get("origin")),
                                reason=_optional_str(raw_event.get("reason")),
                                version=_optional_str(raw_event.get("version")),
                                client=_optional_str(raw_event.get("client")),
                            )
                        )
                    if (
                        isinstance(api_version, bool)
                        or not isinstance(api_version, int)
                        or api_version < 1
                        or not isinstance(agent_version, str)
                        or not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+-]{0,63}", agent_version)
                        or not isinstance(accounts_payload, list)
                    ):
                        raise RbwApiError(
                            "invalid_response",
                            "The rbw API returned an invalid status response",
                            retryable=True,
                            http_status=response.status,
                        )
                    return RbwApiStatus(
                        api_version,
                        agent_version,
                        tuple(accounts),
                        tuple(events),
                    )
        except TimeoutError:
            raise RbwApiError("timeout", "The rbw API request timed out", retryable=True) from None
        except aiohttp.ClientSSLError:
            raise RbwApiError(
                "tls_error",
                "TLS verification or client authentication failed",
                retryable=False,
                authentication_error=True,
            ) from None
        except aiohttp.ClientError:
            raise RbwApiError(
                "connection_error", "Could not connect to the rbw API", retryable=True
            ) from None

    async def async_unlock(
        self,
        password: str,
        *,
        account: str = "default",
        consumer: str | None = None,
    ) -> RbwAccountStatus:
        """Unlock an explicitly authorized account on the rbw agent."""
        if not password or not account or not account.strip():
            raise RbwApiError(
                "invalid_request",
                "Account and master password are required",
                retryable=False,
            )
        if self._ssl_context is None:
            raise RbwApiError(
                "client_certificate",
                "The mTLS client certificate configuration needs attention",
                retryable=False,
                authentication_error=True,
            )

        await self._async_wait_for_retry_after()
        url = f"{self._base_url}/v1/unlock"
        request_kwargs: dict[str, object] = {
            "ssl": self._ssl_context,
            "json": {"account": account.strip(), "password": password},
        }
        if consumer:
            request_kwargs["headers"] = {"X-Rbw-Consumer": consumer}
        try:
            async with asyncio.timeout(15):
                async with self._session.post(url, **request_kwargs) as response:
                    try:
                        payload = await response.json(content_type="application/json")
                    except (aiohttp.ContentTypeError, json.JSONDecodeError):
                        raise RbwApiError(
                            "invalid_response",
                            "The rbw API returned an invalid response",
                            retryable=True,
                            http_status=response.status,
                        ) from None

                    if response.status >= 400:
                        code = payload.get("code") if isinstance(payload, dict) else None
                        if not isinstance(code, str) or not re.fullmatch(
                            r"[a-z][a-z0-9_]{0,63}", code
                        ):
                            code = f"http_{response.status}"
                        payload_retryable = (
                            payload.get("retryable") if isinstance(payload, dict) else None
                        )
                        retryable = (
                            payload_retryable
                            if isinstance(payload_retryable, bool)
                            else response.status in (423, 503)
                        )
                        if code == "invalid_password":
                            retryable = False
                        raise RbwApiError(
                            code,
                            "The rbw API unlock request failed",
                            retryable=retryable,
                            authentication_error=response.status == 401,
                            http_status=response.status,
                        )

                    if (
                        not isinstance(payload, dict)
                        or set(payload) != {"account", "state"}
                        or not isinstance(payload.get("account"), str)
                        or payload.get("state") not in ("locked", "unlocked", "unconfigured")
                    ):
                        raise RbwApiError(
                            "invalid_response",
                            "The rbw API returned an invalid unlock response",
                            retryable=True,
                            http_status=response.status,
                        )
                    return RbwAccountStatus(payload["account"], payload["state"])
        except TimeoutError:
            raise RbwApiError("timeout", "The rbw API request timed out", retryable=True) from None
        except aiohttp.ClientSSLError:
            raise RbwApiError(
                "tls_error",
                "TLS verification or client authentication failed",
                retryable=False,
                authentication_error=True,
            ) from None
        except aiohttp.ClientError:
            raise RbwApiError(
                "connection_error", "Could not connect to the rbw API", retryable=True
            ) from None

    async def _async_wait_for_retry_after(self) -> None:
        """Avoid issuing requests before the server's retry deadline."""
        if self._not_before_until:
            delay = self._not_before_until - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)
            self._not_before_until = 0.0


def _optional_str(value: object) -> str | None:
    """Return a non-empty string without control characters, or None."""
    if not isinstance(value, str):
        return None
    cleaned = "".join(ch for ch in value if ord(ch) >= 32 and ord(ch) != 127).strip()
    return cleaned[:128] if cleaned else None

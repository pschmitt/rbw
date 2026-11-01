"""mTLS client for the rbw policy API."""

from __future__ import annotations

import asyncio
import json
import os
import re
import ssl
import stat
import time
from pathlib import Path
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
    ) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable
        self.authentication_error = authentication_error
        self.retry_after_seconds = retry_after_seconds


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

    async def async_get_field(self, item_id: str, field_id: str) -> dict[str, str | bool | None]:
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

        if self._not_before_until:
            delay = self._not_before_until - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)
            self._not_before_until = 0.0

        url = (
            f"{self._base_url}/v1/items/{quote(item_id, safe='')}"
            f"/fields/{'/'.join(quote(part, safe='') for part in field_id.split('/'))}"
        )
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

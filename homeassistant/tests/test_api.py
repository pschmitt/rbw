"""Tests for the mTLS API client, isolated from Home Assistant startup."""

from __future__ import annotations

import importlib.util
import ssl
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

API_PATH = Path(__file__).parents[1] / "custom_components" / "rbw" / "api.py"
SPEC = importlib.util.spec_from_file_location("rbw_test_api", API_PATH)
assert SPEC and SPEC.loader
api = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(api)


class FakeResponse:
    def __init__(
        self,
        status: int,
        payload: dict[str, object],
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status = status
        self.payload = payload
        self.headers = headers or {}

    async def __aenter__(self) -> FakeResponse:
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    async def json(self, content_type: str) -> dict[str, object]:
        return self.payload


class FakeSession:
    def __init__(self, *responses: FakeResponse) -> None:
        self.responses = list(responses)
        self.requests: list[tuple[str, dict[str, object]]] = []

    def get(self, url: str, **kwargs: object) -> FakeResponse:
        self.requests.append((url, kwargs))
        return self.responses.pop(0)


def success(field_id: str, value: str | None, *, sensitive: bool = True) -> FakeResponse:
    return FakeResponse(
        200,
        {"field": field_id, "value": value, "sensitive": sensitive},
    )


class RbwApiClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_custom_field_path_is_encoded_and_mtls_context_is_passed(self) -> None:
        session = FakeSession(success("custom/Work email", "secret-value"))
        context = ssl.create_default_context()
        client = api.RbwApiClient(session, "https://vault.example", context)

        result = await client.async_get_field("item/id 1", "custom/Work email")

        self.assertEqual(
            result,
            {"field": "custom/Work email", "value": "secret-value", "sensitive": True},
        )
        url, kwargs = session.requests[0]
        self.assertEqual(
            url,
            "https://vault.example/v1/items/item%2Fid%201/fields/custom/Work%20email",
        )
        self.assertIs(kwargs["ssl"], context)
        self.assertEqual(len(session.requests), 1)

    async def test_nested_field_tokens_use_backend_catch_all_segments(self) -> None:
        session = FakeSession(
            success("uri/0", "https://example.test"), success("identity/first_name", "Ada")
        )
        client = api.RbwApiClient(session, "https://vault.example", ssl.create_default_context())

        await client.async_get_field("item-id", "uri/0")
        await client.async_get_field("item-id", "identity/first_name")

        self.assertTrue(session.requests[0][0].endswith("/fields/uri/0"))
        self.assertTrue(session.requests[1][0].endswith("/fields/identity/first_name"))

    async def test_totp_response_preserves_value_and_sensitivity_metadata(self) -> None:
        session = FakeSession(success("totp", "9B72M"))
        client = api.RbwApiClient(session, "https://vault.example", ssl.create_default_context())

        result = await client.async_get_field("item-id", "totp")

        self.assertEqual(result, {"field": "totp", "value": "9B72M", "sensitive": True})
        self.assertTrue(session.requests[0][0].endswith("/items/item-id/fields/totp"))

    async def test_retry_after_is_honored_before_next_request(self) -> None:
        session = FakeSession(
            FakeResponse(
                423,
                {"code": "vault_locked", "message": "Vault is locked", "retryable": True},
                {"Retry-After": "5"},
            ),
            success("password", "secret-value"),
        )
        client = api.RbwApiClient(session, "https://vault.example", ssl.create_default_context())

        with self.assertRaises(api.RbwApiError) as raised:
            await client.async_get_field("item-id", "password")
        self.assertTrue(raised.exception.retryable)
        self.assertEqual(raised.exception.retry_after_seconds, 5)

        with patch.object(api.asyncio, "sleep", new_callable=AsyncMock) as sleep:
            await client.async_get_field("item-id", "password")

        sleep.assert_awaited_once()
        self.assertGreater(sleep.await_args.args[0], 4.9)
        self.assertLessEqual(sleep.await_args.args[0], 5)
        self.assertEqual(len(session.requests), 2)

    async def test_unauthorized_response_is_a_permanent_auth_failure(self) -> None:
        session = FakeSession(
            FakeResponse(
                401,
                {"code": "client_revoked", "message": "safe", "retryable": False},
            )
        )
        client = api.RbwApiClient(session, "https://vault.example", ssl.create_default_context())

        with self.assertRaises(api.RbwApiError) as raised:
            await client.async_get_field("item-id", "password")

        self.assertTrue(raised.exception.authentication_error)
        self.assertFalse(raised.exception.retryable)

    async def test_master_password_reprompt_is_not_a_transient_locked_vault(self) -> None:
        session = FakeSession(
            FakeResponse(
                423,
                {
                    "code": "reauthentication_required",
                    "message": "Interactive unlock is required",
                    "retryable": False,
                },
                {"Retry-After": "5"},
            )
        )
        client = api.RbwApiClient(session, "https://vault.example", ssl.create_default_context())

        with self.assertRaises(api.RbwApiError) as raised:
            await client.async_get_field("item-id", "password")

        self.assertEqual(raised.exception.code, "reauthentication_required")
        self.assertFalse(raised.exception.retryable)
        self.assertIsNone(raised.exception.retry_after_seconds)

    async def test_error_message_never_echoes_server_text_or_secret(self) -> None:
        secret = "secret-that-must-not-be-logged"
        session = FakeSession(
            FakeResponse(
                403,
                {
                    "code": "policy_denied",
                    "message": secret,
                    "retryable": False,
                },
            )
        )
        client = api.RbwApiClient(session, "https://vault.example", ssl.create_default_context())

        with self.assertRaises(api.RbwApiError) as raised:
            await client.async_get_field("item-id", "password")

        self.assertNotIn(secret, str(raised.exception))
        self.assertEqual(raised.exception.code, "policy_denied")

    async def test_invalid_sensitivity_metadata_fails_closed(self) -> None:
        session = FakeSession(
            FakeResponse(
                200,
                {"field": "password", "value": "secret-value", "sensitive": "false"},
            )
        )
        client = api.RbwApiClient(session, "https://vault.example", ssl.create_default_context())

        with self.assertRaises(api.RbwApiError) as raised:
            await client.async_get_field("item-id", "password")

        self.assertEqual(raised.exception.code, "invalid_response")
        self.assertTrue(raised.exception.retryable)

    async def test_null_optional_field_value_matches_backend_response(self) -> None:
        session = FakeSession(success("name", None, sensitive=False))
        client = api.RbwApiClient(session, "https://vault.example", ssl.create_default_context())

        result = await client.async_get_field("item-id", "name")

        self.assertEqual(result, {"field": "name", "value": None, "sensitive": False})

    async def test_api_url_must_be_an_origin_with_no_path_prefix(self) -> None:
        self.assertEqual(
            api.RbwApiClient.validate_base_url("https://vault.example:24871/"),
            "https://vault.example:24871",
        )
        with self.assertRaises(ValueError):
            api.RbwApiClient.validate_base_url("https://vault.example/api")


if __name__ == "__main__":
    unittest.main()

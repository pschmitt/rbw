"""Tests for the mTLS API client, isolated from Home Assistant startup."""

from __future__ import annotations

import importlib.util
import ssl
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

API_PATH = Path(__file__).parents[1] / "custom_components" / "rbw" / "api.py"
SPEC = importlib.util.spec_from_file_location("rbw_test_api", API_PATH)
assert SPEC and SPEC.loader
api = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = api
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

    def post(self, url: str, **kwargs: object) -> FakeResponse:
        self.requests.append((url, kwargs))
        return self.responses.pop(0)


def success(field_id: str, value: str | None, *, sensitive: bool = True) -> FakeResponse:
    return FakeResponse(
        200,
        {"field": field_id, "value": value, "sensitive": sensitive},
    )


def status_success(
    accounts: list[dict[str, str]] | None = None,
    *,
    api_version: int = 1,
    agent_version: str = "2.39.0",
) -> FakeResponse:
    """Build a safe status response from the backend contract."""
    return FakeResponse(
        200,
        {
            "apiVersion": api_version,
            "agentVersion": agent_version,
            "accounts": accounts
            if accounts is not None
            else [{"account": "personal", "state": "unlocked"}],
        },
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

    async def test_status_request_returns_only_safe_status_and_uses_mtls(self) -> None:
        context = ssl.create_default_context()
        session = FakeSession(status_success([{"account": "personal", "state": "locked"}]))
        client = api.RbwApiClient(session, "https://vault.example", context)

        result = await client.async_get_status()

        self.assertEqual(
            result,
            api.RbwApiStatus(
                api_version=1,
                agent_version="2.39.0",
                accounts=(api.RbwAccountStatus("personal", "locked"),),
            ),
        )
        url, kwargs = session.requests[0]
        self.assertEqual(url, "https://vault.example/v1/status")
        self.assertIs(kwargs["ssl"], context)

    async def test_status_preserves_unconfigured_account_without_calling_it_unlocked(self) -> None:
        client = api.RbwApiClient(
            FakeSession(status_success([{"account": "retired", "state": "unconfigured"}])),
            "https://vault.example",
            ssl.create_default_context(),
        )

        result = await client.async_get_status()

        self.assertEqual(
            result.accounts,
            (api.RbwAccountStatus("retired", "unconfigured"),),
        )

    async def test_status_preserves_all_explicitly_granted_accounts(self) -> None:
        client = api.RbwApiClient(
            FakeSession(
                status_success(
                    [
                        {"account": "personal", "state": "locked"},
                        {"account": "work", "state": "unlocked"},
                    ]
                )
            ),
            "https://vault.example",
            ssl.create_default_context(),
        )

        result = await client.async_get_status()

        self.assertEqual(
            result.accounts,
            (
                api.RbwAccountStatus("personal", "locked"),
                api.RbwAccountStatus("work", "unlocked"),
            ),
        )

    async def test_status_forbidden_preserves_reachability_and_error_code(self) -> None:
        client = api.RbwApiClient(
            FakeSession(
                FakeResponse(
                    403,
                    {"code": "forbidden", "message": "not granted", "retryable": False},
                )
            ),
            "https://vault.example",
            ssl.create_default_context(),
        )

        with self.assertRaises(api.RbwApiError) as raised:
            await client.async_get_status()

        self.assertEqual(raised.exception.code, "forbidden")
        self.assertEqual(raised.exception.http_status, 403)
        self.assertFalse(raised.exception.retryable)
        self.assertNotIn("not granted", str(raised.exception))

    async def test_status_rejects_invalid_metadata_or_account_rows(self) -> None:
        for payload in (
            {"apiVersion": True, "agentVersion": "2.39.0", "accounts": []},
            {"apiVersion": 1, "agentVersion": "2.39.0\nsecret", "accounts": []},
            {
                "apiVersion": 1,
                "agentVersion": "2.39.0",
                "accounts": [{"account": "a", "state": "maybe"}],
            },
            {
                "apiVersion": 1,
                "agentVersion": "2.39.0",
                "accounts": [{"account": "", "state": "locked"}],
            },
            {
                "apiVersion": 1,
                "agentVersion": "2.39.0",
                "accounts": [
                    {"account": "a", "state": "locked"},
                    {"account": "a", "state": "unlocked"},
                ],
            },
            {
                "apiVersion": 1,
                "agentVersion": "2.39.0",
                "accounts": [{"account": "a", "state": "locked", "password": "secret"}],
            },
            {
                "apiVersion": 1,
                "agentVersion": "2.39.0",
                "accounts": [],
                "vault": {"password": "secret"},
            },
        ):
            with self.subTest(payload=payload):
                client = api.RbwApiClient(
                    FakeSession(FakeResponse(200, payload)),
                    "https://vault.example",
                    ssl.create_default_context(),
                )
                with self.assertRaises(api.RbwApiError) as raised:
                    await client.async_get_status()
                self.assertEqual(raised.exception.code, "invalid_response")
                self.assertEqual(raised.exception.http_status, 200)
                self.assertNotIn("secret", str(raised.exception))

    async def test_status_parses_recent_audit_events_and_unlock_posts_password(self) -> None:
        session = FakeSession(
            FakeResponse(
                200,
                {
                    "apiVersion": 1,
                    "agentVersion": "2.41.0",
                    "accounts": [{"account": "default", "state": "unlocked"}],
                    "events": [
                        {
                            "timestamp": "12345.000",
                            "actor": "home-assistant",
                            "operation": "api.field_read",
                            "outcome": "allowed",
                            "account": "default",
                            "item_id": "item-uuid",
                            "item_name": "HR WORKS",
                            "field": "password",
                            "client": "custom_components.hrworks",
                        }
                    ],
                },
            ),
            FakeResponse(
                200,
                {"account": "default", "state": "unlocked"},
            ),
        )
        client = api.RbwApiClient(session, "https://vault.example", ssl.create_default_context())

        status = await client.async_get_status()
        self.assertEqual(len(status.events), 1)
        self.assertEqual(status.events[0].actor, "home-assistant")
        self.assertEqual(status.events[0].item_name, "HR WORKS")
        self.assertEqual(status.events[0].client, "custom_components.hrworks")

        unlocked = await client.async_unlock(
            "correct-horse-battery-staple",
            account="default",
            consumer="homeassistant.repairs",
        )
        self.assertEqual(unlocked, api.RbwAccountStatus("default", "unlocked"))
        post_url, post_kwargs = session.requests[1]
        self.assertEqual(post_url, "https://vault.example/v1/unlock")
        self.assertEqual(
            post_kwargs["json"],
            {"account": "default", "password": "correct-horse-battery-staple"},
        )
        self.assertEqual(post_kwargs["headers"], {"X-Rbw-Consumer": "homeassistant.repairs"})


if __name__ == "__main__":
    unittest.main()


class ListItemsTests(unittest.IsolatedAsyncioTestCase):
    def client(self, *responses: FakeResponse) -> api.RbwApiClient:
        return api.RbwApiClient(
            FakeSession(*responses), "https://vault.example", ssl.create_default_context()
        )

    async def test_lists_names_and_fields(self) -> None:
        items = [{"id": "a", "name": "Item", "fields": ["password"]}]
        client = self.client(FakeResponse(200, {"items": items}))
        self.assertEqual(await client.async_list_items(), items)

    async def test_a_locked_vault_leaves_the_name_out(self) -> None:
        items = [{"id": "a", "name": None, "fields": []}]
        client = self.client(FakeResponse(200, {"items": items}))
        self.assertEqual(await client.async_list_items(), items)

    async def test_invalid_answers_and_denials_raise(self) -> None:
        for response, code in (
            (FakeResponse(200, {"items": [{"id": 1}]}), "invalid_response"),
            (FakeResponse(200, []), "invalid_response"),
            (FakeResponse(403, {"code": "forbidden"}), "http_403"),
        ):
            with self.assertRaises(api.RbwApiError) as err:
                await self.client(response).async_list_items()
            self.assertEqual(err.exception.code, code)

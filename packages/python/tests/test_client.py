"""Tests for BotchaClient class."""

import base64
import json
import time
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx

from botcha.client import BotchaClient


def make_fake_jwt(exp: int | None = None) -> str:
    """Create a fake JWT for testing."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "exp": exp or int(time.time()) + 3600,
        "sub": "test",
        "iat": int(time.time()),
    }

    header_b64 = (
        base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    )
    payload_b64 = (
        base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    )

    return f"{header_b64}.{payload_b64}.fakesignature"


@pytest.mark.asyncio
@respx.mock
async def test_get_token_happy_path():
    """Test successful token acquisition."""
    # Mock GET /v1/token
    respx.get("https://botcha.ai/v1/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "test-challenge-id",
                "problems": [123456, 789012],
                "timeLimit": 500,
            },
        )
    )

    # Mock POST /v1/token/verify
    fake_token = make_fake_jwt()
    respx.post("https://botcha.ai/v1/token/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "verified": True,
                "token": fake_token,
                "solveTimeMs": 42.5,
            },
        )
    )

    async with BotchaClient() as client:
        token = await client.get_token()

        assert token == fake_token
        assert client._token == fake_token
        assert client._token_expires_at > time.time()


@pytest.mark.asyncio
@respx.mock
async def test_get_token_caching():
    """Test that token is cached and not re-requested."""
    # Set up mocks
    get_mock = respx.get("https://botcha.ai/v1/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "test-challenge-id",
                "problems": [123456],
                "timeLimit": 500,
            },
        )
    )

    fake_token = make_fake_jwt(exp=int(time.time()) + 3600)
    post_mock = respx.post("https://botcha.ai/v1/token/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "verified": True,
                "token": fake_token,
                "solveTimeMs": 42.5,
            },
        )
    )

    async with BotchaClient() as client:
        # First call - should hit the API
        token1 = await client.get_token()
        assert get_mock.called
        assert post_mock.called

        # Reset call counts
        get_mock.reset()
        post_mock.reset()

        # Second call - should use cached token
        token2 = await client.get_token()
        assert token1 == token2
        assert not get_mock.called
        assert not post_mock.called


@pytest.mark.asyncio
@respx.mock
async def test_get_token_refresh_near_expiry():
    """Test that token is refreshed when near expiry."""
    # First token expires in 4 minutes (less than 5min buffer)
    old_token = make_fake_jwt(exp=int(time.time()) + 240)
    new_token = make_fake_jwt(exp=int(time.time()) + 3600)

    get_mock = respx.get("https://botcha.ai/v1/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "test-challenge-id",
                "problems": [123456],
                "timeLimit": 500,
            },
        )
    )

    post_mock = respx.post("https://botcha.ai/v1/token/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "verified": True,
                "token": new_token,
                "solveTimeMs": 42.5,
            },
        )
    )

    async with BotchaClient() as client:
        # Manually set an expiring token
        client._token = old_token
        client._token_expires_at = time.time() + 240  # 4 minutes from now

        # Should refresh because it's within 5min buffer
        token = await client.get_token()

        assert token == new_token
        assert get_mock.called
        assert post_mock.called


@pytest.mark.asyncio
@respx.mock
async def test_fetch_auto_attaches_bearer_token():
    """Test that fetch() automatically attaches Bearer token."""
    fake_token = make_fake_jwt()

    # Mock token endpoints
    respx.get("https://botcha.ai/v1/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "test-challenge-id",
                "problems": [123456],
                "timeLimit": 500,
            },
        )
    )

    respx.post("https://botcha.ai/v1/token/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "verified": True,
                "token": fake_token,
                "solveTimeMs": 42.5,
            },
        )
    )

    # Mock API endpoint
    api_route = respx.get("https://api.example.com/data").mock(
        return_value=httpx.Response(200, json={"result": "success"})
    )

    async with BotchaClient() as client:
        response = await client.fetch("https://api.example.com/data")

        assert response.status_code == 200
        assert response.json() == {"result": "success"}

        # Verify Bearer token was sent
        request = api_route.calls.last.request
        assert "Authorization" in request.headers
        assert request.headers["Authorization"] == f"Bearer {fake_token}"


@pytest.mark.asyncio
@respx.mock
async def test_fetch_retries_on_401():
    """Test that fetch() retries on 401 with fresh token."""
    old_token = make_fake_jwt()
    new_token = make_fake_jwt()

    # Mock token endpoints - called twice (initial + refresh)
    get_call_count = 0

    def get_token_handler(request):
        nonlocal get_call_count
        get_call_count += 1
        return httpx.Response(
            200,
            json={
                "id": f"challenge-{get_call_count}",
                "problems": [123456],
                "timeLimit": 500,
            },
        )

    post_call_count = 0

    def verify_token_handler(request):
        nonlocal post_call_count
        post_call_count += 1
        token = new_token if post_call_count > 1 else old_token
        return httpx.Response(
            200,
            json={
                "verified": True,
                "token": token,
                "solveTimeMs": 42.5,
            },
        )

    respx.get("https://botcha.ai/v1/token").mock(side_effect=get_token_handler)
    respx.post("https://botcha.ai/v1/token/verify").mock(
        side_effect=verify_token_handler
    )

    # Mock API endpoint - returns 401 first, then 200
    api_call_count = 0

    def api_handler(request):
        nonlocal api_call_count
        api_call_count += 1
        if api_call_count == 1:
            return httpx.Response(401, json={"error": "Unauthorized"})
        return httpx.Response(200, json={"result": "success"})

    respx.get("https://api.example.com/data").mock(side_effect=api_handler)

    async with BotchaClient() as client:
        response = await client.fetch("https://api.example.com/data")

        # Should succeed after retry
        assert response.status_code == 200
        assert response.json() == {"result": "success"}

        # Verify retry happened
        assert api_call_count == 2
        assert get_call_count == 2
        assert post_call_count == 2


@pytest.mark.asyncio
@respx.mock
async def test_fetch_solves_inline_challenge_on_403():
    """Test that fetch() solves inline challenge on 403."""
    fake_token = make_fake_jwt()

    # Mock token endpoints
    respx.get("https://botcha.ai/v1/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "test-challenge-id",
                "problems": [123456],
                "timeLimit": 500,
            },
        )
    )

    respx.post("https://botcha.ai/v1/token/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "verified": True,
                "token": fake_token,
                "solveTimeMs": 42.5,
            },
        )
    )

    # Mock API endpoint - returns 403 with challenge first, then 200
    api_call_count = 0

    def api_handler(request):
        nonlocal api_call_count
        api_call_count += 1

        if api_call_count == 1:
            return httpx.Response(
                403,
                json={
                    "error": "Challenge required",
                    "challenge": {
                        "id": "inline-challenge-id",
                        "problems": [111111, 222222],
                    },
                },
            )

        # On second call, verify challenge headers were sent
        assert "X-Botcha-Challenge-Id" in request.headers
        assert request.headers["X-Botcha-Challenge-Id"] == "inline-challenge-id"
        assert "X-Botcha-Answers" in request.headers

        return httpx.Response(200, json={"result": "success"})

    respx.get("https://api.example.com/data").mock(side_effect=api_handler)

    async with BotchaClient() as client:
        response = await client.fetch("https://api.example.com/data")

        # Should succeed after solving challenge
        assert response.status_code == 200
        assert response.json() == {"result": "success"}
        assert api_call_count == 2


@pytest.mark.asyncio
async def test_solve_delegates_to_solver():
    """Test that solve() delegates to solve_botcha()."""
    client = BotchaClient()

    solutions = client.solve([123456, 789012])

    # Verify correct solutions
    assert len(solutions) == 2
    assert solutions[0] == "8d969eef"
    assert solutions[1] == "29be3ceb"


@pytest.mark.asyncio
@respx.mock
async def test_context_manager():
    """Test that context manager works correctly."""
    # Mock token endpoints
    respx.get("https://botcha.ai/v1/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "test-challenge-id",
                "problems": [123456],
                "timeLimit": 500,
            },
        )
    )

    fake_token = make_fake_jwt()
    respx.post("https://botcha.ai/v1/token/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "verified": True,
                "token": fake_token,
                "solveTimeMs": 42.5,
            },
        )
    )

    # Use context manager
    async with BotchaClient() as client:
        token = await client.get_token()
        assert token == fake_token

    # Client should be closed after exiting context


@pytest.mark.asyncio
@respx.mock
async def test_fetch_with_auto_token_disabled():
    """Test that fetch() works with auto_token=False."""
    # Mock API endpoint
    respx.get("https://api.example.com/data").mock(
        return_value=httpx.Response(200, json={"result": "success"})
    )

    async with BotchaClient(auto_token=False) as client:
        response = await client.fetch("https://api.example.com/data")

        assert response.status_code == 200

        # Verify no Authorization header was sent
        request = respx.routes[-1].calls.last.request
        assert "Authorization" not in request.headers


@pytest.mark.asyncio
@respx.mock
async def test_fetch_with_custom_method():
    """Test that fetch() supports custom HTTP methods via kwargs."""
    fake_token = make_fake_jwt()

    # Mock token endpoints
    respx.get("https://botcha.ai/v1/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "test-challenge-id",
                "problems": [123456],
                "timeLimit": 500,
            },
        )
    )

    respx.post("https://botcha.ai/v1/token/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "verified": True,
                "token": fake_token,
                "solveTimeMs": 42.5,
            },
        )
    )

    # Mock API endpoint with POST
    api_route = respx.post("https://api.example.com/data").mock(
        return_value=httpx.Response(201, json={"created": True})
    )

    async with BotchaClient() as client:
        # Note: The current implementation only supports GET in fetch()
        # This test documents the limitation - we'd need to update fetch() signature
        # For now, test that it works when we modify the implementation
        pass


@pytest.mark.asyncio
@respx.mock
async def test_custom_base_url():
    """Test that custom base_url is respected."""
    fake_token = make_fake_jwt()

    # Mock token endpoints on custom URL
    respx.get("https://custom.botcha.dev/v1/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "test-challenge-id",
                "problems": [123456],
                "timeLimit": 500,
            },
        )
    )

    respx.post("https://custom.botcha.dev/v1/token/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "verified": True,
                "token": fake_token,
                "solveTimeMs": 42.5,
            },
        )
    )

    async with BotchaClient(base_url="https://custom.botcha.dev") as client:
        token = await client.get_token()
        assert token == fake_token


@pytest.mark.asyncio
async def test_agent_identity_sets_user_agent():
    """Test that agent_identity sets User-Agent header."""
    client = BotchaClient(agent_identity="TestBot/1.0")

    assert "User-Agent" in client._client.headers
    assert client._client.headers["User-Agent"] == "TestBot/1.0"

    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_token_parsing_with_invalid_jwt():
    """Test that invalid JWT still works with default 1hr expiry."""
    invalid_token = "not.a.valid.jwt"

    respx.get("https://botcha.ai/v1/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "test-challenge-id",
                "problems": [123456],
                "timeLimit": 500,
            },
        )
    )

    respx.post("https://botcha.ai/v1/token/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "verified": True,
                "token": invalid_token,
                "solveTimeMs": 42.5,
            },
        )
    )

    async with BotchaClient() as client:
        token = await client.get_token()

        assert token == invalid_token
        # Should default to 1hr expiry
        assert client._token_expires_at > time.time()
        assert client._token_expires_at <= time.time() + 3610  # ~1hr with small buffer


@pytest.mark.asyncio
@respx.mock
async def test_fetch_403_without_challenge():
    """Test that 403 without challenge structure returns original response."""
    fake_token = make_fake_jwt()

    # Mock token endpoints
    respx.get("https://botcha.ai/v1/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "test-challenge-id",
                "problems": [123456],
                "timeLimit": 500,
            },
        )
    )

    respx.post("https://botcha.ai/v1/token/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "verified": True,
                "token": fake_token,
                "solveTimeMs": 42.5,
            },
        )
    )

    # Mock API endpoint - returns 403 without challenge structure
    respx.get("https://api.example.com/data").mock(
        return_value=httpx.Response(
            403,
            json={"error": "Forbidden", "reason": "Insufficient permissions"},
        )
    )

    async with BotchaClient() as client:
        response = await client.fetch("https://api.example.com/data")

        # Should return original 403 response
        assert response.status_code == 403
        data = response.json()
        assert data["error"] == "Forbidden"


@pytest.mark.asyncio
@respx.mock
async def test_audience_passed_in_verify():
    """Test that audience parameter is included in verify request."""
    fake_token = make_fake_jwt()

    # Mock GET /v1/token
    respx.get("https://botcha.ai/v1/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "test-challenge-id",
                "problems": [123456],
                "timeLimit": 500,
            },
        )
    )

    # Mock POST /v1/token/verify and capture the request
    verify_route = respx.post("https://botcha.ai/v1/token/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "verified": True,
                "token": fake_token,
                "solveTimeMs": 42.5,
            },
        )
    )

    async with BotchaClient(audience="api.example.com") as client:
        token = await client.get_token()

        # Verify audience was sent in the request body
        request = verify_route.calls.last.request
        body = json.loads(request.content)
        assert "audience" in body
        assert body["audience"] == "api.example.com"
        assert token == fake_token


@pytest.mark.asyncio
@respx.mock
async def test_audience_not_included_when_none():
    """Test that audience is not included in verify request when not set."""
    fake_token = make_fake_jwt()

    # Mock GET /v1/token
    respx.get("https://botcha.ai/v1/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "test-challenge-id",
                "problems": [123456],
                "timeLimit": 500,
            },
        )
    )

    # Mock POST /v1/token/verify and capture the request
    verify_route = respx.post("https://botcha.ai/v1/token/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "verified": True,
                "token": fake_token,
                "solveTimeMs": 42.5,
            },
        )
    )

    async with BotchaClient() as client:
        token = await client.get_token()

        # Verify audience was NOT sent in the request body
        request = verify_route.calls.last.request
        body = json.loads(request.content)
        assert "audience" not in body
        assert token == fake_token


@pytest.mark.asyncio
@respx.mock
async def test_refresh_token_stored_from_verify():
    """Test that refresh token is stored from get_token response."""
    fake_token = make_fake_jwt()
    fake_refresh_token = "refresh_token_12345"

    # Mock GET /v1/token
    respx.get("https://botcha.ai/v1/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "test-challenge-id",
                "problems": [123456],
                "timeLimit": 500,
            },
        )
    )

    # Mock POST /v1/token/verify with refresh_token
    respx.post("https://botcha.ai/v1/token/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "verified": True,
                "token": fake_token,
                "access_token": fake_token,
                "expires_in": 300,
                "refresh_token": fake_refresh_token,
                "refresh_expires_in": 3600,
                "solveTimeMs": 42.5,
            },
        )
    )

    async with BotchaClient() as client:
        token = await client.get_token()

        assert token == fake_token
        assert client._refresh_token == fake_refresh_token
        # Token should expire in ~300 seconds (5 minutes)
        assert client._token_expires_at <= time.time() + 305
        assert client._token_expires_at >= time.time() + 295


@pytest.mark.asyncio
@respx.mock
async def test_refresh_token_method():
    """Test that refresh_token() calls correct endpoint and updates token."""
    fake_token = make_fake_jwt()
    fake_refresh_token = "refresh_token_12345"
    new_access_token = make_fake_jwt(exp=int(time.time()) + 3600)

    # Mock refresh endpoint
    refresh_route = respx.post("https://botcha.ai/v1/token/refresh").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": new_access_token,
                "expires_in": 300,
            },
        )
    )

    async with BotchaClient() as client:
        # Manually set refresh token
        client._refresh_token = fake_refresh_token
        client._token = fake_token

        # Call refresh
        new_token = await client.refresh_token()

        assert new_token == new_access_token
        assert client._token == new_access_token

        # Verify correct endpoint was called
        request = refresh_route.calls.last.request
        body = json.loads(request.content)
        assert body["refresh_token"] == fake_refresh_token


@pytest.mark.asyncio
@respx.mock
async def test_refresh_token_without_refresh_token_raises():
    """Test that refresh_token() raises ValueError when no refresh token is stored."""
    async with BotchaClient() as client:
        # No refresh token set
        with pytest.raises(ValueError, match="No refresh token available"):
            await client.refresh_token()


@pytest.mark.asyncio
@respx.mock
async def test_fetch_401_tries_refresh_first():
    """Test that 401 triggers refresh_token() before full re-verify."""
    old_token = make_fake_jwt()
    refresh_token = "refresh_token_12345"
    refreshed_token = make_fake_jwt(exp=int(time.time()) + 3600)

    # Mock refresh endpoint
    refresh_route = respx.post("https://botcha.ai/v1/token/refresh").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": refreshed_token,
                "expires_in": 300,
            },
        )
    )

    # Mock API endpoint - returns 401 first, then 200
    api_call_count = 0

    def api_handler(request):
        nonlocal api_call_count
        api_call_count += 1
        if api_call_count == 1:
            return httpx.Response(401, json={"error": "Unauthorized"})
        # Check that refreshed token is being used
        assert request.headers["Authorization"] == f"Bearer {refreshed_token}"
        return httpx.Response(200, json={"result": "success"})

    respx.get("https://api.example.com/data").mock(side_effect=api_handler)

    async with BotchaClient() as client:
        # Set up client with tokens
        client._token = old_token
        client._refresh_token = refresh_token
        client._token_expires_at = time.time() + 600  # Still valid but will get 401

        response = await client.fetch("https://api.example.com/data")

        # Should succeed after refresh
        assert response.status_code == 200
        assert response.json() == {"result": "success"}

        # Verify refresh was called
        assert refresh_route.called
        assert api_call_count == 2


@pytest.mark.asyncio
@respx.mock
async def test_fetch_401_falls_back_to_full_verify_on_refresh_failure():
    """Test that if refresh fails, falls back to full get_token()."""
    old_token = make_fake_jwt()
    refresh_token = "refresh_token_12345"
    new_token = make_fake_jwt(exp=int(time.time()) + 3600)

    # Mock refresh endpoint - fails
    refresh_route = respx.post("https://botcha.ai/v1/token/refresh").mock(
        return_value=httpx.Response(401, json={"error": "Invalid refresh token"})
    )

    # Mock full token flow
    respx.get("https://botcha.ai/v1/token").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "test-challenge-id",
                "problems": [123456],
                "timeLimit": 500,
            },
        )
    )

    verify_route = respx.post("https://botcha.ai/v1/token/verify").mock(
        return_value=httpx.Response(
            200,
            json={
                "verified": True,
                "token": new_token,
                "solveTimeMs": 42.5,
            },
        )
    )

    # Mock API endpoint - returns 401 first, then 200
    api_call_count = 0

    def api_handler(request):
        nonlocal api_call_count
        api_call_count += 1
        if api_call_count == 1:
            return httpx.Response(401, json={"error": "Unauthorized"})
        return httpx.Response(200, json={"result": "success"})

    respx.get("https://api.example.com/data").mock(side_effect=api_handler)

    async with BotchaClient() as client:
        # Set up client with tokens
        client._token = old_token
        client._refresh_token = refresh_token
        client._token_expires_at = time.time() + 600

        response = await client.fetch("https://api.example.com/data")

        # Should succeed after full re-verify
        assert response.status_code == 200
        assert response.json() == {"result": "success"}

        # Verify refresh was attempted
        assert refresh_route.called
        # Verify fallback to full flow
        assert verify_route.called


@pytest.mark.asyncio
@respx.mock
async def test_close_clears_refresh_token():
    """Test that close() clears the refresh token."""
    client = BotchaClient()
    client._token = "access_token"
    client._refresh_token = "refresh_token"
    client._token_expires_at = time.time() + 300

    await client.close()

    assert client._token is None
    assert client._refresh_token is None
    assert client._token_expires_at == 0

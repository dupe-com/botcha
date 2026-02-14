"""Tests for BotchaClient TAP (Trusted Agent Protocol) methods."""

import json
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx

from botcha.client import BotchaClient


# ============ register_tap_agent Tests ============


@pytest.mark.asyncio
@respx.mock
async def test_register_tap_agent_happy_path():
    """Test successful TAP agent registration with just name."""
    respx.post("https://botcha.ai/v1/agents/register/tap").mock(
        return_value=httpx.Response(
            201,
            json={
                "success": True,
                "agent_id": "agent_abc123",
                "app_id": "app_test",
                "name": "my-agent",
                "created_at": "2026-02-14T00:00:00Z",
                "tap_enabled": True,
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.register_tap_agent("my-agent")

        assert result.success is True
        assert result.agent_id == "agent_abc123"
        assert result.name == "my-agent"
        assert result.tap_enabled is True


@pytest.mark.asyncio
@respx.mock
async def test_register_tap_agent_with_all_params():
    """Test TAP agent registration with all optional parameters."""
    respx.post("https://botcha.ai/v1/agents/register/tap").mock(
        return_value=httpx.Response(
            201,
            json={
                "success": True,
                "agent_id": "agent_full123",
                "app_id": "app_test",
                "name": "full-agent",
                "operator": "acme-corp",
                "version": "1.0.0",
                "created_at": "2026-02-14T00:00:00Z",
                "tap_enabled": True,
                "trust_level": "verified",
                "capabilities": [{"action": "browse", "scope": ["products"]}],
                "signature_algorithm": "ecdsa-p256-sha256",
                "issuer": "acme-ca",
                "has_public_key": True,
                "key_fingerprint": "sha256:abc123",
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.register_tap_agent(
            name="full-agent",
            operator="acme-corp",
            version="1.0.0",
            public_key="-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
            signature_algorithm="ecdsa-p256-sha256",
            capabilities=[{"action": "browse", "scope": ["products"]}],
            trust_level="verified",
            issuer="acme-ca",
        )

        assert result.success is True
        assert result.agent_id == "agent_full123"
        assert result.operator == "acme-corp"
        assert result.version == "1.0.0"
        assert result.trust_level == "verified"
        assert result.has_public_key is True


@pytest.mark.asyncio
@respx.mock
async def test_register_tap_agent_sends_correct_body():
    """Test that register_tap_agent sends correct request body."""
    route = respx.post("https://botcha.ai/v1/agents/register/tap").mock(
        return_value=httpx.Response(
            201,
            json={
                "success": True,
                "agent_id": "agent_xyz",
                "name": "test-agent",
            },
        )
    )

    async with BotchaClient() as client:
        await client.register_tap_agent(
            name="test-agent",
            operator="test-corp",
            capabilities=[{"action": "read"}],
        )

        request = route.calls.last.request
        body = json.loads(request.content)
        assert body["name"] == "test-agent"
        assert body["operator"] == "test-corp"
        assert body["capabilities"] == [{"action": "read"}]


@pytest.mark.asyncio
@respx.mock
async def test_register_tap_agent_with_app_id():
    """Test that register_tap_agent adds app_id query param."""
    route = respx.post(
        "https://botcha.ai/v1/agents/register/tap", params={"app_id": "app_test123"}
    ).mock(
        return_value=httpx.Response(
            201,
            json={
                "success": True,
                "agent_id": "agent_app",
                "app_id": "app_test123",
                "name": "app-agent",
            },
        )
    )

    async with BotchaClient(app_id="app_test123") as client:
        result = await client.register_tap_agent("app-agent")

        assert result.success is True
        assert result.app_id == "app_test123"
        assert route.called


@pytest.mark.asyncio
@respx.mock
async def test_register_tap_agent_attaches_bearer_token():
    """Test that register_tap_agent attaches Bearer token when available."""
    route = respx.post("https://botcha.ai/v1/agents/register/tap").mock(
        return_value=httpx.Response(
            201,
            json={
                "success": True,
                "agent_id": "agent_auth",
                "name": "auth-agent",
            },
        )
    )

    async with BotchaClient() as client:
        # Manually set a token
        client._token = "test-token-xyz"

        await client.register_tap_agent("auth-agent")

        request = route.calls.last.request
        assert "Authorization" in request.headers
        assert request.headers["Authorization"] == "Bearer test-token-xyz"


@pytest.mark.asyncio
@respx.mock
async def test_register_tap_agent_error_400():
    """Test register_tap_agent with 400 bad request."""
    respx.post("https://botcha.ai/v1/agents/register/tap").mock(
        return_value=httpx.Response(
            400,
            json={
                "success": False,
                "error": "MISSING_NAME",
                "message": "Agent name is required",
            },
        )
    )

    async with BotchaClient() as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.register_tap_agent("")


# ============ get_tap_agent Tests ============


@pytest.mark.asyncio
@respx.mock
async def test_get_tap_agent_happy_path():
    """Test getting a TAP agent by ID."""
    respx.get("https://botcha.ai/v1/agents/agent_abc123/tap").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "agent_id": "agent_abc123",
                "app_id": "app_test",
                "name": "my-agent",
                "operator": "acme-corp",
                "version": "1.0.0",
                "created_at": "2026-02-14T00:00:00Z",
                "tap_enabled": True,
                "trust_level": "verified",
                "has_public_key": True,
                "key_fingerprint": "sha256:abc",
                "last_verified_at": "2026-02-14T01:00:00Z",
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.get_tap_agent("agent_abc123")

        assert result.success is True
        assert result.agent_id == "agent_abc123"
        assert result.name == "my-agent"
        assert result.operator == "acme-corp"
        assert result.last_verified_at == "2026-02-14T01:00:00Z"


@pytest.mark.asyncio
@respx.mock
async def test_get_tap_agent_not_found():
    """Test get_tap_agent with 404 not found."""
    respx.get("https://botcha.ai/v1/agents/nonexistent/tap").mock(
        return_value=httpx.Response(
            404,
            json={
                "success": False,
                "error": "NOT_FOUND",
                "message": "Agent not found",
            },
        )
    )

    async with BotchaClient() as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.get_tap_agent("nonexistent")


@pytest.mark.asyncio
@respx.mock
async def test_get_tap_agent_url_encodes_special_chars():
    """Test that get_tap_agent URL-encodes agent_id with special characters."""
    route = respx.get("https://botcha.ai/v1/agents/agent%2Fwith%2Fslash/tap").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "agent_id": "agent/with/slash",
                "name": "encoded-agent",
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.get_tap_agent("agent/with/slash")

        assert result.success is True
        assert route.called


# ============ list_tap_agents Tests ============


@pytest.mark.asyncio
@respx.mock
async def test_list_tap_agents_happy_path():
    """Test listing TAP agents."""
    respx.get("https://botcha.ai/v1/agents/tap").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "agents": [
                    {"agent_id": "agent_1", "name": "Agent 1", "tap_enabled": True},
                    {"agent_id": "agent_2", "name": "Agent 2", "tap_enabled": False},
                ],
                "count": 2,
                "tap_enabled_count": 1,
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.list_tap_agents()

        assert result.success is True
        assert len(result.agents) == 2
        assert result.count == 2
        assert result.tap_enabled_count == 1
        assert result.agents[0]["agent_id"] == "agent_1"


@pytest.mark.asyncio
@respx.mock
async def test_list_tap_agents_with_tap_only_param():
    """Test list_tap_agents with tap_only=True parameter."""
    route = respx.get(
        "https://botcha.ai/v1/agents/tap", params={"tap_only": "true"}
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "agents": [
                    {"agent_id": "agent_1", "name": "Agent 1", "tap_enabled": True},
                ],
                "count": 1,
                "tap_enabled_count": 1,
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.list_tap_agents(tap_only=True)

        assert result.success is True
        assert result.count == 1
        assert result.tap_enabled_count == 1
        assert route.called


@pytest.mark.asyncio
@respx.mock
async def test_list_tap_agents_with_app_id():
    """Test list_tap_agents with app_id parameter."""
    route = respx.get(
        "https://botcha.ai/v1/agents/tap", params={"app_id": "app_test123"}
    ).mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "agents": [],
                "count": 0,
                "tap_enabled_count": 0,
            },
        )
    )

    async with BotchaClient(app_id="app_test123") as client:
        result = await client.list_tap_agents()

        assert result.success is True
        assert route.called


@pytest.mark.asyncio
@respx.mock
async def test_list_tap_agents_attaches_bearer_token():
    """Test that list_tap_agents attaches Bearer token when available."""
    route = respx.get("https://botcha.ai/v1/agents/tap").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "agents": [],
                "count": 0,
                "tap_enabled_count": 0,
            },
        )
    )

    async with BotchaClient() as client:
        client._token = "bearer-token-xyz"

        await client.list_tap_agents()

        request = route.calls.last.request
        assert "Authorization" in request.headers
        assert request.headers["Authorization"] == "Bearer bearer-token-xyz"


@pytest.mark.asyncio
@respx.mock
async def test_list_tap_agents_empty_list():
    """Test list_tap_agents returns empty list when no agents."""
    respx.get("https://botcha.ai/v1/agents/tap").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "agents": [],
                "count": 0,
                "tap_enabled_count": 0,
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.list_tap_agents()

        assert result.success is True
        assert result.agents == []
        assert result.count == 0


@pytest.mark.asyncio
@respx.mock
async def test_list_tap_agents_error_500():
    """Test list_tap_agents with 500 server error."""
    respx.get("https://botcha.ai/v1/agents/tap").mock(
        return_value=httpx.Response(
            500,
            json={
                "success": False,
                "error": "INTERNAL_ERROR",
            },
        )
    )

    async with BotchaClient() as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.list_tap_agents()


# ============ create_tap_session Tests ============


@pytest.mark.asyncio
@respx.mock
async def test_create_tap_session_happy_path():
    """Test creating a TAP session."""
    respx.post("https://botcha.ai/v1/sessions/tap").mock(
        return_value=httpx.Response(
            201,
            json={
                "success": True,
                "session_id": "session_xyz123",
                "agent_id": "agent_abc123",
                "capabilities": [{"action": "browse", "scope": ["products"]}],
                "intent": {
                    "action": "browse",
                    "resource": "products",
                    "duration": 3600,
                },
                "expires_at": "2026-02-14T01:00:00Z",
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.create_tap_session(
            agent_id="agent_abc123",
            user_context="user-hash-abc",
            intent={"action": "browse", "resource": "products", "duration": 3600},
        )

        assert result.success is True
        assert result.session_id == "session_xyz123"
        assert result.agent_id == "agent_abc123"
        assert result.capabilities is not None
        assert result.intent is not None
        assert result.expires_at == "2026-02-14T01:00:00Z"


@pytest.mark.asyncio
@respx.mock
async def test_create_tap_session_sends_correct_body():
    """Test that create_tap_session sends correct request body."""
    route = respx.post("https://botcha.ai/v1/sessions/tap").mock(
        return_value=httpx.Response(
            201,
            json={
                "success": True,
                "session_id": "session_test",
                "agent_id": "agent_test",
            },
        )
    )

    async with BotchaClient() as client:
        await client.create_tap_session(
            agent_id="agent_test",
            user_context="context_123",
            intent={"action": "read", "resource": "data"},
        )

        request = route.calls.last.request
        body = json.loads(request.content)
        assert body["agent_id"] == "agent_test"
        assert body["user_context"] == "context_123"
        assert body["intent"]["action"] == "read"


@pytest.mark.asyncio
@respx.mock
async def test_create_tap_session_agent_not_found():
    """Test create_tap_session with 404 agent not found."""
    respx.post("https://botcha.ai/v1/sessions/tap").mock(
        return_value=httpx.Response(
            404,
            json={
                "success": False,
                "error": "AGENT_NOT_FOUND",
                "message": "Agent not found",
            },
        )
    )

    async with BotchaClient() as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.create_tap_session(
                agent_id="nonexistent",
                user_context="context",
                intent={"action": "test"},
            )


@pytest.mark.asyncio
@respx.mock
async def test_create_tap_session_missing_fields():
    """Test create_tap_session with 400 missing fields."""
    respx.post("https://botcha.ai/v1/sessions/tap").mock(
        return_value=httpx.Response(
            400,
            json={
                "success": False,
                "error": "MISSING_FIELDS",
                "message": "Missing required fields",
            },
        )
    )

    async with BotchaClient() as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.create_tap_session(
                agent_id="",
                user_context="",
                intent={},
            )


# ============ get_tap_session Tests ============


@pytest.mark.asyncio
@respx.mock
async def test_get_tap_session_happy_path():
    """Test getting a TAP session by ID."""
    respx.get("https://botcha.ai/v1/sessions/session_xyz123/tap").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "session_id": "session_xyz123",
                "agent_id": "agent_abc123",
                "app_id": "app_test",
                "capabilities": [{"action": "browse"}],
                "intent": {"action": "browse", "resource": "products"},
                "created_at": "2026-02-14T00:00:00Z",
                "expires_at": "2026-02-14T01:00:00Z",
                "time_remaining": 3600,
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.get_tap_session("session_xyz123")

        assert result.success is True
        assert result.session_id == "session_xyz123"
        assert result.agent_id == "agent_abc123"
        assert result.app_id == "app_test"
        assert result.created_at == "2026-02-14T00:00:00Z"
        assert result.expires_at == "2026-02-14T01:00:00Z"


@pytest.mark.asyncio
@respx.mock
async def test_get_tap_session_not_found():
    """Test get_tap_session with 404 not found."""
    respx.get("https://botcha.ai/v1/sessions/nonexistent/tap").mock(
        return_value=httpx.Response(
            404,
            json={
                "success": False,
                "error": "NOT_FOUND",
                "message": "Session not found or expired",
            },
        )
    )

    async with BotchaClient() as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.get_tap_session("nonexistent")


@pytest.mark.asyncio
@respx.mock
async def test_get_tap_session_with_time_remaining():
    """Test get_tap_session with time_remaining field populated."""
    respx.get("https://botcha.ai/v1/sessions/session_active/tap").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "session_id": "session_active",
                "agent_id": "agent_active",
                "time_remaining": 1800,  # 30 minutes
                "expires_at": "2026-02-14T00:30:00Z",
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.get_tap_session("session_active")

        assert result.success is True
        assert result.time_remaining == 1800


@pytest.mark.asyncio
@respx.mock
async def test_get_tap_session_url_encodes_id():
    """Test that get_tap_session URL-encodes session_id."""
    route = respx.get("https://botcha.ai/v1/sessions/session%2Fwith%2Fslash/tap").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "session_id": "session/with/slash",
                "agent_id": "agent_test",
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.get_tap_session("session/with/slash")

        assert result.success is True
        assert route.called

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


# ============ get_jwks Tests ============


@pytest.mark.asyncio
@respx.mock
async def test_get_jwks_happy_path():
    """Test fetching JWKS from well-known endpoint."""
    respx.get("https://botcha.ai/.well-known/jwks").mock(
        return_value=httpx.Response(
            200,
            json={
                "keys": [
                    {
                        "kty": "EC",
                        "kid": "agent_abc123",
                        "alg": "ES256",
                        "crv": "P-256",
                        "x": "x-val",
                        "y": "y-val",
                    },
                    {
                        "kty": "OKP",
                        "kid": "agent_def456",
                        "alg": "EdDSA",
                        "crv": "Ed25519",
                        "x": "x-val",
                    },
                ],
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.get_jwks()

        assert len(result["keys"]) == 2
        assert result["keys"][0]["kid"] == "agent_abc123"
        assert result["keys"][1]["alg"] == "EdDSA"


@pytest.mark.asyncio
@respx.mock
async def test_get_jwks_with_app_id():
    """Test JWKS request includes app_id query param."""
    route = respx.get(
        "https://botcha.ai/.well-known/jwks", params={"app_id": "app_test123"}
    ).mock(return_value=httpx.Response(200, json={"keys": []}))

    async with BotchaClient(app_id="app_test123") as client:
        result = await client.get_jwks()

        assert result["keys"] == []
        assert route.called


@pytest.mark.asyncio
@respx.mock
async def test_get_jwks_explicit_app_id_overrides():
    """Test explicit app_id param overrides client default."""
    route = respx.get(
        "https://botcha.ai/.well-known/jwks", params={"app_id": "app_override"}
    ).mock(return_value=httpx.Response(200, json={"keys": []}))

    async with BotchaClient(app_id="app_default") as client:
        result = await client.get_jwks(app_id="app_override")

        assert route.called


@pytest.mark.asyncio
@respx.mock
async def test_get_jwks_server_error():
    """Test JWKS request raises on 500."""
    respx.get("https://botcha.ai/.well-known/jwks").mock(
        return_value=httpx.Response(500, json={"message": "Internal error"})
    )

    async with BotchaClient() as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.get_jwks()


# ============ get_key_by_id Tests ============


@pytest.mark.asyncio
@respx.mock
async def test_get_key_by_id_happy_path():
    """Test fetching a specific key by ID."""
    respx.get("https://botcha.ai/v1/keys/agent_abc123").mock(
        return_value=httpx.Response(
            200,
            json={"kty": "EC", "kid": "agent_abc123", "alg": "ES256", "crv": "P-256"},
        )
    )

    async with BotchaClient() as client:
        result = await client.get_key_by_id("agent_abc123")

        assert result["kid"] == "agent_abc123"
        assert result["alg"] == "ES256"


@pytest.mark.asyncio
@respx.mock
async def test_get_key_by_id_url_encodes():
    """Test key ID with special characters is URL-encoded."""
    route = respx.get("https://botcha.ai/v1/keys/agent%2Fspecial").mock(
        return_value=httpx.Response(200, json={"kid": "agent/special"})
    )

    async with BotchaClient() as client:
        result = await client.get_key_by_id("agent/special")

        assert route.called
        assert result["kid"] == "agent/special"


@pytest.mark.asyncio
@respx.mock
async def test_get_key_by_id_not_found():
    """Test 404 for nonexistent key."""
    respx.get("https://botcha.ai/v1/keys/nonexistent").mock(
        return_value=httpx.Response(404, json={"message": "Key not found"})
    )

    async with BotchaClient() as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.get_key_by_id("nonexistent")


# ============ rotate_agent_key Tests ============


@pytest.mark.asyncio
@respx.mock
async def test_rotate_agent_key_happy_path():
    """Test key rotation with all params."""
    route = respx.post("https://botcha.ai/v1/agents/agent_abc123/tap/rotate-key").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "agent_id": "agent_abc123",
                "signature_algorithm": "ecdsa-p256-sha256",
            },
        )
    )

    async with BotchaClient() as client:
        # Simulate having a token
        client._token = "bearer-token-xyz"

        result = await client.rotate_agent_key(
            agent_id="agent_abc123",
            public_key="-----BEGIN PUBLIC KEY-----\nNEWKEY\n-----END PUBLIC KEY-----",
            signature_algorithm="ecdsa-p256-sha256",
            key_expires_at="2027-01-01T00:00:00Z",
        )

        assert result["success"] is True
        assert result["agent_id"] == "agent_abc123"

        request = route.calls.last.request
        body = json.loads(request.content)
        assert body["public_key"].startswith("-----BEGIN")
        assert body["signature_algorithm"] == "ecdsa-p256-sha256"
        assert body["key_expires_at"] == "2027-01-01T00:00:00Z"
        assert request.headers["Authorization"] == "Bearer bearer-token-xyz"


@pytest.mark.asyncio
@respx.mock
async def test_rotate_agent_key_ed25519():
    """Test key rotation with Ed25519 algorithm."""
    respx.post("https://botcha.ai/v1/agents/agent_ed/tap/rotate-key").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "agent_id": "agent_ed",
                "signature_algorithm": "ed25519",
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.rotate_agent_key(
            agent_id="agent_ed",
            public_key="11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
            signature_algorithm="ed25519",
        )

        assert result["signature_algorithm"] == "ed25519"


@pytest.mark.asyncio
@respx.mock
async def test_rotate_agent_key_forbidden():
    """Test 403 on unauthorized rotation."""
    respx.post("https://botcha.ai/v1/agents/agent_other/tap/rotate-key").mock(
        return_value=httpx.Response(403, json={"message": "Not authorized"})
    )

    async with BotchaClient() as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.rotate_agent_key(
                agent_id="agent_other",
                public_key="key",
                signature_algorithm="ecdsa-p256-sha256",
            )


# ============ create_invoice Tests ============


@pytest.mark.asyncio
@respx.mock
async def test_create_invoice_happy_path():
    """Test creating an invoice with all fields."""
    route = respx.post("https://botcha.ai/v1/invoices").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "invoice_id": "inv_abc123",
                "resource_uri": "https://example.com/premium",
                "amount": "500",
                "currency": "USD",
                "card_acceptor_id": "CAID_ABC",
                "status": "pending",
                "expires_at": "2026-02-14T22:00:00Z",
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.create_invoice(
            resource_uri="https://example.com/premium",
            amount="500",
            currency="USD",
            card_acceptor_id="CAID_ABC",
            description="Premium article",
            ttl_seconds=3600,
        )

        assert result["invoice_id"] == "inv_abc123"
        assert result["amount"] == "500"
        assert result["status"] == "pending"

        request = route.calls.last.request
        body = json.loads(request.content)
        assert body["resource_uri"] == "https://example.com/premium"
        assert body["card_acceptor_id"] == "CAID_ABC"
        assert body["description"] == "Premium article"
        assert body["ttl_seconds"] == 3600


@pytest.mark.asyncio
@respx.mock
async def test_create_invoice_with_auth_token():
    """Test invoice creation attaches Bearer token."""
    route = respx.post("https://botcha.ai/v1/invoices").mock(
        return_value=httpx.Response(
            200,
            json={"success": True, "invoice_id": "inv_auth"},
        )
    )

    async with BotchaClient() as client:
        client._token = "my-token"

        await client.create_invoice(
            resource_uri="https://example.com/gated",
            amount="100",
            currency="USD",
            card_acceptor_id="CAID_XYZ",
        )

        request = route.calls.last.request
        assert request.headers["Authorization"] == "Bearer my-token"


@pytest.mark.asyncio
@respx.mock
async def test_create_invoice_minimal_fields():
    """Test invoice creation without optional fields."""
    route = respx.post("https://botcha.ai/v1/invoices").mock(
        return_value=httpx.Response(
            200,
            json={"success": True, "invoice_id": "inv_min"},
        )
    )

    async with BotchaClient() as client:
        result = await client.create_invoice(
            resource_uri="https://example.com",
            amount="100",
            currency="USD",
            card_acceptor_id="CAID",
        )

        request = route.calls.last.request
        body = json.loads(request.content)
        assert "description" not in body
        assert "ttl_seconds" not in body


@pytest.mark.asyncio
@respx.mock
async def test_create_invoice_bad_request():
    """Test 400 on invalid invoice."""
    respx.post("https://botcha.ai/v1/invoices").mock(
        return_value=httpx.Response(
            400, json={"message": "Missing required field: amount"}
        )
    )

    async with BotchaClient() as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.create_invoice(
                resource_uri="https://example.com",
                amount="",
                currency="USD",
                card_acceptor_id="CAID",
            )


# ============ get_invoice Tests ============


@pytest.mark.asyncio
@respx.mock
async def test_get_invoice_happy_path():
    """Test fetching an invoice by ID."""
    respx.get("https://botcha.ai/v1/invoices/inv_abc123").mock(
        return_value=httpx.Response(
            200,
            json={
                "invoice_id": "inv_abc123",
                "status": "pending",
                "amount": "500",
                "currency": "USD",
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.get_invoice("inv_abc123")

        assert result["invoice_id"] == "inv_abc123"
        assert result["status"] == "pending"


@pytest.mark.asyncio
@respx.mock
async def test_get_invoice_url_encodes():
    """Test invoice ID with special chars is URL-encoded."""
    route = respx.get("https://botcha.ai/v1/invoices/inv%2Fspecial").mock(
        return_value=httpx.Response(200, json={"invoice_id": "inv/special"})
    )

    async with BotchaClient() as client:
        result = await client.get_invoice("inv/special")
        assert route.called


@pytest.mark.asyncio
@respx.mock
async def test_get_invoice_not_found():
    """Test 404 for nonexistent invoice."""
    respx.get("https://botcha.ai/v1/invoices/nonexistent").mock(
        return_value=httpx.Response(404, json={"message": "Invoice not found"})
    )

    async with BotchaClient() as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.get_invoice("nonexistent")


# ============ verify_browsing_iou Tests ============


@pytest.mark.asyncio
@respx.mock
async def test_verify_browsing_iou_happy_path():
    """Test successful IOU verification."""
    route = respx.post("https://botcha.ai/v1/invoices/inv_abc123/verify-iou").mock(
        return_value=httpx.Response(
            200,
            json={
                "verified": True,
                "access_token": "access_token_xyz",
                "expires_in": 3600,
            },
        )
    )

    iou = {
        "invoiceId": "inv_abc123",
        "amount": "500",
        "cardAcceptorId": "CAID_ABC",
        "acquirerId": "ACQ_XYZ",
        "uri": "https://example.com/premium",
        "sequenceCounter": "1",
        "paymentService": "agent-pay",
        "kid": "agent_def456",
        "alg": "ES256",
        "signature": "base64-signature-here",
    }

    async with BotchaClient() as client:
        result = await client.verify_browsing_iou("inv_abc123", iou)

        assert result["verified"] is True
        assert result["access_token"] == "access_token_xyz"

        request = route.calls.last.request
        body = json.loads(request.content)
        assert body["invoiceId"] == "inv_abc123"
        assert body["amount"] == "500"
        assert body["signature"] == "base64-signature-here"


@pytest.mark.asyncio
@respx.mock
async def test_verify_browsing_iou_rejected():
    """Test IOU verification rejection (amount mismatch)."""
    respx.post("https://botcha.ai/v1/invoices/inv_abc123/verify-iou").mock(
        return_value=httpx.Response(
            200,
            json={"verified": False, "error": "Amount mismatch"},
        )
    )

    async with BotchaClient() as client:
        result = await client.verify_browsing_iou(
            "inv_abc123",
            {
                "invoiceId": "inv_abc123",
                "amount": "999",
                "cardAcceptorId": "CAID_ABC",
                "acquirerId": "ACQ_XYZ",
                "uri": "https://example.com",
                "sequenceCounter": "1",
                "paymentService": "agent-pay",
                "kid": "agent_def456",
                "alg": "ES256",
                "signature": "bad-sig",
            },
        )

        assert result["verified"] is False
        assert result["error"] == "Amount mismatch"


@pytest.mark.asyncio
@respx.mock
async def test_verify_browsing_iou_server_error():
    """Test IOU verification raises on server error."""
    respx.post("https://botcha.ai/v1/invoices/inv_err/verify-iou").mock(
        return_value=httpx.Response(500, json={"message": "Internal error"})
    )

    async with BotchaClient() as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.verify_browsing_iou(
                "inv_err",
                {"invoiceId": "inv_err", "amount": "500"},
            )


@pytest.mark.asyncio
@respx.mock
async def test_verify_browsing_iou_url_encodes():
    """Test invoice ID in IOU verification URL is encoded."""
    route = respx.post("https://botcha.ai/v1/invoices/inv%2Fslash/verify-iou").mock(
        return_value=httpx.Response(200, json={"verified": True})
    )

    async with BotchaClient() as client:
        await client.verify_browsing_iou("inv/slash", {"invoiceId": "inv/slash"})
        assert route.called


# ============ create_delegation Tests ============


@pytest.mark.asyncio
@respx.mock
async def test_create_delegation_happy_path():
    """Test successful delegation creation."""
    respx.post("https://botcha.ai/v1/delegations").mock(
        return_value=httpx.Response(
            201,
            json={
                "success": True,
                "delegation_id": "del_abc123",
                "grantor_id": "agent_grantor",
                "grantee_id": "agent_grantee",
                "app_id": "app_test",
                "capabilities": [{"action": "browse", "scope": ["products"]}],
                "chain": ["agent_grantor", "agent_grantee"],
                "depth": 0,
                "max_depth": 3,
                "parent_delegation_id": None,
                "created_at": "2026-02-14T00:00:00Z",
                "expires_at": "2026-02-14T01:00:00Z",
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.create_delegation(
            grantor_id="agent_grantor",
            grantee_id="agent_grantee",
            capabilities=[{"action": "browse", "scope": ["products"]}],
        )

        assert result["success"] is True
        assert result["delegation_id"] == "del_abc123"
        assert result["grantor_id"] == "agent_grantor"
        assert result["grantee_id"] == "agent_grantee"
        assert result["depth"] == 0


@pytest.mark.asyncio
@respx.mock
async def test_create_delegation_with_all_options():
    """Test delegation creation with all optional parameters."""
    respx.post("https://botcha.ai/v1/delegations").mock(
        return_value=httpx.Response(
            201,
            json={
                "success": True,
                "delegation_id": "del_full",
                "grantor_id": "agent_a",
                "grantee_id": "agent_b",
                "app_id": "app_test",
                "capabilities": [{"action": "browse"}],
                "chain": ["agent_a", "agent_b"],
                "depth": 0,
                "max_depth": 5,
                "parent_delegation_id": None,
                "created_at": "2026-02-14T00:00:00Z",
                "expires_at": "2026-02-14T02:00:00Z",
                "metadata": {"purpose": "testing"},
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.create_delegation(
            grantor_id="agent_a",
            grantee_id="agent_b",
            capabilities=[{"action": "browse"}],
            duration_seconds=7200,
            max_depth=5,
            metadata={"purpose": "testing"},
        )

        assert result["success"] is True
        assert result["max_depth"] == 5
        assert result["metadata"]["purpose"] == "testing"


@pytest.mark.asyncio
@respx.mock
async def test_create_delegation_with_app_id():
    """Test delegation creation attaches app_id query param."""
    route = respx.post("https://botcha.ai/v1/delegations?app_id=app_myapp").mock(
        return_value=httpx.Response(
            201, json={"success": True, "delegation_id": "del_x"}
        )
    )

    async with BotchaClient(app_id="app_myapp") as client:
        await client.create_delegation(
            grantor_id="a",
            grantee_id="b",
            capabilities=[{"action": "browse"}],
        )
        assert route.called


@pytest.mark.asyncio
@respx.mock
async def test_create_delegation_with_parent():
    """Test sub-delegation creation with parent_delegation_id."""
    respx.post("https://botcha.ai/v1/delegations").mock(
        return_value=httpx.Response(
            201,
            json={
                "success": True,
                "delegation_id": "del_child",
                "depth": 1,
                "parent_delegation_id": "del_parent",
                "chain": ["agent_a", "agent_b", "agent_c"],
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.create_delegation(
            grantor_id="agent_b",
            grantee_id="agent_c",
            capabilities=[{"action": "browse"}],
            parent_delegation_id="del_parent",
        )

        assert result["success"] is True
        assert result["depth"] == 1
        assert result["parent_delegation_id"] == "del_parent"


@pytest.mark.asyncio
@respx.mock
async def test_create_delegation_server_error():
    """Test delegation creation raises on server error."""
    respx.post("https://botcha.ai/v1/delegations").mock(
        return_value=httpx.Response(500, json={"message": "Internal error"})
    )

    async with BotchaClient() as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.create_delegation(
                grantor_id="a", grantee_id="b", capabilities=[{"action": "browse"}]
            )


# ============ get_delegation Tests ============


@pytest.mark.asyncio
@respx.mock
async def test_get_delegation_happy_path():
    """Test successful delegation retrieval."""
    respx.get("https://botcha.ai/v1/delegations/del_abc123").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "delegation_id": "del_abc123",
                "grantor_id": "agent_a",
                "grantee_id": "agent_b",
                "capabilities": [{"action": "browse"}],
                "revoked": False,
                "time_remaining": 3000000,
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.get_delegation("del_abc123")

        assert result["success"] is True
        assert result["delegation_id"] == "del_abc123"
        assert result["revoked"] is False


@pytest.mark.asyncio
@respx.mock
async def test_get_delegation_not_found():
    """Test delegation retrieval returns 404."""
    respx.get("https://botcha.ai/v1/delegations/del_missing").mock(
        return_value=httpx.Response(
            404, json={"success": False, "error": "DELEGATION_NOT_FOUND"}
        )
    )

    async with BotchaClient() as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.get_delegation("del_missing")


@pytest.mark.asyncio
@respx.mock
async def test_get_delegation_url_encodes():
    """Test delegation ID is URL-encoded."""
    route = respx.get("https://botcha.ai/v1/delegations/del%2Fslash").mock(
        return_value=httpx.Response(200, json={"success": True})
    )

    async with BotchaClient() as client:
        await client.get_delegation("del/slash")
        assert route.called


# ============ list_delegations Tests ============


@pytest.mark.asyncio
@respx.mock
async def test_list_delegations_happy_path():
    """Test listing delegations for an agent."""
    respx.get("https://botcha.ai/v1/delegations").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "delegations": [
                    {
                        "delegation_id": "del_1",
                        "grantor_id": "agent_a",
                        "grantee_id": "agent_b",
                    },
                    {
                        "delegation_id": "del_2",
                        "grantor_id": "agent_a",
                        "grantee_id": "agent_c",
                    },
                ],
                "count": 2,
                "agent_id": "agent_a",
                "direction": "out",
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.list_delegations("agent_a", direction="out")

        assert result["success"] is True
        assert result["count"] == 2
        assert len(result["delegations"]) == 2


@pytest.mark.asyncio
@respx.mock
async def test_list_delegations_with_filters():
    """Test listing delegations with include_revoked and include_expired."""
    route = respx.get("https://botcha.ai/v1/delegations").mock(
        return_value=httpx.Response(
            200, json={"success": True, "delegations": [], "count": 0}
        )
    )

    async with BotchaClient() as client:
        await client.list_delegations(
            "agent_a",
            direction="in",
            include_revoked=True,
            include_expired=True,
        )
        assert route.called


@pytest.mark.asyncio
@respx.mock
async def test_list_delegations_empty():
    """Test listing delegations returns empty list."""
    respx.get("https://botcha.ai/v1/delegations").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "delegations": [],
                "count": 0,
                "agent_id": "agent_x",
                "direction": "both",
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.list_delegations("agent_x")
        assert result["count"] == 0


# ============ revoke_delegation Tests ============


@pytest.mark.asyncio
@respx.mock
async def test_revoke_delegation_happy_path():
    """Test successful delegation revocation."""
    respx.post("https://botcha.ai/v1/delegations/del_abc123/revoke").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "delegation_id": "del_abc123",
                "revoked": True,
                "revoked_at": "2026-02-14T01:00:00Z",
                "revocation_reason": "no longer needed",
                "message": "Delegation revoked. Sub-delegations have been cascaded.",
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.revoke_delegation("del_abc123", reason="no longer needed")

        assert result["success"] is True
        assert result["revoked"] is True
        assert result["revocation_reason"] == "no longer needed"


@pytest.mark.asyncio
@respx.mock
async def test_revoke_delegation_without_reason():
    """Test delegation revocation without a reason."""
    respx.post("https://botcha.ai/v1/delegations/del_xyz/revoke").mock(
        return_value=httpx.Response(200, json={"success": True, "revoked": True})
    )

    async with BotchaClient() as client:
        result = await client.revoke_delegation("del_xyz")
        assert result["success"] is True


@pytest.mark.asyncio
@respx.mock
async def test_revoke_delegation_not_found():
    """Test revocation of nonexistent delegation."""
    respx.post("https://botcha.ai/v1/delegations/del_missing/revoke").mock(
        return_value=httpx.Response(
            404, json={"success": False, "error": "DELEGATION_NOT_FOUND"}
        )
    )

    async with BotchaClient() as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.revoke_delegation("del_missing")


@pytest.mark.asyncio
@respx.mock
async def test_revoke_delegation_url_encodes():
    """Test delegation ID is URL-encoded in revoke."""
    route = respx.post("https://botcha.ai/v1/delegations/del%2Fslash/revoke").mock(
        return_value=httpx.Response(200, json={"success": True})
    )

    async with BotchaClient() as client:
        await client.revoke_delegation("del/slash")
        assert route.called


# ============ verify_delegation_chain Tests ============


@pytest.mark.asyncio
@respx.mock
async def test_verify_delegation_chain_valid():
    """Test successful delegation chain verification."""
    respx.post("https://botcha.ai/v1/verify/delegation").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "valid": True,
                "chain_length": 2,
                "chain": [
                    {
                        "delegation_id": "del_1",
                        "grantor_id": "a",
                        "grantee_id": "b",
                        "depth": 0,
                    },
                    {
                        "delegation_id": "del_2",
                        "grantor_id": "b",
                        "grantee_id": "c",
                        "depth": 1,
                    },
                ],
                "effective_capabilities": [{"action": "browse", "scope": ["products"]}],
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.verify_delegation_chain("del_2")

        assert result["success"] is True
        assert result["valid"] is True
        assert result["chain_length"] == 2
        assert len(result["chain"]) == 2
        assert result["effective_capabilities"][0]["action"] == "browse"


@pytest.mark.asyncio
@respx.mock
async def test_verify_delegation_chain_invalid():
    """Test delegation chain verification fails for revoked chain."""
    respx.post("https://botcha.ai/v1/verify/delegation").mock(
        return_value=httpx.Response(
            400,
            json={
                "success": False,
                "valid": False,
                "error": "Delegation del_abc has been revoked",
            },
        )
    )

    async with BotchaClient() as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.verify_delegation_chain("del_abc")


@pytest.mark.asyncio
@respx.mock
async def test_verify_delegation_chain_server_error():
    """Test chain verification raises on server error."""
    respx.post("https://botcha.ai/v1/verify/delegation").mock(
        return_value=httpx.Response(500, json={"message": "Internal error"})
    )

    async with BotchaClient() as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.verify_delegation_chain("del_err")


# ============ issue_attestation Tests ============


@pytest.mark.asyncio
@respx.mock
async def test_issue_attestation_happy_path():
    """Test successful attestation issuance."""
    respx.post("https://botcha.ai/v1/attestations").mock(
        return_value=httpx.Response(
            201,
            json={
                "success": True,
                "attestation_id": "att_abc123",
                "agent_id": "agent_a",
                "app_id": "app_test",
                "token": "eyJ...",
                "can": ["read:invoices", "browse:*"],
                "cannot": ["write:transfers"],
                "created_at": "2026-02-14T00:00:00Z",
                "expires_at": "2026-02-14T01:00:00Z",
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.issue_attestation(
            agent_id="agent_a",
            can=["read:invoices", "browse:*"],
            cannot=["write:transfers"],
        )

        assert result["success"] is True
        assert result["attestation_id"] == "att_abc123"
        assert result["token"] == "eyJ..."
        assert result["can"] == ["read:invoices", "browse:*"]
        assert result["cannot"] == ["write:transfers"]


@pytest.mark.asyncio
@respx.mock
async def test_issue_attestation_with_all_options():
    """Test attestation issuance with all optional parameters."""
    respx.post("https://botcha.ai/v1/attestations").mock(
        return_value=httpx.Response(
            201,
            json={
                "success": True,
                "attestation_id": "att_full",
                "agent_id": "agent_a",
                "token": "eyJ...",
                "can": ["read:invoices"],
                "cannot": [],
                "restrictions": {"max_amount": 1000},
                "delegation_id": "del_abc",
                "metadata": {"purpose": "testing"},
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.issue_attestation(
            agent_id="agent_a",
            can=["read:invoices"],
            restrictions={"max_amount": 1000},
            duration_seconds=7200,
            delegation_id="del_abc",
            metadata={"purpose": "testing"},
        )

        assert result["success"] is True
        assert result["restrictions"]["max_amount"] == 1000
        assert result["delegation_id"] == "del_abc"


@pytest.mark.asyncio
@respx.mock
async def test_issue_attestation_with_app_id():
    """Test attestation issuance attaches app_id query param."""
    route = respx.post("https://botcha.ai/v1/attestations?app_id=app_myapp").mock(
        return_value=httpx.Response(
            201, json={"success": True, "attestation_id": "att_x"}
        )
    )

    async with BotchaClient(app_id="app_myapp") as client:
        await client.issue_attestation(
            agent_id="agent_a",
            can=["browse:*"],
        )
        assert route.called


@pytest.mark.asyncio
@respx.mock
async def test_issue_attestation_server_error():
    """Test attestation issuance raises on server error."""
    respx.post("https://botcha.ai/v1/attestations").mock(
        return_value=httpx.Response(500, json={"message": "Internal error"})
    )

    async with BotchaClient() as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.issue_attestation(agent_id="agent_a", can=["read:invoices"])


# ============ get_attestation Tests ============


@pytest.mark.asyncio
@respx.mock
async def test_get_attestation_happy_path():
    """Test successful attestation retrieval."""
    respx.get("https://botcha.ai/v1/attestations/att_abc123").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "attestation_id": "att_abc123",
                "can": ["read:invoices"],
                "revoked": False,
                "time_remaining": 3000000,
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.get_attestation("att_abc123")

        assert result["success"] is True
        assert result["attestation_id"] == "att_abc123"
        assert result["revoked"] is False


@pytest.mark.asyncio
@respx.mock
async def test_get_attestation_not_found():
    """Test attestation retrieval returns 404."""
    respx.get("https://botcha.ai/v1/attestations/att_missing").mock(
        return_value=httpx.Response(
            404, json={"success": False, "error": "ATTESTATION_NOT_FOUND"}
        )
    )

    async with BotchaClient() as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.get_attestation("att_missing")


@pytest.mark.asyncio
@respx.mock
async def test_get_attestation_url_encodes():
    """Test attestation ID is URL-encoded."""
    route = respx.get("https://botcha.ai/v1/attestations/att%2Fslash").mock(
        return_value=httpx.Response(200, json={"success": True})
    )

    async with BotchaClient() as client:
        await client.get_attestation("att/slash")
        assert route.called


# ============ list_attestations Tests ============


@pytest.mark.asyncio
@respx.mock
async def test_list_attestations_happy_path():
    """Test listing attestations for an agent."""
    respx.get("https://botcha.ai/v1/attestations").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "attestations": [
                    {"attestation_id": "att_1"},
                    {"attestation_id": "att_2"},
                ],
                "count": 2,
                "agent_id": "agent_a",
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.list_attestations("agent_a")

        assert result["success"] is True
        assert result["count"] == 2


@pytest.mark.asyncio
@respx.mock
async def test_list_attestations_empty():
    """Test listing attestations returns empty list."""
    respx.get("https://botcha.ai/v1/attestations").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "attestations": [],
                "count": 0,
                "agent_id": "agent_x",
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.list_attestations("agent_x")
        assert result["count"] == 0


# ============ revoke_attestation Tests ============


@pytest.mark.asyncio
@respx.mock
async def test_revoke_attestation_happy_path():
    """Test successful attestation revocation."""
    respx.post("https://botcha.ai/v1/attestations/att_abc123/revoke").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "attestation_id": "att_abc123",
                "revoked": True,
                "revoked_at": "2026-02-14T01:00:00Z",
                "revocation_reason": "abuse",
                "message": "Attestation revoked.",
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.revoke_attestation("att_abc123", reason="abuse")

        assert result["success"] is True
        assert result["revoked"] is True
        assert result["revocation_reason"] == "abuse"


@pytest.mark.asyncio
@respx.mock
async def test_revoke_attestation_without_reason():
    """Test attestation revocation without a reason."""
    respx.post("https://botcha.ai/v1/attestations/att_xyz/revoke").mock(
        return_value=httpx.Response(200, json={"success": True, "revoked": True})
    )

    async with BotchaClient() as client:
        result = await client.revoke_attestation("att_xyz")
        assert result["success"] is True


@pytest.mark.asyncio
@respx.mock
async def test_revoke_attestation_not_found():
    """Test revocation of nonexistent attestation."""
    respx.post("https://botcha.ai/v1/attestations/att_missing/revoke").mock(
        return_value=httpx.Response(
            404, json={"success": False, "error": "ATTESTATION_NOT_FOUND"}
        )
    )

    async with BotchaClient() as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.revoke_attestation("att_missing")


@pytest.mark.asyncio
@respx.mock
async def test_revoke_attestation_url_encodes():
    """Test attestation ID is URL-encoded in revoke."""
    route = respx.post("https://botcha.ai/v1/attestations/att%2Fslash/revoke").mock(
        return_value=httpx.Response(200, json={"success": True})
    )

    async with BotchaClient() as client:
        await client.revoke_attestation("att/slash")
        assert route.called


# ============ verify_attestation Tests ============


@pytest.mark.asyncio
@respx.mock
async def test_verify_attestation_token_only():
    """Test verification of attestation token without capability check."""
    respx.post("https://botcha.ai/v1/verify/attestation").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "valid": True,
                "agent_id": "agent_a",
                "can": ["read:invoices"],
                "cannot": [],
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.verify_attestation("eyJ...")

        assert result["success"] is True
        assert result["valid"] is True
        assert result["agent_id"] == "agent_a"


@pytest.mark.asyncio
@respx.mock
async def test_verify_attestation_with_capability_check():
    """Test verification with capability check."""
    respx.post("https://botcha.ai/v1/verify/attestation").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "valid": True,
                "allowed": True,
                "agent_id": "agent_a",
                "matched_rule": "read:invoices",
                "checked_capability": "read:invoices",
            },
        )
    )

    async with BotchaClient() as client:
        result = await client.verify_attestation(
            "eyJ...", action="read", resource="invoices"
        )

        assert result["allowed"] is True
        assert result["matched_rule"] == "read:invoices"


@pytest.mark.asyncio
@respx.mock
async def test_verify_attestation_denied():
    """Test verification fails when capability denied."""
    respx.post("https://botcha.ai/v1/verify/attestation").mock(
        return_value=httpx.Response(
            403,
            json={
                "success": False,
                "valid": False,
                "allowed": False,
                "error": "No matching allow rule",
            },
        )
    )

    async with BotchaClient() as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.verify_attestation(
                "eyJ...", action="write", resource="transfers"
            )


@pytest.mark.asyncio
@respx.mock
async def test_verify_attestation_invalid_token():
    """Test verification fails with invalid token."""
    respx.post("https://botcha.ai/v1/verify/attestation").mock(
        return_value=httpx.Response(
            401, json={"success": False, "valid": False, "error": "Invalid token"}
        )
    )

    async with BotchaClient() as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.verify_attestation("bad-token")

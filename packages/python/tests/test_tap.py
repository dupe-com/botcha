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

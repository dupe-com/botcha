# BOTCHA Python SDK

**Prove you're a bot. Humans need not apply.**

BOTCHA is an anti-CAPTCHA system designed to keep humans out and let AI agents in. This Python SDK provides a simple interface for AI agents to solve BOTCHA challenges and access protected endpoints.

📄 **Whitepaper:** [botcha.ai/whitepaper](https://botcha.ai/whitepaper) · 🌐 **Website:** [botcha.ai](https://botcha.ai) · 📦 **npm:** [@dupecom/botcha](https://www.npmjs.com/package/@dupecom/botcha)

## Installation

```bash
pip install botcha
```

## Quickstart

```python
from botcha import BotchaClient

async with BotchaClient() as client:
    response = await client.fetch("https://api.example.com/agent-only")
    print(response.json())
```

That's it! The client automatically handles token acquisition, challenge solving, and authentication.

## API Reference

### `BotchaClient`

HTTP client with automatic BOTCHA challenge solving and JWT token management.

#### Constructor

```python
BotchaClient(
    base_url: str = "https://botcha.ai",
    agent_identity: Optional[str] = None,
    max_retries: int = 3,
    auto_token: bool = True,
    audience: Optional[str] = None,
    app_id: Optional[str] = None,
    app_secret: Optional[str] = None,
)
```

**Parameters:**
- `base_url` (str): Base URL for the BOTCHA service. Default: `"https://botcha.ai"`
- `agent_identity` (str, optional): Custom agent identity string for User-Agent header
- `max_retries` (int): Maximum number of retries for failed requests. Default: `3`
- `auto_token` (bool): Automatically acquire and attach Bearer tokens. Default: `True`
- `audience` (str, optional): Scope tokens to a specific API/service
- `app_id` (str, optional): Multi-tenant app ID for token/challenge scoping
- `app_secret` (str, optional): App secret for app-management endpoints (`verify_email`, `resend_verification`)

#### Methods

##### `async fetch(url: str, **kwargs) -> httpx.Response`

Make an HTTP GET request with automatic BOTCHA handling.

**Features:**
- Automatically acquires and attaches Bearer token (if `auto_token=True`)
- Retries once on 401 (Unauthorized) with fresh token
- Solves inline challenges on 403 (Forbidden) responses

**Parameters:**
- `url` (str): URL to fetch
- `**kwargs`: Additional arguments passed to httpx request

**Returns:** `httpx.Response` object

**Example:**
```python
async with BotchaClient() as client:
    response = await client.fetch("https://api.example.com/data")
    data = response.json()
```

##### `async get_token() -> str`

Acquire or return cached JWT token.

Implements token caching with a buffer before expiry. If token is cached and valid, returns the cached token. Otherwise, acquires a new token via the challenge flow:

1. GET `/v1/token` to receive challenge
2. Solve challenge problems
3. POST `/v1/token/verify` with solutions
4. Parse and cache JWT token

**Returns:** JWT token string

**Example:**
```python
async with BotchaClient() as client:
    token = await client.get_token()
    print(f"Token: {token}")
```

##### `solve(problems: list[int]) -> list[str]`

Solve BOTCHA challenge problems synchronously.

**Parameters:**
- `problems` (list[int]): List of 6-digit integers to solve

**Returns:** List of 8-character hex strings (SHA256 hash prefixes)

**Example:**
```python
client = BotchaClient()
answers = client.solve([123456, 789012])
print(answers)  # ['8d969eef', 'ca2f2c8f']
```

##### `async close() -> None`

Close the underlying HTTP client. Automatically called when using async context manager.

##### `async create_app(email: str) -> CreateAppResponse`

Create a new BOTCHA app. Returns `app_id` and `app_secret`.

##### `async verify_email(code: str, app_id: str = None, app_secret: str = None) -> VerifyEmailResponse`

Verify email with 6-digit code sent to your email.

##### `async resend_verification(app_id: str = None, app_secret: str = None) -> ResendVerificationResponse`

Resend the email verification code.

##### `async recover_account(email: str) -> RecoverAccountResponse`

Request account recovery via verified email.

##### `async rotate_secret(app_id: str = None) -> RotateSecretResponse`

Rotate the app secret. Old secret is immediately invalidated.

##### TAP (Trusted Agent Protocol) Methods

##### `async register_tap_agent(name, operator=None, version=None, public_key=None, signature_algorithm=None, capabilities=None, trust_level=None, issuer=None) -> TAPAgentResponse`

Register an agent with TAP capabilities including cryptographic identity and capability-scoped permissions.

##### `async get_tap_agent(agent_id: str) -> TAPAgentResponse`

Get a TAP agent by ID, including public key and verification status.

##### `async list_tap_agents(tap_only: bool = False) -> TAPAgentListResponse`

List TAP agents for the current app. Set `tap_only=True` to filter to TAP-enabled agents only.

##### `async create_tap_session(agent_id: str, user_context: str, intent: dict) -> TAPSessionResponse`

Create a TAP session with intent validation. The intent dict should include `action`, and optionally `resource`, `scope`, and `duration`.

##### `async get_tap_session(session_id: str) -> TAPSessionResponse`

Get a TAP session by ID, including time remaining before expiry.

##### `async rotate_agent_key(agent_id: str) -> RotateKeyResponse`

Rotate the key pair for a TAP-registered agent. Returns the new public key.

##### Delegation Methods

##### `async create_delegation(grantor_id: str, grantee_id: str, capabilities: list, ttl: int = 3600, parent_delegation_id: str = None) -> DelegationResponse`

Delegate capabilities from one agent to another. Capabilities can only be narrowed, never expanded. Supports chained delegation via `parent_delegation_id`.

##### `async get_delegation(delegation_id: str) -> DelegationResponse`

Get delegation details by ID.

##### `async list_delegations(agent_id: str, direction: str = 'both') -> DelegationListResponse`

List delegations for an agent. `direction` can be `'in'`, `'out'`, or `'both'`.

##### `async revoke_delegation(delegation_id: str, reason: str = None) -> RevokeResponse`

Revoke a delegation. Cascades to all sub-delegations.

##### `async verify_delegation_chain(delegation_id: str) -> DelegationChainResponse`

Verify the entire delegation chain and compute effective capabilities.

##### Attestation Methods

##### `async issue_attestation(agent_id: str, can: list[str], cannot: list[str] = None, ttl: int = 3600, delegation_id: str = None) -> AttestationResponse`

Issue a capability attestation token with `action:resource` permission patterns and explicit deny rules. Wildcards supported (`browse:*`, `*:products`).

##### `async get_attestation(attestation_id: str) -> AttestationResponse`

Get attestation details by ID.

##### `async list_attestations(agent_id: str) -> AttestationListResponse`

List attestations for an agent.

##### `async revoke_attestation(attestation_id: str, reason: str = None) -> RevokeResponse`

Revoke an attestation token.

##### `async verify_attestation(token: str, action: str, resource: str) -> AttestationVerifyResponse`

Verify an attestation token and check if a specific capability is allowed.

##### Reputation Methods

##### `async get_reputation(agent_id: str) -> ReputationResponse`

Get an agent's reputation score (0–1000) and tier (`untrusted`, `low`, `neutral`, `good`, `excellent`).

##### `async record_reputation_event(agent_id: str, category: str, action: str, metadata: dict = None, source_agent_id: str = None) -> ReputationEventResponse`

Record a reputation event. Categories: `verification`, `commerce`, `compliance`, `social`, `security`, `governance`.

##### `async list_reputation_events(agent_id: str, category: str = None, limit: int = 50) -> ReputationEventListResponse`

List reputation events for an agent, optionally filtered by category.

##### `async reset_reputation(agent_id: str) -> ResetResponse`

Reset an agent's reputation to the neutral base score (admin use).

##### Webhook Methods

##### `async create_webhook(url: str, events: list[str]) -> WebhookResponse`

Register a webhook endpoint. Returns the signing secret once — save it.

##### `async list_webhooks() -> WebhookListResponse`

List all webhooks for the current app.

##### `async get_webhook(webhook_id: str) -> WebhookResponse`

Get webhook details by ID.

##### `async update_webhook(webhook_id: str, url: str = None, events: list[str] = None, enabled: bool = None) -> WebhookResponse`

Update webhook URL, event subscriptions, or enabled state.

##### `async delete_webhook(webhook_id: str) -> DeleteResponse`

Delete a webhook and all its delivery logs.

##### `async test_webhook(webhook_id: str) -> WebhookTestResponse`

Send a signed test event to the webhook endpoint.

##### `async list_webhook_deliveries(webhook_id: str) -> WebhookDeliveryListResponse`

List the last 100 delivery attempts for a webhook.

##### x402 Methods

##### `async get_x402_info() -> X402InfoResponse`

Get payment configuration: amount, currency (USDC), chain (base), and recipient address.

##### `async get_x402_challenge(payment_proof: str = None) -> X402ChallengeResponse`

Initiate the x402 payment flow. Without a proof, returns a 402 with payment terms. With a valid `payment_proof`, returns a BOTCHA access token.

##### `async verify_x402_payment(payment_proof: str, chain: str = 'base') -> X402VerifyResponse`

Verify a raw x402 payment proof.

##### ANS Methods

##### `async get_ans_identity() -> ANSIdentityResponse`

Get BOTCHA's own ANS identity record.

##### `async resolve_ans_name(name: str) -> ANSResolveResponse`

Resolve an agent name to its ANS record via DNS TXT lookup.

##### `async discover_ans_agents() -> ANSDiscoverResponse`

List all BOTCHA-verified ANS agents.

##### `async get_ans_nonce(name: str) -> ANSNonceResponse`

Get a one-time nonce for ANS ownership verification. Requires Bearer token.

##### `async verify_ans_ownership(name: str, agent_url: str, nonce: str, proof: str) -> ANSVerifyResponse`

Prove ownership of an ANS name and receive a BOTCHA-signed badge JWT.

##### DID / Verifiable Credential Methods

##### `async issue_credential(subject: dict, credential_type: list[str] = None, ttl_seconds: int = 3600) -> VCResponse`

Issue a W3C Verifiable Credential JWT. Requires Bearer token. The VC is signed with BOTCHA's private key and can be verified by any party who resolves `did:web:botcha.ai`.

##### `async verify_credential(vc: str) -> VCVerifyResponse`

Verify a BOTCHA-issued VC JWT. Public endpoint — no auth required.

##### `async resolve_did(did: str) -> DIDDocumentResponse`

Resolve a `did:web` DID to its DID Document.

##### A2A Methods

##### `async get_agent_card() -> A2ACardResponse`

Get BOTCHA's own A2A Agent Card.

##### `async attest_agent_card(card: dict, duration_seconds: int = 86400, trust_level: str = 'verified') -> A2AAttestResponse`

Submit an A2A Agent Card for BOTCHA attestation. Returns a tamper-evident trust seal. Requires Bearer token.

##### `async verify_agent_card(card: dict) -> A2AVerifyResponse`

Verify the BOTCHA trust seal on an attested agent card.

##### `async verify_agent(agent_url: str = None, agent_card: dict = None) -> A2AVerifyResponse`

Verify an agent by URL or full card with embedded attestation.

##### `async get_trust_level(agent_url: str) -> A2ATrustLevelResponse`

Get the current BOTCHA trust level for an agent URL. Returns `"unverified"` if no attestation exists.

##### `async list_attested_cards() -> A2ACardListResponse`

Browse the registry of all BOTCHA-attested A2A agent cards.

##### OIDC-A Methods

##### `async issue_eat(agent_model: str = None, ttl_seconds: int = 900, verification_method: str = None, nonce: str = None) -> EATResponse`

Issue an Entity Attestation Token (EAT / RFC 9334). Requires Bearer token. Suitable for presentation to enterprise relying parties.

##### `async issue_oidca_claims(agent_model: str = None, agent_version: str = None, agent_capabilities: list[str] = None, agent_operator: str = None, human_oversight_required: bool = False, task_id: str = None, task_purpose: str = None, nonce: str = None) -> OIDCAClaimsResponse`

Issue an OIDC-A agent claims block JWT. Suitable for inclusion in OAuth2 token responses.

##### `async create_agent_grant(scope: str, human_oversight_required: bool = False, agent_model: str = None, agent_operator: str = None, task_id: str = None, task_purpose: str = None) -> AgentGrantResponse`

Initiate an OAuth2-style agent grant flow. If `human_oversight_required=True`, returns a pending grant with an `oversight_url` for the human to approve.

##### `async get_agent_grant_status(grant_id: str) -> AgentGrantStatusResponse`

Poll the status of an agent grant.

##### `async resolve_agent_grant(grant_id: str, decision: str) -> AgentGrantResolveResponse`

Approve or reject an agent grant. `decision` is `"approved"` or `"rejected"`.

##### `async get_oidc_userinfo() -> OIDCUserInfoResponse`

Get OIDC-A UserInfo claims for the currently authenticated agent.

---

### `solve_botcha(problems: list[int]) -> list[str]`

Standalone function to solve BOTCHA speed challenges without needing a client instance.

**Parameters:**
- `problems` (list[int]): List of 6-digit integers to solve

**Returns:** List of 8-character hex strings (SHA256 hash prefixes)

**Example:**
```python
from botcha import solve_botcha

answers = solve_botcha([123456, 789012])
print(answers)  # ['8d969eef', 'ca2f2c8f']
```

## Usage Examples

### Basic Usage with Auto-Token

The simplest way to use BOTCHA - the client handles everything automatically:

```python
import asyncio
from botcha import BotchaClient

async def main():
    async with BotchaClient(base_url="https://botcha.ai") as client:
        # Client automatically acquires token and solves challenges
        response = await client.fetch("https://api.example.com/agent-only")
        print(response.json())

asyncio.run(main())
```

### Manual Token Acquisition

If you need more control over token management:

```python
import asyncio
from botcha import BotchaClient

async def main():
    async with BotchaClient(auto_token=False) as client:
        # Manually acquire token
        token = await client.get_token()
        print(f"Acquired token: {token}")
        
        # Use token in custom requests
        response = await client.fetch(
            "https://api.example.com/data",
            headers={"Authorization": f"Bearer {token}"}
        )
        print(response.json())

asyncio.run(main())
```

### Standalone Solver

Use the solver without creating a client instance:

```python
from botcha import solve_botcha

# Solve challenges independently
problems = [123456, 789012, 456789]
answers = solve_botcha(problems)

print(f"Problems: {problems}")
print(f"Answers: {answers}")
# Problems: [123456, 789012, 456789]
# Answers: ['8d969eef', 'ca2f2c8f', 'c888c9ce']
```

### Custom Agent Identity

Set a custom User-Agent header for your bot:

```python
import asyncio
from botcha import BotchaClient

async def main():
    async with BotchaClient(agent_identity="MyBot/1.0") as client:
        response = await client.fetch("https://api.example.com/data")
        print(response.json())

asyncio.run(main())
```

### Inline Challenge Handling

The client automatically handles inline challenges (403 responses):

```python
import asyncio
from botcha import BotchaClient

async def main():
    async with BotchaClient() as client:
        # If the endpoint returns a 403 with a BOTCHA challenge,
        # the client automatically solves it and retries
        response = await client.fetch("https://api.example.com/protected")
        
        # You get the successful response without manual intervention
        print(response.json())

asyncio.run(main())
```

### Error Handling

Handle errors gracefully:

```python
import asyncio
import httpx
from botcha import BotchaClient

async def main():
    try:
        async with BotchaClient() as client:
            response = await client.fetch("https://api.example.com/data")
            response.raise_for_status()
            print(response.json())
    except httpx.HTTPError as e:
        print(f"Request failed: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

asyncio.run(main())
```

### TAP (Trusted Agent Protocol)

Enterprise-grade cryptographic agent authentication:

```python
import asyncio
from botcha import BotchaClient

async def main():
    async with BotchaClient(app_id="app_abc123") as client:
        # Register a TAP agent
        agent = await client.register_tap_agent(
            name="my-agent",
            operator="Acme Corp",
            trust_level="verified",
            capabilities=[{"action": "browse", "scope": ["products"]}],
        )
        print(f"Agent ID: {agent.agent_id}")

        # Create a TAP session
        session = await client.create_tap_session(
            agent_id=agent.agent_id,
            user_context="user-hash",
            intent={"action": "browse", "resource": "products", "duration": 3600},
        )
        print(f"Session expires: {session.expires_at}")

asyncio.run(main())
```

### Delegation Chains

Delegate capabilities between agents with auditable, revocable chains:

```python
import asyncio
from botcha import BotchaClient

async def main():
    async with BotchaClient(app_id="app_abc123") as client:
        # Agent A delegates to Agent B
        delegation = await client.create_delegation(
            grantor_id="agent_aaa",
            grantee_id="agent_bbb",
            capabilities=[{"action": "browse", "resource": "products"}],
            ttl=3600,
        )

        # Verify the full chain
        chain = await client.verify_delegation_chain(delegation.delegation_id)
        print(f"Effective capabilities: {chain.effective_capabilities}")

        # Revoke (cascades to all sub-delegations)
        await client.revoke_delegation(delegation.delegation_id, reason="Session ended")

asyncio.run(main())
```

### Capability Attestation

Fine-grained action:resource permission tokens with deny rules:

```python
import asyncio
from botcha import BotchaClient

async def main():
    async with BotchaClient(app_id="app_abc123") as client:
        # Issue attestation
        att = await client.issue_attestation(
            agent_id="agent_abc123",
            can=["read:invoices", "browse:*"],
            cannot=["purchase:*"],
            ttl=3600,
        )
        print(f"Token: {att.token}")

        # Verify capability
        check = await client.verify_attestation(att.token, "read", "invoices")
        print(f"Allowed: {check.allowed}")  # True

asyncio.run(main())
```

### Agent Reputation

Track agent trust scores over time:

```python
import asyncio
from botcha import BotchaClient

async def main():
    async with BotchaClient(app_id="app_abc123") as client:
        # Get reputation
        rep = await client.get_reputation("agent_abc123")
        print(f"Score: {rep.score}, Tier: {rep.tier}")

        # Record positive event
        await client.record_reputation_event(
            agent_id="agent_abc123",
            category="verification",
            action="challenge_solved",
        )

        # Endorsement from another agent
        await client.record_reputation_event(
            agent_id="agent_abc123",
            category="social",
            action="endorsement_received",
            source_agent_id="agent_def456",
        )

asyncio.run(main())
```

### DID / Verifiable Credentials

Issue and verify portable W3C credential JWTs:

```python
import asyncio
from botcha import BotchaClient

async def main():
    async with BotchaClient() as client:
        # Issue a verifiable credential
        vc_result = await client.issue_credential(
            subject={"agentType": "llm", "operator": "Acme Corp"},
            credential_type=["VerifiableCredential", "BotchaVerification"],
            ttl_seconds=3600,
        )
        print(f"VC JWT: {vc_result.vc}")

        # Anyone can verify — no auth required
        verified = await client.verify_credential(vc_result.vc)
        print(f"Valid: {verified.valid}")
        print(f"Issuer: {verified.payload['iss']}")  # did:web:botcha.ai

asyncio.run(main())
```

### A2A Agent Card Attestation

Get a BOTCHA trust seal for your A2A Agent Card:

```python
import asyncio
from botcha import BotchaClient

async def main():
    async with BotchaClient() as client:
        # Attest your agent's card
        result = await client.attest_agent_card(
            card={
                "name": "My Commerce Agent",
                "url": "https://myagent.example",
                "version": "1.0.0",
                "capabilities": {"streaming": False},
                "skills": [{"id": "browse", "name": "Browse"}],
            },
            trust_level="verified",
        )
        print(f"Trust seal: {result.attestation.token}")

        # Verify an attested card
        check = await client.verify_agent_card(result.attested_card)
        print(f"Valid: {check.valid}")

asyncio.run(main())
```

### OIDC-A Attestation

Enterprise agent auth chains with EAT tokens and agent grants:

```python
import asyncio
from botcha import BotchaClient

async def main():
    async with BotchaClient() as client:
        # Issue an Entity Attestation Token (EAT)
        eat = await client.issue_eat(
            agent_model="gpt-5",
            ttl_seconds=900,
            verification_method="speed-challenge",
        )
        print(f"EAT token: {eat.token}")

        # Initiate an agent grant (OAuth2-style)
        grant = await client.create_agent_grant(
            scope="agent:read openid",
            human_oversight_required=True,
            agent_model="gpt-5",
            task_purpose="invoice reconciliation",
        )
        print(f"Grant status: {grant.status}")
        if grant.oversight_url:
            print(f"Human oversight required: {grant.oversight_url}")

asyncio.run(main())
```

## How It Works

BOTCHA is a speed challenge designed to prove computational capability:

1. **Challenge Generation**: Server generates a list of 6-digit integers
2. **Solving**: Client computes SHA256 hash of each integer and returns the first 8 hex characters
3. **Verification**: Server validates solutions within the time limit (typically 10 seconds)
4. **Token Issuance**: Upon successful verification, server issues a JWT token

**Why it works:**
- **Fast for bots**: Modern computers can solve thousands of challenges per second
- **Slow for humans**: Manual calculation is impractical
- **Simple to implement**: Standard SHA256 hashing, no complex cryptography
- **Stateless**: No session management required

**Security properties:**
- Solutions cannot be precomputed (random challenges)
- Time-limited to prevent delayed solving
- JWT tokens expire to limit attack windows
- No brute-force protection needed (humans self-exclude)

## Type Hints

This package includes type hints (PEP 484) and ships with a `py.typed` marker for full type checking support in IDEs and tools like mypy.

## Requirements

- Python >= 3.9
- httpx >= 0.27

## Development

```bash
# Clone the repository
git clone https://github.com/dupe-com/botcha.git
cd botcha/packages/python

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run type checking
mypy src/botcha
```

## Links

- **Website**: [https://botcha.ai](https://botcha.ai)
- **Repository**: [https://github.com/dupe-com/botcha](https://github.com/dupe-com/botcha)
- **Issues**: [https://github.com/dupe-com/botcha/issues](https://github.com/dupe-com/botcha/issues)
- **PyPI**: [https://pypi.org/project/botcha/](https://pypi.org/project/botcha/)

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

Ramin <ramin@dupe.com>

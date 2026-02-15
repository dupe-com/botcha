"""Type definitions for BOTCHA SDK."""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Union


@dataclass
class ChallengeResponse:
    """Response from the /challenge endpoint."""

    id: str
    problems: list[int]
    time_limit: int


@dataclass
class TokenResponse:
    """Response from the /solve endpoint."""

    verified: bool
    token: str
    solve_time_ms: float


@dataclass
class VerifyResponse:
    """Response from the /verify endpoint."""

    verified: bool
    method: Optional[str] = None
    hint: Optional[str] = None


# ============ App Management Types ============


@dataclass
class CreateAppResponse:
    """Response from POST /v1/apps."""

    success: bool
    app_id: str
    app_secret: str
    email: str
    email_verified: bool = False
    verification_required: bool = True
    warning: str = ""
    credential_advice: str = ""
    created_at: str = ""
    rate_limit: int = 100
    next_step: str = ""


@dataclass
class VerifyEmailResponse:
    """Response from POST /v1/apps/:id/verify-email."""

    success: bool
    email_verified: Optional[bool] = None
    error: Optional[str] = None
    message: Optional[str] = None


@dataclass
class ResendVerificationResponse:
    """Response from POST /v1/apps/:id/resend-verification."""

    success: bool
    message: Optional[str] = None
    error: Optional[str] = None


@dataclass
class RecoverAccountResponse:
    """Response from POST /v1/auth/recover."""

    success: bool
    message: str = ""


@dataclass
class RotateSecretResponse:
    """Response from POST /v1/apps/:id/rotate-secret."""

    success: bool
    app_id: Optional[str] = None
    app_secret: Optional[str] = None
    warning: Optional[str] = None
    rotated_at: Optional[str] = None
    error: Optional[str] = None
    message: Optional[str] = None


# ============ TAP (Trusted Agent Protocol) Types ============


@dataclass
class TAPCapability:
    """TAP capability defining what actions an agent can perform."""

    action: str  # browse, compare, purchase, audit, search
    scope: Optional[list[str]] = None
    restrictions: Optional[dict] = None


@dataclass
class TAPIntent:
    """TAP intent declaring what an agent wants to do."""

    action: str
    resource: Optional[str] = None
    scope: Optional[list[str]] = None
    duration: Optional[int] = None


@dataclass
class TAPAgentResponse:
    """Response from TAP agent registration or retrieval."""

    success: bool
    agent_id: str
    app_id: str = ""
    name: str = ""
    operator: Optional[str] = None
    version: Optional[str] = None
    created_at: str = ""
    tap_enabled: bool = False
    trust_level: Optional[str] = None
    capabilities: Optional[list[dict]] = None
    signature_algorithm: Optional[str] = None
    issuer: Optional[str] = None
    has_public_key: bool = False
    key_fingerprint: Optional[str] = None
    last_verified_at: Optional[str] = None
    public_key: Optional[str] = None


@dataclass
class TAPAgentListResponse:
    """Response from listing TAP agents."""

    success: bool
    agents: list[dict] = field(default_factory=list)
    count: int = 0
    tap_enabled_count: int = 0


@dataclass
class TAPSessionResponse:
    """Response from TAP session creation or retrieval."""

    success: bool
    session_id: str
    agent_id: str = ""
    app_id: str = ""
    capabilities: Optional[list[dict]] = None
    intent: Optional[dict] = None
    created_at: str = ""
    expires_at: str = ""
    time_remaining: Optional[int] = None


# ============ JWK / JWKS Types ============


@dataclass
class JWK:
    """JSON Web Key"""

    kty: str
    kid: str
    use: str
    alg: str
    n: Optional[str] = None
    e: Optional[str] = None
    crv: Optional[str] = None
    x: Optional[str] = None
    y: Optional[str] = None
    agent_id: Optional[str] = None
    agent_name: Optional[str] = None
    expires_at: Optional[str] = None


@dataclass
class JWKSet:
    """JSON Web Key Set"""

    keys: List[JWK]


# ============ Agentic Consumer Recognition Types ============


@dataclass
class ContextualData:
    """Consumer contextual data (TAP Layer 2)"""

    country_code: Optional[str] = None
    zip: Optional[str] = None
    ip_address: Optional[str] = None
    device_data: Optional[Dict[str, Any]] = None


@dataclass
class IDTokenClaims:
    """OIDC ID Token claims"""

    iss: str = ""
    sub: str = ""
    aud: Union[str, List[str]] = ""
    exp: int = 0
    iat: int = 0
    jti: Optional[str] = None
    auth_time: Optional[int] = None
    amr: Optional[List[str]] = None
    phone_number: Optional[str] = None
    phone_number_verified: Optional[bool] = None
    phone_number_mask: Optional[str] = None
    email: Optional[str] = None
    email_verified: Optional[bool] = None
    email_mask: Optional[str] = None


@dataclass
class AgenticConsumerResult:
    """Result from agentic consumer verification"""

    verified: bool
    nonce_linked: bool
    signature_valid: bool
    id_token_valid: Optional[bool] = None
    id_token_claims: Optional[IDTokenClaims] = None
    contextual_data: Optional[ContextualData] = None
    error: Optional[str] = None


# ============ Agentic Payment Types ============


@dataclass
class CardMetadata:
    """Card metadata from Agentic Payment Container"""

    last_four: str = ""
    payment_account_reference: str = ""
    short_description: Optional[str] = None
    card_data: Optional[List[Dict[str, Any]]] = None


@dataclass
class CredentialHash:
    """Credential hash for payment verification"""

    hash: str = ""
    algorithm: str = ""


@dataclass
class BrowsingIOU:
    """Browsing IOU for 402 micropayment flow"""

    invoice_id: str = ""
    amount: str = ""
    card_acceptor_id: str = ""
    acquirer_id: str = ""
    uri: str = ""
    sequence_counter: str = ""
    payment_service: str = ""
    kid: str = ""
    alg: str = ""
    signature: str = ""


# ============ Invoice Types (402 Flow) ============


@dataclass
class InvoiceResponse:
    """Invoice details for 402 flow"""

    success: bool = False
    invoice_id: str = ""
    app_id: str = ""
    resource_uri: str = ""
    amount: str = ""
    currency: str = ""
    card_acceptor_id: str = ""
    description: Optional[str] = None
    created_at: str = ""
    expires_at: str = ""
    status: str = "pending"


@dataclass
class VerifyIOUResponse:
    """IOU verification result"""

    success: bool = False
    verified: bool = False
    access_token: Optional[str] = None
    expires_at: Optional[str] = None
    error: Optional[str] = None


# ============ Delegation Chain Types ============


@dataclass
class DelegationResponse:
    """Response from delegation creation or retrieval."""

    success: bool = False
    delegation_id: str = ""
    grantor_id: str = ""
    grantee_id: str = ""
    app_id: str = ""
    capabilities: Optional[List[Dict[str, Any]]] = None
    chain: Optional[List[str]] = None
    depth: int = 0
    max_depth: int = 3
    parent_delegation_id: Optional[str] = None
    created_at: str = ""
    expires_at: str = ""
    revoked: bool = False
    revoked_at: Optional[str] = None
    revocation_reason: Optional[str] = None
    metadata: Optional[Dict[str, str]] = None
    time_remaining: Optional[int] = None


@dataclass
class DelegationListResponse:
    """Response from listing delegations."""

    success: bool = False
    delegations: Optional[List[Dict[str, Any]]] = None
    count: int = 0
    agent_id: str = ""
    direction: str = "both"


@dataclass
class RevokeDelegationResponse:
    """Response from revoking a delegation."""

    success: bool = False
    delegation_id: str = ""
    revoked: bool = False
    revoked_at: Optional[str] = None
    revocation_reason: Optional[str] = None
    message: str = ""


@dataclass
class DelegationVerifyResponse:
    """Response from verifying a delegation chain."""

    success: bool = False
    valid: bool = False
    chain_length: Optional[int] = None
    chain: Optional[List[Dict[str, Any]]] = None
    effective_capabilities: Optional[List[Dict[str, Any]]] = None
    error: Optional[str] = None


# ============ Capability Attestation Types ============


@dataclass
class AttestationResponse:
    """Response from attestation issuance or retrieval."""

    success: bool = False
    attestation_id: str = ""
    agent_id: str = ""
    app_id: str = ""
    token: str = ""
    can: Optional[List[str]] = None
    cannot: Optional[List[str]] = None
    restrictions: Optional[Dict[str, Any]] = None
    delegation_id: Optional[str] = None
    metadata: Optional[Dict[str, str]] = None
    created_at: str = ""
    expires_at: str = ""
    revoked: bool = False
    revoked_at: Optional[str] = None
    revocation_reason: Optional[str] = None
    time_remaining: Optional[int] = None


@dataclass
class AttestationListResponse:
    """Response from listing attestations."""

    success: bool = False
    attestations: Optional[List[Dict[str, Any]]] = None
    count: int = 0
    agent_id: str = ""


@dataclass
class RevokeAttestationResponse:
    """Response from revoking an attestation."""

    success: bool = False
    attestation_id: str = ""
    revoked: bool = False
    revoked_at: Optional[str] = None
    revocation_reason: Optional[str] = None
    message: str = ""


@dataclass
class AttestationVerifyResponse:
    """Response from verifying an attestation token."""

    success: bool = False
    valid: bool = False
    allowed: Optional[bool] = None
    agent_id: Optional[str] = None
    issuer: Optional[str] = None
    can: Optional[List[str]] = None
    cannot: Optional[List[str]] = None
    restrictions: Optional[Dict[str, Any]] = None
    delegation_id: Optional[str] = None
    issued_at: Optional[str] = None
    expires_at: Optional[str] = None
    reason: Optional[str] = None
    matched_rule: Optional[str] = None
    checked_capability: Optional[str] = None
    error: Optional[str] = None


# ============ Agent Reputation Scoring Types ============


@dataclass
class ReputationScoreResponse:
    """Response from getting an agent's reputation score."""

    success: bool = False
    agent_id: str = ""
    app_id: str = ""
    score: int = 500
    tier: str = "neutral"
    event_count: int = 0
    positive_events: int = 0
    negative_events: int = 0
    last_event_at: Optional[str] = None
    created_at: str = ""
    updated_at: str = ""
    category_scores: Optional[Dict[str, int]] = None


@dataclass
class ReputationEventResponse:
    """Response from recording a reputation event."""

    success: bool = False
    event: Optional[Dict[str, Any]] = None
    score: Optional[Dict[str, Any]] = None


@dataclass
class ReputationEventListResponse:
    """Response from listing reputation events."""

    success: bool = False
    events: Optional[List[Dict[str, Any]]] = None
    count: int = 0
    agent_id: str = ""


@dataclass
class ReputationResetResponse:
    """Response from resetting an agent's reputation."""

    success: bool = False
    agent_id: str = ""
    score: int = 500
    tier: str = "neutral"
    message: str = ""

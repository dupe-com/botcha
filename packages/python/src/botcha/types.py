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

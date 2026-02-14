"""Type definitions for BOTCHA SDK."""

from dataclasses import dataclass, field
from typing import Optional


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

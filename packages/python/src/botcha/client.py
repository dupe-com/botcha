"""BotchaClient - HTTP client for interacting with BOTCHA-protected endpoints."""

import base64
import json
import time
from typing import Any, Optional
from urllib.parse import quote

import httpx

from botcha.solver import solve_botcha
from botcha.types import (
    ChallengeResponse,
    CreateAppResponse,
    RecoverAccountResponse,
    ResendVerificationResponse,
    RotateSecretResponse,
    TAPAgentListResponse,
    TAPAgentResponse,
    TAPSessionResponse,
    TokenResponse,
    VerifyEmailResponse,
)


class BotchaClient:
    """
    HTTP client with automatic BOTCHA challenge solving and JWT token management.

    Handles:
    - Token acquisition and caching via /v1/token endpoint
    - Token rotation with refresh tokens (5-minute access tokens)
    - Automatic token refresh on 401 responses (tries refresh first, then re-verify)
    - Inline challenge solving on 403 responses
    - Bearer token authentication with optional audience claims

    Example:
        >>> async with BotchaClient(audience="api.example.com") as client:
        ...     response = await client.fetch("https://api.example.com/data")
        ...     print(response.json())
    """

    def __init__(
        self,
        base_url: str = "https://botcha.ai",
        agent_identity: Optional[str] = None,
        max_retries: int = 3,
        auto_token: bool = True,
        audience: Optional[str] = None,
        app_id: Optional[str] = None,
    ):
        """
        Initialize the BotchaClient.

        Args:
            base_url: Base URL for the BOTCHA service (default: https://botcha.ai)
            agent_identity: Optional agent identity string for User-Agent header
            max_retries: Maximum number of retries for failed requests (default: 3)
            auto_token: Automatically acquire and attach Bearer tokens (default: True)
            audience: Optional audience claim for token verification
            app_id: Optional multi-tenant application ID
        """
        self.base_url = base_url.rstrip("/")
        self.agent_identity = agent_identity
        self.max_retries = max_retries
        self.auto_token = auto_token
        self.audience = audience
        self.app_id = app_id

        self._token: Optional[str] = None
        self._token_expires_at: float = 0
        self._refresh_token: Optional[str] = None

        # Create httpx AsyncClient with custom headers
        headers = {}
        if agent_identity:
            headers["User-Agent"] = agent_identity

        self._client = httpx.AsyncClient(headers=headers, timeout=30.0)

    def solve(self, problems: list[int]) -> list[str]:
        """
        Solve BOTCHA challenge problems synchronously.

        Args:
            problems: List of 6-digit integers to solve

        Returns:
            List of 8-character hex strings (SHA256 hash prefixes)
        """
        return solve_botcha(problems)

    async def get_token(self) -> str:
        """
        Acquire or return cached JWT access token.

        Implements token caching with 5-minute buffer before expiry.
        If token is cached and valid (>5min before expiry), returns cached token.
        Otherwise, acquires new token via challenge flow:
        1. GET /v1/token to get challenge
        2. Solve challenge problems
        3. POST /v1/token/verify with solutions (including audience if set)
        4. Parse and cache access token (5-minute expiry) and refresh token (1-hour expiry)

        Returns:
            JWT access token string

        Raises:
            httpx.HTTPError: If token acquisition fails
        """
        # Check if cached token is still valid (>5min before expiry)
        now = time.time()
        if self._token and self._token_expires_at > (now + 300):  # 300s = 5min buffer
            return self._token

        # Step 1: Get challenge
        token_url = f"{self.base_url}/v1/token"
        if self.app_id:
            token_url += f"?app_id={self.app_id}"
        challenge_response = await self._client.get(token_url)
        challenge_response.raise_for_status()
        challenge_data = challenge_response.json()

        # Parse challenge
        challenge = ChallengeResponse(
            id=challenge_data["id"],
            problems=challenge_data["problems"],
            time_limit=challenge_data["timeLimit"],
        )

        # Step 2: Solve challenge
        solutions = self.solve(challenge.problems)

        # Step 3: Verify and get token
        verify_payload = {"id": challenge.id, "answers": solutions}
        if self.audience:
            verify_payload["audience"] = self.audience
        if self.app_id:
            verify_payload["app_id"] = self.app_id

        verify_response = await self._client.post(
            f"{self.base_url}/v1/token/verify",
            json=verify_payload,
        )
        verify_response.raise_for_status()
        verify_data = verify_response.json()

        # Parse token response
        token_response = TokenResponse(
            verified=verify_data["verified"],
            token=verify_data["token"],
            solve_time_ms=verify_data["solveTimeMs"],
        )

        # Cache the access token
        self._token = token_response.token

        # Store refresh token if provided
        if "refresh_token" in verify_data:
            self._refresh_token = verify_data["refresh_token"]

        # Set token expiry from expires_in (5 minutes = 300 seconds)
        if "expires_in" in verify_data:
            self._token_expires_at = now + verify_data["expires_in"]
        else:
            # Fallback: Parse expiry from JWT payload
            try:
                # JWT structure: header.payload.signature
                parts = token_response.token.split(".")
                if len(parts) >= 2:
                    # Decode payload (add padding if needed)
                    payload_b64 = parts[1]
                    # Add padding for proper base64 decoding
                    padding = 4 - (len(payload_b64) % 4)
                    if padding != 4:
                        payload_b64 += "=" * padding

                    payload_bytes = base64.urlsafe_b64decode(payload_b64)
                    payload = json.loads(payload_bytes)

                    # Extract expiry timestamp
                    if "exp" in payload:
                        self._token_expires_at = float(payload["exp"])
                    else:
                        # Default to 5 minutes from now if no exp field
                        self._token_expires_at = now + 300
                else:
                    # Invalid JWT format, default to 5 minutes
                    self._token_expires_at = now + 300
            except Exception:
                # Failed to parse JWT, default to 5 minutes expiry
                self._token_expires_at = now + 300

        return self._token

    async def refresh_token(self) -> str:
        """
        Refresh the access token using the stored refresh token.

        Uses the refresh token to obtain a new access token without solving
        a new challenge. This is faster than get_token() for refreshing
        expired access tokens.

        Returns:
            New access token string

        Raises:
            httpx.HTTPError: If token refresh fails
            ValueError: If no refresh token is available
        """
        if not self._refresh_token:
            raise ValueError("No refresh token available")

        # Call refresh endpoint
        refresh_response = await self._client.post(
            f"{self.base_url}/v1/token/refresh",
            json={"refresh_token": self._refresh_token},
        )
        refresh_response.raise_for_status()
        refresh_data = refresh_response.json()

        # Update access token
        self._token = refresh_data["access_token"]

        # Update expiry time
        now = time.time()
        if "expires_in" in refresh_data:
            self._token_expires_at = now + refresh_data["expires_in"]
        else:
            # Default to 5 minutes if not provided
            self._token_expires_at = now + 300

        return self._token

    async def fetch(self, url: str, **kwargs: Any) -> httpx.Response:
        """
        Make an HTTP request with automatic BOTCHA handling.

        Features:
        - Automatically acquires and attaches Bearer token if auto_token=True
        - Retries once on 401 (Unauthorized) with fresh token
        - Solves inline challenges on 403 (Forbidden) responses

        Args:
            url: URL to fetch
            **kwargs: Additional arguments to pass to httpx request

        Returns:
            httpx.Response object

        Raises:
            httpx.HTTPError: If request fails after retries
        """
        # Prepare headers
        headers = kwargs.pop("headers", {})

        # Auto-attach token if enabled
        if self.auto_token:
            token = await self.get_token()
            headers["Authorization"] = f"Bearer {token}"

        # Make request
        kwargs["headers"] = headers
        response = await self._client.request("GET", url, **kwargs)

        # Handle 401 - token expired, try refresh first, then full re-verify
        if response.status_code == 401 and self.auto_token:
            # Try refresh token first if available
            if self._refresh_token:
                try:
                    token = await self.refresh_token()
                    headers["Authorization"] = f"Bearer {token}"
                    kwargs["headers"] = headers

                    # Retry request with refreshed token
                    response = await self._client.request("GET", url, **kwargs)

                    # If still 401, fall through to full re-verify
                    if response.status_code != 401:
                        return response
                except Exception:
                    # Refresh failed, fall through to full re-verify
                    pass

            # Clear cached tokens and get fresh token via challenge
            self._token = None
            self._token_expires_at = 0
            self._refresh_token = None

            # Get fresh token
            token = await self.get_token()
            headers["Authorization"] = f"Bearer {token}"
            kwargs["headers"] = headers

            # Retry request
            response = await self._client.request("GET", url, **kwargs)

        # Handle 403 - inline challenge
        if response.status_code == 403:
            try:
                body = response.json()
                if "challenge" in body and "problems" in body["challenge"]:
                    # Solve inline challenge
                    challenge = body["challenge"]
                    solutions = self.solve(challenge["problems"])

                    # Retry with challenge headers
                    headers["X-Botcha-Challenge-Id"] = challenge["id"]
                    headers["X-Botcha-Answers"] = json.dumps(solutions)
                    if self.app_id:
                        headers["X-Botcha-App-Id"] = self.app_id
                    kwargs["headers"] = headers

                    response = await self._client.request("GET", url, **kwargs)
            except (json.JSONDecodeError, KeyError):
                # Not a BOTCHA challenge, return original response
                pass

        return response

    # ============ APP MANAGEMENT ============

    async def create_app(
        self, email: str, name: Optional[str] = None
    ) -> CreateAppResponse:
        """
        Create a new BOTCHA app. Email is required, name is optional.

        The returned ``app_secret`` is only shown once — save it securely.
        A 6-digit verification code will be sent to the provided email.

        Args:
            email: Email address for the app owner.
            name: Optional human-readable label (e.g., "My Shopping App").

        Returns:
            CreateAppResponse with app_id, name, and app_secret.

        Raises:
            httpx.HTTPStatusError: If app creation fails.

        Example::

            app = await client.create_app("agent@example.com", name="My Shopping App")
            print(app.app_id)      # 'app_abc123'
            print(app.name)        # 'My Shopping App'
            print(app.app_secret)  # 'sk_...' (save this!)
        """
        body: dict = {"email": email}
        if name:
            body["name"] = name

        response = await self._client.post(
            f"{self.base_url}/v1/apps",
            json=body,
        )
        response.raise_for_status()
        data = response.json()

        # Auto-set app_id for subsequent requests
        if "app_id" in data:
            self.app_id = data["app_id"]

        return CreateAppResponse(
            success=data.get("success", False),
            app_id=data["app_id"],
            app_secret=data["app_secret"],
            email=data.get("email", email),
            name=data.get("name"),
            email_verified=data.get("email_verified", False),
            verification_required=data.get("verification_required", True),
            warning=data.get("warning", ""),
            credential_advice=data.get("credential_advice", ""),
            created_at=data.get("created_at", ""),
            rate_limit=data.get("rate_limit", 100),
            next_step=data.get("next_step", ""),
        )

    async def verify_email(
        self, code: str, app_id: Optional[str] = None
    ) -> VerifyEmailResponse:
        """
        Verify the email address for an app using the 6-digit code.

        Args:
            code: The 6-digit verification code from the email.
            app_id: The app ID (defaults to the client's app_id).

        Returns:
            VerifyEmailResponse with verification status.

        Raises:
            ValueError: If no app_id is available.
            httpx.HTTPStatusError: If verification fails.
        """
        aid = app_id or self.app_id
        if not aid:
            raise ValueError("No app ID. Call create_app() first or pass app_id.")

        response = await self._client.post(
            f"{self.base_url}/v1/apps/{quote(aid, safe='')}/verify-email",
            json={"code": code},
        )
        response.raise_for_status()
        data = response.json()

        return VerifyEmailResponse(
            success=data.get("success", False),
            email_verified=data.get("email_verified"),
            error=data.get("error"),
            message=data.get("message"),
        )

    async def resend_verification(
        self, app_id: Optional[str] = None
    ) -> ResendVerificationResponse:
        """
        Resend the email verification code.

        Args:
            app_id: The app ID (defaults to the client's app_id).

        Returns:
            ResendVerificationResponse with success status.

        Raises:
            ValueError: If no app_id is available.
            httpx.HTTPStatusError: If resend fails.
        """
        aid = app_id or self.app_id
        if not aid:
            raise ValueError("No app ID. Call create_app() first or pass app_id.")

        response = await self._client.post(
            f"{self.base_url}/v1/apps/{quote(aid, safe='')}/resend-verification",
        )
        response.raise_for_status()
        data = response.json()

        return ResendVerificationResponse(
            success=data.get("success", False),
            message=data.get("message"),
            error=data.get("error"),
        )

    async def recover_account(self, email: str) -> RecoverAccountResponse:
        """
        Request account recovery via verified email.

        Sends a device code to the registered email address.
        Anti-enumeration: always returns the same response shape.

        Args:
            email: The email address associated with the app.

        Returns:
            RecoverAccountResponse (always success for anti-enumeration).

        Raises:
            httpx.HTTPStatusError: If the request fails.
        """
        response = await self._client.post(
            f"{self.base_url}/v1/auth/recover",
            json={"email": email},
        )
        response.raise_for_status()
        data = response.json()

        return RecoverAccountResponse(
            success=data.get("success", False),
            message=data.get("message", ""),
        )

    async def rotate_secret(self, app_id: Optional[str] = None) -> RotateSecretResponse:
        """
        Rotate the app secret. Requires an active dashboard session (Bearer token).

        The old secret is immediately invalidated.

        Args:
            app_id: The app ID (defaults to the client's app_id).

        Returns:
            RotateSecretResponse with new app_secret (save it!).

        Raises:
            ValueError: If no app_id is available.
            httpx.HTTPStatusError: If rotation fails or auth is missing.
        """
        aid = app_id or self.app_id
        if not aid:
            raise ValueError("No app ID. Call create_app() first or pass app_id.")

        headers: dict[str, str] = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        response = await self._client.post(
            f"{self.base_url}/v1/apps/{quote(aid, safe='')}/rotate-secret",
            headers=headers,
        )
        response.raise_for_status()
        data = response.json()

        return RotateSecretResponse(
            success=data.get("success", False),
            app_id=data.get("app_id"),
            app_secret=data.get("app_secret"),
            warning=data.get("warning"),
            rotated_at=data.get("rotated_at"),
            error=data.get("error"),
            message=data.get("message"),
        )

    # ============ TAP (TRUSTED AGENT PROTOCOL) ============

    async def register_tap_agent(
        self,
        name: str,
        operator: Optional[str] = None,
        version: Optional[str] = None,
        public_key: Optional[str] = None,
        signature_algorithm: Optional[str] = None,
        capabilities: Optional[list[dict]] = None,
        trust_level: Optional[str] = None,
        issuer: Optional[str] = None,
    ) -> TAPAgentResponse:
        """
        Register an agent with TAP (Trusted Agent Protocol) capabilities.

        Args:
            name: Agent name (required).
            operator: Agent operator/organization.
            version: Agent version string.
            public_key: PEM-encoded public key for cryptographic signing.
            signature_algorithm: Signing algorithm ('ecdsa-p256-sha256' or 'rsa-pss-sha256').
            capabilities: List of capability dicts with action, scope, restrictions.
            trust_level: Trust level ('basic', 'verified', 'enterprise').
            issuer: Who issued/verified this agent.

        Returns:
            TAPAgentResponse with agent_id and details.

        Raises:
            httpx.HTTPStatusError: If registration fails.

        Example::

            agent = await client.register_tap_agent(
                name="my-shopping-agent",
                operator="acme-corp",
                capabilities=[{"action": "browse", "scope": ["products"]}],
                trust_level="verified",
            )
            print(agent.agent_id)
        """
        url = f"{self.base_url}/v1/agents/register/tap"
        if self.app_id:
            url += f"?app_id={self.app_id}"

        payload: dict = {"name": name}
        if operator is not None:
            payload["operator"] = operator
        if version is not None:
            payload["version"] = version
        if public_key is not None:
            payload["public_key"] = public_key
        if signature_algorithm is not None:
            payload["signature_algorithm"] = signature_algorithm
        if capabilities is not None:
            payload["capabilities"] = capabilities
        if trust_level is not None:
            payload["trust_level"] = trust_level
        if issuer is not None:
            payload["issuer"] = issuer

        headers: dict[str, str] = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        response = await self._client.post(url, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()

        return TAPAgentResponse(
            success=data.get("success", False),
            agent_id=data["agent_id"],
            app_id=data.get("app_id", ""),
            name=data.get("name", name),
            operator=data.get("operator"),
            version=data.get("version"),
            created_at=data.get("created_at", ""),
            tap_enabled=data.get("tap_enabled", False),
            trust_level=data.get("trust_level"),
            capabilities=data.get("capabilities"),
            signature_algorithm=data.get("signature_algorithm"),
            issuer=data.get("issuer"),
            has_public_key=data.get("has_public_key", False),
            key_fingerprint=data.get("key_fingerprint"),
        )

    async def get_tap_agent(self, agent_id: str) -> TAPAgentResponse:
        """
        Get a TAP agent by ID.

        Args:
            agent_id: The agent ID to retrieve.

        Returns:
            TAPAgentResponse with agent details.

        Raises:
            httpx.HTTPStatusError: If agent not found.
        """
        response = await self._client.get(
            f"{self.base_url}/v1/agents/{quote(agent_id, safe='')}/tap"
        )
        response.raise_for_status()
        data = response.json()

        return TAPAgentResponse(
            success=data.get("success", False),
            agent_id=data.get("agent_id", agent_id),
            app_id=data.get("app_id", ""),
            name=data.get("name", ""),
            operator=data.get("operator"),
            version=data.get("version"),
            created_at=data.get("created_at", ""),
            tap_enabled=data.get("tap_enabled", False),
            trust_level=data.get("trust_level"),
            capabilities=data.get("capabilities"),
            signature_algorithm=data.get("signature_algorithm"),
            issuer=data.get("issuer"),
            has_public_key=data.get("has_public_key", False),
            key_fingerprint=data.get("key_fingerprint"),
            last_verified_at=data.get("last_verified_at"),
            public_key=data.get("public_key"),
        )

    async def list_tap_agents(self, tap_only: bool = False) -> TAPAgentListResponse:
        """
        List TAP agents for the current app.

        Args:
            tap_only: If True, only return TAP-enabled agents.

        Returns:
            TAPAgentListResponse with agents list and counts.

        Raises:
            httpx.HTTPStatusError: If listing fails.
        """
        url = f"{self.base_url}/v1/agents/tap"
        params = {}
        if self.app_id:
            params["app_id"] = self.app_id
        if tap_only:
            params["tap_only"] = "true"

        headers: dict[str, str] = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        response = await self._client.get(url, params=params, headers=headers)
        response.raise_for_status()
        data = response.json()

        return TAPAgentListResponse(
            success=data.get("success", False),
            agents=data.get("agents", []),
            count=data.get("count", 0),
            tap_enabled_count=data.get("tap_enabled_count", 0),
        )

    async def create_tap_session(
        self,
        agent_id: str,
        user_context: str,
        intent: dict,
    ) -> TAPSessionResponse:
        """
        Create a TAP session after agent verification.

        Args:
            agent_id: The registered TAP agent ID.
            user_context: Anonymous hash of user ID.
            intent: Intent dict with action, resource, scope, duration.

        Returns:
            TAPSessionResponse with session_id and expiry.

        Raises:
            httpx.HTTPStatusError: If session creation fails.

        Example::

            session = await client.create_tap_session(
                agent_id="agent_abc123",
                user_context="user-hash",
                intent={"action": "browse", "resource": "products", "duration": 3600},
            )
            print(session.session_id, session.expires_at)
        """
        response = await self._client.post(
            f"{self.base_url}/v1/sessions/tap",
            json={
                "agent_id": agent_id,
                "user_context": user_context,
                "intent": intent,
            },
        )
        response.raise_for_status()
        data = response.json()

        return TAPSessionResponse(
            success=data.get("success", False),
            session_id=data["session_id"],
            agent_id=data.get("agent_id", agent_id),
            capabilities=data.get("capabilities"),
            intent=data.get("intent"),
            expires_at=data.get("expires_at", ""),
        )

    async def get_tap_session(self, session_id: str) -> TAPSessionResponse:
        """
        Get a TAP session by ID.

        Args:
            session_id: The session ID to retrieve.

        Returns:
            TAPSessionResponse with session details and time_remaining.

        Raises:
            httpx.HTTPStatusError: If session not found or expired.
        """
        response = await self._client.get(
            f"{self.base_url}/v1/sessions/{quote(session_id, safe='')}/tap"
        )
        response.raise_for_status()
        data = response.json()

        return TAPSessionResponse(
            success=data.get("success", False),
            session_id=data.get("session_id", session_id),
            agent_id=data.get("agent_id", ""),
            app_id=data.get("app_id", ""),
            capabilities=data.get("capabilities"),
            intent=data.get("intent"),
            created_at=data.get("created_at", ""),
            expires_at=data.get("expires_at", ""),
            time_remaining=data.get("time_remaining"),
        )

    # ============ JWKS & KEY MANAGEMENT ============

    async def get_jwks(self, app_id: Optional[str] = None) -> dict:
        """Get the JWK Set for an app's TAP agents.

        Fetches from /.well-known/jwks endpoint.

        Args:
            app_id: Optional app ID (uses default if not specified)

        Returns:
            JWK Set with keys array
        """
        params = {}
        effective_app_id = app_id or self.app_id
        if effective_app_id:
            params["app_id"] = effective_app_id

        response = await self._client.get(
            f"{self.base_url}/.well-known/jwks", params=params
        )
        response.raise_for_status()
        return response.json()

    async def get_key_by_id(self, key_id: str) -> dict:
        """Get a specific public key by key ID.

        Args:
            key_id: The key identifier

        Returns:
            JWK object with key data
        """
        response = await self._client.get(
            f"{self.base_url}/v1/keys/{quote(key_id, safe='')}"
        )
        response.raise_for_status()
        return response.json()

    async def rotate_agent_key(
        self,
        agent_id: str,
        public_key: str,
        signature_algorithm: str,
        key_expires_at: Optional[str] = None,
    ) -> dict:
        """Rotate an agent's key pair.

        Args:
            agent_id: The agent ID
            public_key: New PEM-encoded public key
            signature_algorithm: Algorithm (ecdsa-p256-sha256, rsa-pss-sha256, ed25519)
            key_expires_at: Optional ISO 8601 expiration date

        Returns:
            Updated agent response
        """
        body: dict = {
            "public_key": public_key,
            "signature_algorithm": signature_algorithm,
        }
        if key_expires_at:
            body["key_expires_at"] = key_expires_at

        headers: dict[str, str] = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        response = await self._client.post(
            f"{self.base_url}/v1/agents/{quote(agent_id, safe='')}/tap/rotate-key",
            json=body,
            headers=headers,
        )
        response.raise_for_status()
        return response.json()

    # ============ INVOICE & PAYMENT (402 Flow) ============

    async def create_invoice(
        self,
        resource_uri: str,
        amount: str,
        currency: str,
        card_acceptor_id: str,
        description: Optional[str] = None,
        ttl_seconds: Optional[int] = None,
    ) -> dict:
        """Create an invoice for gated content (402 micropayment flow).

        Args:
            resource_uri: URI of the gated resource
            amount: Payment amount
            currency: Currency code (e.g., 'USD')
            card_acceptor_id: Merchant's card acceptor ID
            description: Optional description
            ttl_seconds: Optional TTL in seconds (default: 3600)

        Returns:
            Invoice details with invoice_id
        """
        body: dict = {
            "resource_uri": resource_uri,
            "amount": amount,
            "currency": currency,
            "card_acceptor_id": card_acceptor_id,
        }
        if description:
            body["description"] = description
        if ttl_seconds:
            body["ttl_seconds"] = ttl_seconds

        headers: dict[str, str] = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        response = await self._client.post(
            f"{self.base_url}/v1/invoices", json=body, headers=headers
        )
        response.raise_for_status()
        return response.json()

    async def get_invoice(self, invoice_id: str) -> dict:
        """Get an invoice by ID.

        Args:
            invoice_id: The invoice ID

        Returns:
            Invoice details
        """
        response = await self._client.get(
            f"{self.base_url}/v1/invoices/{quote(invoice_id, safe='')}"
        )
        response.raise_for_status()
        return response.json()

    async def verify_browsing_iou(self, invoice_id: str, iou: dict) -> dict:
        """Verify a Browsing IOU against an invoice.

        Args:
            invoice_id: The invoice ID to verify against
            iou: The Browsing IOU object

        Returns:
            Verification result with access_token if successful
        """
        response = await self._client.post(
            f"{self.base_url}/v1/invoices/{quote(invoice_id, safe='')}/verify-iou",
            json=iou,
        )
        response.raise_for_status()
        return response.json()

    # ============ Delegation Chain Methods ============

    async def create_delegation(
        self,
        grantor_id: str,
        grantee_id: str,
        capabilities: list[dict],
        duration_seconds: Optional[int] = None,
        max_depth: Optional[int] = None,
        parent_delegation_id: Optional[str] = None,
        metadata: Optional[dict[str, str]] = None,
    ) -> dict:
        """Create a delegation from one agent to another.

        Grants a subset of the grantor's capabilities to the grantee.

        Args:
            grantor_id: Agent granting capabilities
            grantee_id: Agent receiving capabilities
            capabilities: Capabilities to delegate (must be subset of grantor's)
            duration_seconds: How long the delegation lasts (default: 3600)
            max_depth: Max sub-delegation depth (default: 3)
            parent_delegation_id: Parent delegation ID for sub-delegations
            metadata: Optional context metadata

        Returns:
            Delegation details including delegation_id
        """
        url = f"{self.base_url}/v1/delegations"
        if self.app_id:
            url += f"?app_id={quote(self.app_id, safe='')}"

        body: dict[str, Any] = {
            "grantor_id": grantor_id,
            "grantee_id": grantee_id,
            "capabilities": capabilities,
        }
        if duration_seconds is not None:
            body["duration_seconds"] = duration_seconds
        if max_depth is not None:
            body["max_depth"] = max_depth
        if parent_delegation_id:
            body["parent_delegation_id"] = parent_delegation_id
        if metadata:
            body["metadata"] = metadata

        headers: dict[str, str] = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        response = await self._client.post(url, json=body, headers=headers)
        response.raise_for_status()
        return response.json()

    async def get_delegation(self, delegation_id: str) -> dict:
        """Get delegation details by ID.

        Args:
            delegation_id: The delegation ID

        Returns:
            Delegation details
        """
        response = await self._client.get(
            f"{self.base_url}/v1/delegations/{quote(delegation_id, safe='')}"
        )
        response.raise_for_status()
        return response.json()

    async def list_delegations(
        self,
        agent_id: str,
        direction: Optional[str] = None,
        include_revoked: bool = False,
        include_expired: bool = False,
    ) -> dict:
        """List delegations for an agent.

        Args:
            agent_id: The agent to list delegations for
            direction: 'in', 'out', or 'both' (default: 'both')
            include_revoked: Include revoked delegations
            include_expired: Include expired delegations

        Returns:
            List of delegations with count
        """
        params = {"agent_id": agent_id}
        if self.app_id:
            params["app_id"] = self.app_id
        if direction:
            params["direction"] = direction
        if include_revoked:
            params["include_revoked"] = "true"
        if include_expired:
            params["include_expired"] = "true"

        headers: dict[str, str] = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        response = await self._client.get(
            f"{self.base_url}/v1/delegations", params=params, headers=headers
        )
        response.raise_for_status()
        return response.json()

    async def revoke_delegation(
        self, delegation_id: str, reason: Optional[str] = None
    ) -> dict:
        """Revoke a delegation. Cascades to all sub-delegations.

        Args:
            delegation_id: The delegation to revoke
            reason: Optional reason for revocation

        Returns:
            Revocation result
        """
        url = f"{self.base_url}/v1/delegations/{quote(delegation_id, safe='')}/revoke"
        if self.app_id:
            url += f"?app_id={quote(self.app_id, safe='')}"

        body: dict[str, Any] = {}
        if reason:
            body["reason"] = reason

        headers: dict[str, str] = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        response = await self._client.post(url, json=body, headers=headers)
        response.raise_for_status()
        return response.json()

    async def verify_delegation_chain(self, delegation_id: str) -> dict:
        """Verify a delegation chain is valid.

        Walks from the leaf delegation up through parent delegations to the root,
        verifying each link is not revoked, not expired, and capabilities are
        valid subsets.

        Args:
            delegation_id: The leaf delegation to verify

        Returns:
            Verification result with chain and effective capabilities
        """
        response = await self._client.post(
            f"{self.base_url}/v1/verify/delegation",
            json={"delegation_id": delegation_id},
        )
        response.raise_for_status()
        return response.json()

    # ============ Capability Attestation Methods ============

    async def issue_attestation(
        self,
        agent_id: str,
        can: list[str],
        cannot: Optional[list[str]] = None,
        restrictions: Optional[dict] = None,
        duration_seconds: Optional[int] = None,
        delegation_id: Optional[str] = None,
        metadata: Optional[dict[str, str]] = None,
    ) -> dict:
        """Issue a capability attestation token for an agent.

        Grants fine-grained "action:resource" permissions with explicit deny.

        Args:
            agent_id: Agent to issue attestation for
            can: Allowed capability patterns (e.g. ["read:invoices", "browse:*"])
            cannot: Denied capability patterns (overrides can)
            restrictions: Optional restrictions (max_amount, rate_limit)
            duration_seconds: How long the attestation lasts (default: 3600)
            delegation_id: Optional link to a delegation chain
            metadata: Optional context metadata

        Returns:
            Attestation details including token
        """
        url = f"{self.base_url}/v1/attestations"
        if self.app_id:
            url += f"?app_id={quote(self.app_id, safe='')}"

        body: dict[str, Any] = {
            "agent_id": agent_id,
            "can": can,
        }
        if cannot is not None:
            body["cannot"] = cannot
        if restrictions is not None:
            body["restrictions"] = restrictions
        if duration_seconds is not None:
            body["duration_seconds"] = duration_seconds
        if delegation_id:
            body["delegation_id"] = delegation_id
        if metadata:
            body["metadata"] = metadata

        headers: dict[str, str] = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        response = await self._client.post(url, json=body, headers=headers)
        response.raise_for_status()
        return response.json()

    async def get_attestation(self, attestation_id: str) -> dict:
        """Get attestation details by ID.

        Args:
            attestation_id: The attestation ID

        Returns:
            Attestation details
        """
        response = await self._client.get(
            f"{self.base_url}/v1/attestations/{quote(attestation_id, safe='')}"
        )
        response.raise_for_status()
        return response.json()

    async def list_attestations(self, agent_id: str) -> dict:
        """List attestations for an agent.

        Args:
            agent_id: The agent to list attestations for

        Returns:
            List of attestations with count
        """
        params = {"agent_id": agent_id}
        if self.app_id:
            params["app_id"] = self.app_id

        headers: dict[str, str] = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        response = await self._client.get(
            f"{self.base_url}/v1/attestations", params=params, headers=headers
        )
        response.raise_for_status()
        return response.json()

    async def revoke_attestation(
        self, attestation_id: str, reason: Optional[str] = None
    ) -> dict:
        """Revoke an attestation. Token will be rejected on future verification.

        Args:
            attestation_id: The attestation to revoke
            reason: Optional reason for revocation

        Returns:
            Revocation result
        """
        url = f"{self.base_url}/v1/attestations/{quote(attestation_id, safe='')}/revoke"
        if self.app_id:
            url += f"?app_id={quote(self.app_id, safe='')}"

        body: dict[str, Any] = {}
        if reason:
            body["reason"] = reason

        headers: dict[str, str] = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        response = await self._client.post(url, json=body, headers=headers)
        response.raise_for_status()
        return response.json()

    async def verify_attestation(
        self,
        token: str,
        action: Optional[str] = None,
        resource: Optional[str] = None,
    ) -> dict:
        """Verify an attestation token and optionally check a specific capability.

        Args:
            token: The attestation JWT token
            action: Optional action to check (e.g. "read")
            resource: Optional resource to check (e.g. "invoices")

        Returns:
            Verification result with capability check if action specified
        """
        body: dict[str, str] = {"token": token}
        if action:
            body["action"] = action
        if resource:
            body["resource"] = resource

        response = await self._client.post(
            f"{self.base_url}/v1/verify/attestation", json=body
        )
        response.raise_for_status()
        return response.json()

    # ============ Agent Reputation Scoring ============

    async def get_reputation(self, agent_id: str) -> dict:
        """Get the reputation score for an agent.

        Args:
            agent_id: The agent to get reputation for

        Returns:
            Reputation score with tier, event counts, and category breakdown
        """
        url = f"{self.base_url}/v1/reputation/{quote(agent_id, safe='')}"
        if self.app_id:
            url += f"?app_id={quote(self.app_id, safe='')}"

        headers: dict[str, str] = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        response = await self._client.get(url, headers=headers)
        response.raise_for_status()
        return response.json()

    async def record_reputation_event(
        self,
        agent_id: str,
        category: str,
        action: str,
        source_agent_id: Optional[str] = None,
        metadata: Optional[dict[str, str]] = None,
    ) -> dict:
        """Record a reputation event for an agent.

        Args:
            agent_id: Agent to record event for
            category: Event category (verification, attestation, delegation, session, violation, endorsement)
            action: Event action (e.g. "challenge_solved", "attestation_issued")
            source_agent_id: Optional source agent (for endorsements)
            metadata: Optional key/value metadata

        Returns:
            Event details and updated score
        """
        url = f"{self.base_url}/v1/reputation/events"
        if self.app_id:
            url += f"?app_id={quote(self.app_id, safe='')}"

        body: dict[str, Any] = {
            "agent_id": agent_id,
            "category": category,
            "action": action,
        }
        if source_agent_id:
            body["source_agent_id"] = source_agent_id
        if metadata:
            body["metadata"] = metadata

        headers: dict[str, str] = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        response = await self._client.post(url, json=body, headers=headers)
        response.raise_for_status()
        return response.json()

    async def list_reputation_events(
        self,
        agent_id: str,
        category: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> dict:
        """List reputation events for an agent.

        Args:
            agent_id: The agent to list events for
            category: Optional category filter
            limit: Max events to return (default: 50, max: 100)

        Returns:
            List of events with count
        """
        url = f"{self.base_url}/v1/reputation/{quote(agent_id, safe='')}/events"
        params: dict[str, str] = {}
        if self.app_id:
            params["app_id"] = self.app_id
        if category:
            params["category"] = category
        if limit is not None:
            params["limit"] = str(limit)

        headers: dict[str, str] = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        response = await self._client.get(url, params=params, headers=headers)
        response.raise_for_status()
        return response.json()

    async def reset_reputation(self, agent_id: str) -> dict:
        """Reset an agent's reputation to default (admin action).

        Args:
            agent_id: The agent to reset

        Returns:
            Reset confirmation with default score
        """
        url = f"{self.base_url}/v1/reputation/{quote(agent_id, safe='')}/reset"
        if self.app_id:
            url += f"?app_id={quote(self.app_id, safe='')}"

        headers: dict[str, str] = {}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        response = await self._client.post(url, headers=headers)
        response.raise_for_status()
        return response.json()

    async def close(self) -> None:
        """Close the underlying HTTP client and clear cached tokens."""
        self._token = None
        self._token_expires_at = 0
        self._refresh_token = None
        await self._client.aclose()

    async def __aenter__(self) -> "BotchaClient":
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()

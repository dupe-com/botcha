"""BotchaClient - HTTP client for interacting with BOTCHA-protected endpoints."""

import base64
import json
import time
from typing import Any, Optional

import httpx

from botcha.solver import solve_botcha
from botcha.types import ChallengeResponse, TokenResponse


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
    ):
        """
        Initialize the BotchaClient.

        Args:
            base_url: Base URL for the BOTCHA service (default: https://botcha.ai)
            agent_identity: Optional agent identity string for User-Agent header
            max_retries: Maximum number of retries for failed requests (default: 3)
            auto_token: Automatically acquire and attach Bearer tokens (default: True)
            audience: Optional audience claim for token verification
        """
        self.base_url = base_url.rstrip("/")
        self.agent_identity = agent_identity
        self.max_retries = max_retries
        self.auto_token = auto_token
        self.audience = audience

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
        challenge_response = await self._client.get(f"{self.base_url}/v1/token")
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
                    kwargs["headers"] = headers

                    response = await self._client.request("GET", url, **kwargs)
            except (json.JSONDecodeError, KeyError):
                # Not a BOTCHA challenge, return original response
                pass

        return response

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

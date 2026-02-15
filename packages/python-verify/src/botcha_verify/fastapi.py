"""FastAPI middleware for BOTCHA token verification."""

from typing import Optional

try:
    from fastapi import HTTPException, Request
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
except ImportError:
    raise ImportError(
        "FastAPI is not installed. Install it with: pip install 'botcha-verify[fastapi]'"
    )

from .verify import verify_botcha_token, extract_bearer_token
from .types import BotchaPayload, VerifyOptions


class BotchaVerify:
    """
    FastAPI dependency for BOTCHA token verification.

    Supports both JWKS-based (ES256, recommended) and shared-secret (HS256, legacy)
    verification modes.

    Usage (JWKS — recommended):
        from botcha_verify.fastapi import BotchaVerify

        botcha = BotchaVerify(jwks_url='https://botcha.ai/.well-known/jwks')

        @app.get('/api/data')
        async def get_data(token: BotchaPayload = Depends(botcha)):
            print(f"Solved in {token.solve_time}ms")
            return {"data": "protected"}

    Usage (shared secret — legacy):
        from botcha_verify.fastapi import BotchaVerify

        botcha = BotchaVerify(secret='your-secret-key')

        @app.get('/api/data')
        async def get_data(token: BotchaPayload = Depends(botcha)):
            print(f"Solved in {token.solve_time}ms")
            return {"data": "protected"}
    """

    def __init__(
        self,
        secret: Optional[str] = None,
        audience: Optional[str] = None,
        auto_error: bool = True,
        jwks_url: Optional[str] = None,
        jwks_cache_ttl: int = 3600,
    ):
        """
        Initialize BOTCHA verification dependency.

        At least one of ``secret`` or ``jwks_url`` must be provided.

        Args:
            secret: Secret key for HS256 JWT verification (legacy)
            audience: Optional required audience claim
            auto_error: If True, raise HTTPException on invalid token.
                       If False, return None for invalid tokens.
            jwks_url: JWKS URL for ES256 verification (recommended).
                      e.g. 'https://botcha.ai/.well-known/jwks'
            jwks_cache_ttl: Cache JWKS keys for this many seconds (default: 3600)
        """
        if not secret and not jwks_url:
            raise ValueError("At least one of 'secret' or 'jwks_url' must be provided")
        self.secret = secret
        self.audience = audience
        self.auto_error = auto_error
        self.jwks_url = jwks_url
        self.jwks_cache_ttl = jwks_cache_ttl
        self.security = HTTPBearer(auto_error=auto_error)

    async def __call__(
        self,
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials] = None,
    ) -> Optional[BotchaPayload]:
        """
        Verify token from request Authorization header.

        Args:
            request: FastAPI request object
            credentials: HTTP Bearer credentials (auto-extracted by FastAPI)

        Returns:
            BotchaPayload if token is valid, None if invalid (when auto_error=False)

        Raises:
            HTTPException: If token is invalid and auto_error=True
        """
        # Extract token from Authorization header
        if credentials:
            token = credentials.credentials
        else:
            # Manual extraction as fallback
            auth_header = request.headers.get("Authorization")
            token = extract_bearer_token(auth_header)

        if not token:
            if self.auto_error:
                raise HTTPException(
                    status_code=401,
                    detail="Missing or invalid Authorization header",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return None

        # Get client IP for optional validation
        client_ip = request.client.host if request.client else None

        # Verify token
        options = VerifyOptions(
            audience=self.audience,
            client_ip=None,  # Don't enforce IP by default in FastAPI
            jwks_url=self.jwks_url,
            jwks_cache_ttl=self.jwks_cache_ttl,
        )
        result = verify_botcha_token(token, self.secret, options)

        if not result.valid:
            if self.auto_error:
                raise HTTPException(
                    status_code=401,
                    detail=result.error or "Invalid token",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return None

        return result.payload


# Convenience function for route-level verification
def verify_token_dependency(
    secret: Optional[str] = None,
    audience: Optional[str] = None,
    jwks_url: Optional[str] = None,
) -> BotchaVerify:
    """
    Create a FastAPI dependency for token verification.

    At least one of ``secret`` or ``jwks_url`` must be provided.

    Args:
        secret: Secret key for HS256 JWT verification (legacy)
        audience: Optional required audience claim
        jwks_url: JWKS URL for ES256 verification (recommended)

    Returns:
        BotchaVerify instance for use with Depends()

    Example (JWKS — recommended):
        verify = verify_token_dependency(jwks_url='https://botcha.ai/.well-known/jwks')

        @app.get('/data')
        async def get_data(token: BotchaPayload = Depends(verify)):
            return {"data": "protected"}

    Example (shared secret — legacy):
        verify = verify_token_dependency(secret='my-secret')

        @app.get('/data')
        async def get_data(token: BotchaPayload = Depends(verify)):
            return {"data": "protected"}
    """
    return BotchaVerify(secret=secret, audience=audience, jwks_url=jwks_url)

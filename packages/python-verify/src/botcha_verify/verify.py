"""Core BOTCHA JWT token verification.

Supports both JWKS-based (ES256, recommended) and shared-secret (HS256, legacy)
verification of BOTCHA JWT tokens.
"""

import jwt
from typing import Optional

from .types import BotchaPayload, VerifyOptions, VerifyResult

# ---------------------------------------------------------------------------
# JWKS client cache – reuse PyJWKClient instances across calls
# ---------------------------------------------------------------------------
_jwks_clients: dict = {}


def _get_jwks_client(jwks_url: str, cache_ttl: int = 3600):
    """Get or create a cached PyJWKClient for the given JWKS URL."""
    from jwt import PyJWKClient

    key = (jwks_url, cache_ttl)
    if key not in _jwks_clients:
        _jwks_clients[key] = PyJWKClient(
            jwks_url, cache_jwk_set=True, lifespan=cache_ttl
        )
    return _jwks_clients[key]


def verify_botcha_token(
    token: str, secret: Optional[str] = None, options: Optional[VerifyOptions] = None
) -> VerifyResult:
    """
    Verify a BOTCHA JWT token.

    Supports two verification modes:

    1. **JWKS (recommended)** – set ``options.jwks_url`` to fetch the public key
       from BOTCHA's JWKS endpoint. Accepts both ES256 and HS256 tokens.
    2. **Shared secret (legacy)** – pass ``secret`` for HS256 verification.

    If both ``jwks_url`` and ``secret`` are provided, JWKS is tried first with
    a fallback to the shared secret.

    Checks:
    - Token signature and expiry
    - Token type must be "botcha-verified"
    - Issuer claim (must be "botcha.ai" in JWKS-only mode)
    - Audience claim (if options.audience provided)
    - Client IP binding (if options.client_ip provided)

    Args:
        token: JWT token string
        secret: Secret key for HS256 verification (optional if jwks_url provided)
        options: Optional verification options (including jwks_url)

    Returns:
        VerifyResult with valid flag, payload, or error message

    Example (JWKS – recommended):
        >>> opts = VerifyOptions(jwks_url="https://botcha.ai/.well-known/jwks")
        >>> result = verify_botcha_token(token, options=opts)
        >>> if result.valid:
        ...     print(f"Solved in {result.payload.solve_time}ms")

    Example (shared secret – legacy):
        >>> result = verify_botcha_token(token, secret="my-secret")
        >>> if result.valid:
        ...     print(f"Solved in {result.payload.solve_time}ms")
    """
    jwks_url = options.jwks_url if options else None
    jwks_cache_ttl = options.jwks_cache_ttl if options else 3600

    # Must have at least one verification method
    if not secret and not jwks_url:
        return VerifyResult(
            valid=False,
            error='Configuration error: at least one of "secret" or "options.jwks_url" must be provided',
        )

    try:
        payload: Optional[dict] = None

        if jwks_url and secret:
            # Both provided: try JWKS first, fall back to secret
            try:
                payload = _decode_with_jwks(token, jwks_url, jwks_cache_ttl, options)
            except Exception:
                payload = _decode_with_secret(token, secret, options)
        elif jwks_url:
            # JWKS-only mode
            payload = _decode_with_jwks(token, jwks_url, jwks_cache_ttl, options)

            # Validate issuer when using JWKS mode
            iss = payload.get("iss")
            if not iss or iss != "botcha.ai":
                return VerifyResult(
                    valid=False,
                    error=f"Invalid issuer claim: expected 'botcha.ai', got '{iss}'",
                )
        else:
            # Secret-only mode (legacy)
            assert secret is not None  # guaranteed by earlier check
            payload = _decode_with_secret(token, secret, options)

        # Check token type (must be access token, not refresh token)
        token_type = payload.get("type")
        if token_type != "botcha-verified":
            return VerifyResult(
                valid=False,
                error=f"Invalid token type: expected 'botcha-verified', got '{token_type}'",
            )

        # Validate client IP binding (if required)
        if options and options.client_ip:
            token_ip = payload.get("client_ip")
            if not token_ip or token_ip != options.client_ip:
                return VerifyResult(
                    valid=False,
                    error=f"Client IP mismatch: expected '{options.client_ip}', got '{token_ip}'",
                )

        # Build payload dataclass
        botcha_payload = BotchaPayload(
            sub=payload["sub"],
            iat=payload["iat"],
            exp=payload["exp"],
            jti=payload["jti"],
            type=payload["type"],
            solve_time=payload.get(
                "solveTime", 0
            ),  # Handle both solveTime and solve_time
            aud=payload.get("aud"),
            client_ip=payload.get("client_ip"),
        )

        return VerifyResult(valid=True, payload=botcha_payload)

    except jwt.ExpiredSignatureError:
        return VerifyResult(valid=False, error="Token has expired")
    except jwt.InvalidTokenError as e:
        return VerifyResult(valid=False, error=f"Invalid token: {str(e)}")
    except Exception as e:
        return VerifyResult(valid=False, error=f"Token verification failed: {str(e)}")


def _decode_with_jwks(
    token: str,
    jwks_url: str,
    cache_ttl: int,
    options: Optional[VerifyOptions],
) -> dict:
    """Decode and verify a token using a JWKS endpoint (ES256 + HS256)."""
    jwks_client = _get_jwks_client(jwks_url, cache_ttl)
    signing_key = jwks_client.get_signing_key_from_jwt(token)

    decode_kwargs: dict = {
        "algorithms": ["ES256", "HS256"],
        "options": {
            "require": ["sub", "iat", "exp", "jti"],
        },
    }
    if options and options.audience:
        decode_kwargs["audience"] = options.audience

    return jwt.decode(token, signing_key.key, **decode_kwargs)


def _decode_with_secret(
    token: str,
    secret: str,
    options: Optional[VerifyOptions],
) -> dict:
    """Decode and verify a token using a shared secret (HS256)."""
    decode_kwargs: dict = {
        "algorithms": ["HS256"],
        "options": {
            "require": ["sub", "iat", "exp", "jti"],
        },
    }
    if options and options.audience:
        decode_kwargs["audience"] = options.audience

    return jwt.decode(token, secret, **decode_kwargs)


def extract_bearer_token(auth_header: Optional[str]) -> Optional[str]:
    """
    Extract Bearer token from Authorization header.

    Args:
        auth_header: Authorization header value (e.g., "Bearer eyJhbG...")

    Returns:
        Token string without "Bearer " prefix, or None if not found
    """
    if not auth_header:
        return None

    if not auth_header.startswith("Bearer "):
        return None

    return auth_header[7:]  # Remove "Bearer " prefix

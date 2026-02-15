"""BOTCHA verification library for server-side JWT token validation."""

from .types import BotchaPayload, VerifyOptions, VerifyResult
from .verify import verify_botcha_token, extract_bearer_token

__version__ = "0.2.0"

__all__ = [
    "BotchaPayload",
    "VerifyOptions",
    "VerifyResult",
    "verify_botcha_token",
    "extract_bearer_token",
]

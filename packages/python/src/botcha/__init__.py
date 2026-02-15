"""BOTCHA Python SDK - Prove you're a bot. Humans need not apply."""

__version__ = "0.20.3"

from botcha.client import BotchaClient
from botcha.solver import solve_botcha
from botcha.types import (
    ChallengeResponse,
    CreateAppResponse,
    RecoverAccountResponse,
    ResendVerificationResponse,
    RotateSecretResponse,
    TokenResponse,
    VerifyEmailResponse,
    VerifyResponse,
)

__all__ = [
    "BotchaClient",
    "solve_botcha",
    "ChallengeResponse",
    "CreateAppResponse",
    "RecoverAccountResponse",
    "ResendVerificationResponse",
    "RotateSecretResponse",
    "TokenResponse",
    "VerifyEmailResponse",
    "VerifyResponse",
    "__version__",
]

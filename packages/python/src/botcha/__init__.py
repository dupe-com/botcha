"""BOTCHA Python SDK - Prove you're a bot. Humans need not apply."""

__version__ = "0.1.0"

from botcha.client import BotchaClient
from botcha.solver import solve_botcha
from botcha.types import ChallengeResponse, TokenResponse, VerifyResponse

__all__ = [
    "BotchaClient",
    "solve_botcha",
    "ChallengeResponse",
    "TokenResponse",
    "VerifyResponse",
    "__version__",
]

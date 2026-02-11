"""Type definitions for BOTCHA SDK."""

from dataclasses import dataclass
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

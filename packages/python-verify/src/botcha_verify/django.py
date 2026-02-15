"""Django middleware for BOTCHA token verification."""

from typing import Callable, Optional, List

try:
    from django.conf import settings
    from django.http import JsonResponse, HttpRequest, HttpResponse
except ImportError:
    raise ImportError(
        "Django is not installed. Install it with: pip install 'botcha-verify[django]'"
    )

from .verify import verify_botcha_token, extract_bearer_token
from .types import VerifyOptions


class BotchaVerifyMiddleware:
    """
    Django middleware for BOTCHA token verification.

    Supports both JWKS-based (ES256, recommended) and shared-secret (HS256, legacy)
    verification modes. At least one of ``BOTCHA_SECRET`` or ``BOTCHA_JWKS_URL``
    must be set.

    Configuration in settings.py (JWKS — recommended):
        MIDDLEWARE = [
            # ... other middleware
            'botcha_verify.django.BotchaVerifyMiddleware',
        ]

        BOTCHA_JWKS_URL = 'https://botcha.ai/.well-known/jwks'
        BOTCHA_AUDIENCE = 'https://api.example.com'  # Optional
        BOTCHA_PROTECTED_PATHS = ['/api/']  # Paths to protect
        BOTCHA_EXCLUDED_PATHS = ['/api/health']  # Paths to exclude

    Configuration in settings.py (shared secret — legacy):
        BOTCHA_SECRET = 'your-secret-key'
        BOTCHA_AUDIENCE = 'https://api.example.com'  # Optional
        BOTCHA_PROTECTED_PATHS = ['/api/']
        BOTCHA_EXCLUDED_PATHS = ['/api/health']

    Usage in views:
        def my_view(request):
            # Access verified payload
            if hasattr(request, 'botcha'):
                print(f"Solved in {request.botcha.solve_time}ms")
            return JsonResponse({"data": "protected"})
    """

    def __init__(self, get_response: Callable):
        """
        Initialize middleware.

        Args:
            get_response: Django middleware get_response callable
        """
        self.get_response = get_response

        # Load configuration from settings
        self.secret = getattr(settings, "BOTCHA_SECRET", None)
        self.jwks_url = getattr(settings, "BOTCHA_JWKS_URL", None)
        self.jwks_cache_ttl = getattr(settings, "BOTCHA_JWKS_CACHE_TTL", 3600)

        if not self.secret and not self.jwks_url:
            raise ValueError(
                "At least one of BOTCHA_SECRET or BOTCHA_JWKS_URL must be set in Django settings"
            )

        self.audience = getattr(settings, "BOTCHA_AUDIENCE", None)
        self.protected_paths: List[str] = getattr(
            settings, "BOTCHA_PROTECTED_PATHS", ["/api/"]
        )
        self.excluded_paths: List[str] = getattr(settings, "BOTCHA_EXCLUDED_PATHS", [])

    def __call__(self, request: HttpRequest) -> HttpResponse:
        """
        Process request through middleware.

        Args:
            request: Django HttpRequest

        Returns:
            HttpResponse from next middleware or view
        """
        # Check if path should be protected
        if not self._should_verify_path(request.path):
            return self.get_response(request)

        # Extract token from Authorization header
        auth_header = request.headers.get("Authorization")
        token = extract_bearer_token(auth_header)

        if not token:
            return JsonResponse(
                {
                    "error": "Missing or invalid Authorization header",
                    "detail": "Expected: Authorization: Bearer <token>",
                },
                status=401,
            )

        # Get client IP for optional validation
        client_ip = self._get_client_ip(request)

        # Verify token
        options = VerifyOptions(
            audience=self.audience,
            client_ip=None,  # Don't enforce IP by default
            jwks_url=self.jwks_url,
            jwks_cache_ttl=self.jwks_cache_ttl,
        )
        result = verify_botcha_token(token, self.secret, options)

        if not result.valid:
            return JsonResponse(
                {"error": "Invalid token", "detail": result.error}, status=401
            )

        # Attach payload to request for use in views
        request.botcha = result.payload  # type: ignore

        return self.get_response(request)

    def _should_verify_path(self, path: str) -> bool:
        """
        Check if path should be verified.

        Args:
            path: Request path

        Returns:
            True if path should be verified, False otherwise
        """
        # Check excluded paths first
        for excluded in self.excluded_paths:
            if path.startswith(excluded):
                return False

        # Check protected paths
        for protected in self.protected_paths:
            if path.startswith(protected):
                return True

        return False

    def _get_client_ip(self, request: HttpRequest) -> Optional[str]:
        """
        Get client IP from request.

        Checks X-Forwarded-For header first (for proxied requests),
        then falls back to REMOTE_ADDR.

        Args:
            request: Django HttpRequest

        Returns:
            Client IP address or None
        """
        # Check X-Forwarded-For header (comma-separated list)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP (client IP)
            return forwarded_for.split(",")[0].strip()

        # Fall back to REMOTE_ADDR
        return request.META.get("REMOTE_ADDR")

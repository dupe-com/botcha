# botcha-verify

Server-side verification middleware for BOTCHA JWT tokens.

Supports both **JWKS-based ES256 verification** (recommended) and shared-secret HS256 verification (legacy).

## Installation

```bash
pip install botcha-verify
```

For FastAPI support:
```bash
pip install "botcha-verify[fastapi]"
```

For Django support:
```bash
pip install "botcha-verify[django]"
```

> **Note:** The `[crypto]` extra (cryptography) is included automatically for ES256 key support.

## Usage

### JWKS Verification (Recommended)

Fetches BOTCHA's public key from the JWKS endpoint. No shared secret to manage.

```python
from botcha_verify import verify_botcha_token, VerifyOptions

result = verify_botcha_token(
    token="eyJhbG...",
    options=VerifyOptions(
        jwks_url="https://botcha.ai/.well-known/jwks",
        audience="https://api.example.com",
    )
)

if result.valid:
    print(f"Challenge solved in {result.payload.solve_time}ms")
else:
    print(f"Invalid token: {result.error}")
```

### Legacy: Shared Secret Verification

Still supported for existing HS256 integrations.

```python
from botcha_verify import verify_botcha_token, VerifyOptions

result = verify_botcha_token(
    token="eyJhbG...",
    secret="your-secret-key",
    options=VerifyOptions(audience="https://api.example.com")
)
```

### FastAPI

```python
from fastapi import FastAPI, Depends
from botcha_verify.fastapi import BotchaVerify
from botcha_verify import BotchaPayload

app = FastAPI()

# RECOMMENDED: JWKS verification
botcha = BotchaVerify(jwks_url='https://botcha.ai/.well-known/jwks')

# LEGACY: Shared secret
# botcha = BotchaVerify(secret='your-secret-key')

@app.get('/api/data')
async def get_data(token: BotchaPayload = Depends(botcha)):
    return {"solve_time": token.solve_time}
```

### Django

```python
# settings.py
MIDDLEWARE = [
    # ... other middleware
    'botcha_verify.django.BotchaVerifyMiddleware',
]

# RECOMMENDED: JWKS verification
BOTCHA_JWKS_URL = 'https://botcha.ai/.well-known/jwks'

# LEGACY: Shared secret
# BOTCHA_SECRET = 'your-secret-key'

BOTCHA_PROTECTED_PATHS = ['/api/']
BOTCHA_EXCLUDED_PATHS = ['/api/health']

# views.py
def my_view(request):
    if hasattr(request, 'botcha'):
        print(f"Solved in {request.botcha.solve_time}ms")
    return JsonResponse({"data": "protected"})
```

## Migration from Shared Secret to JWKS

During the transition period, provide both `secret` and `jwks_url`. JWKS is tried first with a fallback to the shared secret:

```python
result = verify_botcha_token(
    token="eyJhbG...",
    secret="your-secret-key",        # fallback during migration
    options=VerifyOptions(
        jwks_url="https://botcha.ai/.well-known/jwks",
        audience="https://api.example.com",
    )
)
```

## Token Structure

BOTCHA JWT tokens contain:
- `sub`: Challenge ID
- `iss`: Issuer (`botcha.ai`, validated in JWKS mode)
- `iat`: Issued at (Unix timestamp)
- `exp`: Expiry (Unix timestamp)
- `jti`: JWT ID for revocation
- `type`: "botcha-verified"
- `solveTime`: Challenge solve time in milliseconds
- `aud`: (optional) Audience claim
- `client_ip`: (optional) Client IP binding

## License

MIT

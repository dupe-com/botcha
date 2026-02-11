# BOTCHA Python SDK

**Prove you're a bot. Humans need not apply.**

BOTCHA is an anti-CAPTCHA system designed to keep humans out and let AI agents in. This Python SDK provides a simple interface for AI agents to solve BOTCHA challenges and access protected endpoints.

## Installation

```bash
pip install botcha
```

## Quickstart

```python
from botcha import BotchaClient

async with BotchaClient() as client:
    response = await client.fetch("https://api.example.com/agent-only")
    print(response.json())
```

That's it! The client automatically handles token acquisition, challenge solving, and authentication.

## API Reference

### `BotchaClient`

HTTP client with automatic BOTCHA challenge solving and JWT token management.

#### Constructor

```python
BotchaClient(
    base_url: str = "https://botcha.ai",
    agent_identity: Optional[str] = None,
    max_retries: int = 3,
    auto_token: bool = True
)
```

**Parameters:**
- `base_url` (str): Base URL for the BOTCHA service. Default: `"https://botcha.ai"`
- `agent_identity` (str, optional): Custom agent identity string for User-Agent header
- `max_retries` (int): Maximum number of retries for failed requests. Default: `3`
- `auto_token` (bool): Automatically acquire and attach Bearer tokens. Default: `True`

#### Methods

##### `async fetch(url: str, **kwargs) -> httpx.Response`

Make an HTTP GET request with automatic BOTCHA handling.

**Features:**
- Automatically acquires and attaches Bearer token (if `auto_token=True`)
- Retries once on 401 (Unauthorized) with fresh token
- Solves inline challenges on 403 (Forbidden) responses

**Parameters:**
- `url` (str): URL to fetch
- `**kwargs`: Additional arguments passed to httpx request

**Returns:** `httpx.Response` object

**Example:**
```python
async with BotchaClient() as client:
    response = await client.fetch("https://api.example.com/data")
    data = response.json()
```

##### `async get_token() -> str`

Acquire or return cached JWT token.

Implements token caching with 5-minute buffer before expiry. If token is cached and valid, returns the cached token. Otherwise, acquires a new token via the challenge flow:

1. GET `/v1/token` to receive challenge
2. Solve challenge problems
3. POST `/v1/token/verify` with solutions
4. Parse and cache JWT token

**Returns:** JWT token string

**Example:**
```python
async with BotchaClient() as client:
    token = await client.get_token()
    print(f"Token: {token}")
```

##### `solve(problems: list[int]) -> list[str]`

Solve BOTCHA challenge problems synchronously.

**Parameters:**
- `problems` (list[int]): List of 6-digit integers to solve

**Returns:** List of 8-character hex strings (SHA256 hash prefixes)

**Example:**
```python
client = BotchaClient()
answers = client.solve([123456, 789012])
print(answers)  # ['8d969eef', 'ca2f2c8f']
```

##### `async close() -> None`

Close the underlying HTTP client. Automatically called when using async context manager.

---

### `solve_botcha(problems: list[int]) -> list[str]`

Standalone function to solve BOTCHA speed challenges without needing a client instance.

**Parameters:**
- `problems` (list[int]): List of 6-digit integers to solve

**Returns:** List of 8-character hex strings (SHA256 hash prefixes)

**Example:**
```python
from botcha import solve_botcha

answers = solve_botcha([123456, 789012])
print(answers)  # ['8d969eef', 'ca2f2c8f']
```

## Usage Examples

### Basic Usage with Auto-Token

The simplest way to use BOTCHA - the client handles everything automatically:

```python
import asyncio
from botcha import BotchaClient

async def main():
    async with BotchaClient(base_url="https://botcha.ai") as client:
        # Client automatically acquires token and solves challenges
        response = await client.fetch("https://api.example.com/agent-only")
        print(response.json())

asyncio.run(main())
```

### Manual Token Acquisition

If you need more control over token management:

```python
import asyncio
from botcha import BotchaClient

async def main():
    async with BotchaClient(auto_token=False) as client:
        # Manually acquire token
        token = await client.get_token()
        print(f"Acquired token: {token}")
        
        # Use token in custom requests
        response = await client.fetch(
            "https://api.example.com/data",
            headers={"Authorization": f"Bearer {token}"}
        )
        print(response.json())

asyncio.run(main())
```

### Standalone Solver

Use the solver without creating a client instance:

```python
from botcha import solve_botcha

# Solve challenges independently
problems = [123456, 789012, 456789]
answers = solve_botcha(problems)

print(f"Problems: {problems}")
print(f"Answers: {answers}")
# Problems: [123456, 789012, 456789]
# Answers: ['8d969eef', 'ca2f2c8f', 'c888c9ce']
```

### Custom Agent Identity

Set a custom User-Agent header for your bot:

```python
import asyncio
from botcha import BotchaClient

async def main():
    async with BotchaClient(agent_identity="MyBot/1.0") as client:
        response = await client.fetch("https://api.example.com/data")
        print(response.json())

asyncio.run(main())
```

### Inline Challenge Handling

The client automatically handles inline challenges (403 responses):

```python
import asyncio
from botcha import BotchaClient

async def main():
    async with BotchaClient() as client:
        # If the endpoint returns a 403 with a BOTCHA challenge,
        # the client automatically solves it and retries
        response = await client.fetch("https://api.example.com/protected")
        
        # You get the successful response without manual intervention
        print(response.json())

asyncio.run(main())
```

### Error Handling

Handle errors gracefully:

```python
import asyncio
import httpx
from botcha import BotchaClient

async def main():
    try:
        async with BotchaClient() as client:
            response = await client.fetch("https://api.example.com/data")
            response.raise_for_status()
            print(response.json())
    except httpx.HTTPError as e:
        print(f"Request failed: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

asyncio.run(main())
```

## How It Works

BOTCHA is a speed challenge designed to prove computational capability:

1. **Challenge Generation**: Server generates a list of 6-digit integers
2. **Solving**: Client computes SHA256 hash of each integer and returns the first 8 hex characters
3. **Verification**: Server validates solutions within the time limit (typically 10 seconds)
4. **Token Issuance**: Upon successful verification, server issues a JWT token

**Why it works:**
- **Fast for bots**: Modern computers can solve thousands of challenges per second
- **Slow for humans**: Manual calculation is impractical
- **Simple to implement**: Standard SHA256 hashing, no complex cryptography
- **Stateless**: No session management required

**Security properties:**
- Solutions cannot be precomputed (random challenges)
- Time-limited to prevent delayed solving
- JWT tokens expire to limit attack windows
- No brute-force protection needed (humans self-exclude)

## Type Hints

This package includes type hints (PEP 484) and ships with a `py.typed` marker for full type checking support in IDEs and tools like mypy.

## Requirements

- Python >= 3.9
- httpx >= 0.27

## Development

```bash
# Clone the repository
git clone https://github.com/dupe-com/botcha.git
cd botcha/packages/python

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run type checking
mypy src/botcha
```

## Links

- **Website**: [https://botcha.ai](https://botcha.ai)
- **Repository**: [https://github.com/dupe-com/botcha](https://github.com/dupe-com/botcha)
- **Issues**: [https://github.com/dupe-com/botcha/issues](https://github.com/dupe-com/botcha/issues)
- **PyPI**: [https://pypi.org/project/botcha/](https://pypi.org/project/botcha/)

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

Ramin <ramin@dupe.com>

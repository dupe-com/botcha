# BOTCHA CLI Tool

> Test, debug, and interact with BOTCHA from the command line

## Installation

```bash
npm install -g @dupecom/botcha-cli
# or
npx botcha <command>
```

## Commands

### Test an Endpoint

Check if an endpoint is BOTCHA-protected and test verification:

```bash
$ botcha test https://api.example.com/agent-only

🔍 Testing https://api.example.com/agent-only...

✅ BOTCHA Detected!
   Version: 0.3.7
   Methods: speed-challenge, standard-challenge, web-bot-auth

📋 Challenge Received:
   Type: speed
   Problems: 5 SHA256 hashes
   Time Limit: 500ms

⚡ Solving challenge...
   Solved in 12ms

🎉 Access Granted!
   Agent: cli-verified
   Method: challenge
   
Response:
{
  "success": true,
  "message": "Welcome, fellow bot!"
}
```

### Solve Challenges

Solve a specific challenge:

```bash
# Speed challenge
$ botcha solve speed --url https://botcha.ai/api/speed-challenge
⚡ Solved in 15ms!

# Landing page challenge
$ botcha solve landing --url https://botcha.ai
🔑 Token: abc123...
   Valid for: 1 hour
   Use header: X-Botcha-Landing-Token

# Standard challenge
$ botcha solve standard --url https://botcha.ai/api/challenge
✅ Solved in 2.3s
```

### Generate Challenges (for testing)

```bash
# Generate a speed challenge
$ botcha generate speed
{
  "id": "test-123",
  "problems": [
    { "num": 123456, "operation": "sha256_first8" },
    ...
  ],
  "timeLimit": "500ms"
}

# Generate with specific difficulty
$ botcha generate standard --difficulty hard
```

### Check Headers

Inspect BOTCHA headers on any URL:

```bash
$ botcha headers https://botcha.ai/api

Headers:
  X-Botcha-Version: 0.3.7
  X-Botcha-Enabled: true
  X-Botcha-Methods: speed-challenge,standard-challenge,web-bot-auth
  X-Botcha-Docs: https://botcha.ai/openapi.json
```

### Discover BOTCHA

Find all BOTCHA discovery endpoints:

```bash
$ botcha discover https://botcha.ai

🔍 Discovery Results:

✅ /robots.txt - Contains BOTCHA instructions
✅ /ai.txt - AI agent discovery file
✅ /.well-known/ai-plugin.json - AI plugin manifest
✅ /openapi.json - OpenAPI specification
✅ Embedded challenge in HTML - <script type="application/botcha+json">

Discovery Score: 5/5 ⭐
```

### Benchmark

Test performance and reliability:

```bash
$ botcha benchmark https://api.example.com/agent-only --iterations 100

🏃 Running 100 iterations...

Results:
  Success Rate: 100%
  Avg Solve Time: 14ms
  Min Solve Time: 8ms
  Max Solve Time: 42ms
  P95 Solve Time: 25ms
  
  Total Time: 3.2s
  Requests/sec: 31.25
```

### Watch Mode

Continuously monitor an endpoint:

```bash
$ botcha watch https://api.example.com/agent-only --interval 60

👀 Watching https://api.example.com/agent-only (every 60s)

[12:00:00] ✅ OK (15ms)
[12:01:00] ✅ OK (12ms)
[12:02:00] ⚠️  Slow (450ms)
[12:03:00] ❌ Failed: Challenge timeout
[12:04:00] ✅ OK (14ms)

Press Ctrl+C to stop
```

### Interactive Mode

```bash
$ botcha interactive https://botcha.ai

🤖 BOTCHA Interactive Shell
   Connected to: https://botcha.ai
   
botcha> challenge
Got challenge: abc123
Type: speed
Problems: 5

botcha> solve
Solving... Done in 12ms!
Token: xyz789

botcha> access /agent-only
{
  "success": true,
  "message": "Welcome, fellow bot!"
}

botcha> exit
```

## Configuration

### Config File

Create `~/.botcharc` or `.botcharc` in your project:

```json
{
  "agentName": "MyCLI/1.0",
  "defaultTimeout": 5000,
  "colorOutput": true,
  "verbose": false
}
```

### Environment Variables

```bash
export BOTCHA_AGENT_NAME="MyCLI/1.0"
export BOTCHA_TIMEOUT=5000
export BOTCHA_VERBOSE=true
```

## Flags

| Flag | Description |
|------|-------------|
| `--verbose, -v` | Show detailed output |
| `--quiet, -q` | Minimal output |
| `--json` | Output as JSON |
| `--timeout <ms>` | Request timeout |
| `--agent <name>` | Agent name to use |
| `--no-color` | Disable colored output |

## Use Cases

### CI/CD Integration

```yaml
# GitHub Actions
- name: Test BOTCHA Protection
  run: |
    npx botcha test ${{ env.API_URL }}/protected
    npx botcha benchmark ${{ env.API_URL }}/protected --iterations 10
```

### Debugging

```bash
# Why is my agent failing?
$ botcha test https://api.example.com/endpoint --verbose

DEBUG: Fetching endpoint...
DEBUG: Got 403 response
DEBUG: BOTCHA headers detected
DEBUG: Challenge type: speed
DEBUG: Starting solve...
DEBUG: Hash 1: 12ms
DEBUG: Hash 2: 8ms
DEBUG: Hash 3: 15ms
DEBUG: Hash 4: 9ms
DEBUG: Hash 5: 11ms
DEBUG: Total solve time: 55ms
DEBUG: Submitting solution...
DEBUG: Got 200 response
```

### Scripting

```bash
# Get token and use in other commands
TOKEN=$(botcha solve landing --url https://botcha.ai --json | jq -r '.token')
curl -H "X-Botcha-Landing-Token: $TOKEN" https://botcha.ai/agent-only
```

## Package Structure

```
@dupecom/botcha-cli/
├── bin/
│   └── botcha.js
├── commands/
│   ├── test.js
│   ├── solve.js
│   ├── generate.js
│   ├── headers.js
│   ├── discover.js
│   ├── benchmark.js
│   └── watch.js
├── lib/
│   ├── client.js
│   ├── output.js
│   └── config.js
└── package.json
```

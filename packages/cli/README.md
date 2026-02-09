# @dupecom/botcha-cli

> CLI tool for testing and debugging BOTCHA-protected endpoints

## Installation

```bash
npm install -g @dupecom/botcha-cli
# or use directly with npx
npx botcha <command>
```

## Commands

### Test an Endpoint

Check if an endpoint is BOTCHA-protected and test verification:

```bash
botcha test https://api.example.com/agent-only
```

Options:
- `--json` - Output as JSON
- `-v, --verbose` - Show detailed output
- `-q, --quiet` - Minimal output

### Solve Challenges

Solve a specific challenge type:

```bash
# Get a token
botcha solve token --url https://botcha.ai/v1/token

# Solve a speed challenge
botcha solve speed --url https://botcha.ai/api/speed-challenge
```

Options:
- `--url <url>` - URL to solve challenge from (required)
- `--json` - Output as JSON
- `-v, --verbose` - Show detailed output
- `-q, --quiet` - Minimal output

### Benchmark

Test performance and reliability:

```bash
botcha benchmark https://api.example.com/agent-only --iterations 100
```

Options:
- `-n, --iterations <number>` - Number of iterations (default: 10)
- `--json` - Output as JSON
- `-v, --verbose` - Show each iteration result
- `-q, --quiet` - Minimal output

### Check Headers

Inspect BOTCHA headers on any URL:

```bash
botcha headers https://botcha.ai/api
```

Options:
- `--json` - Output as JSON
- `-v, --verbose` - Show all headers (not just BOTCHA)
- `-q, --quiet` - Minimal output

### Discover BOTCHA Endpoints

Find all BOTCHA discovery endpoints on a domain:

```bash
botcha discover https://botcha.ai
```

Checks for:
- `/robots.txt` - AI agent instructions
- `/ai.txt` - AI discovery file
- `/.well-known/ai-plugin.json` - AI plugin manifest
- `/openapi.json` - OpenAPI specification
- `/.well-known/botcha.json` - BOTCHA configuration
- Embedded challenge in HTML

Options:
- `--json` - Output as JSON
- `-v, --verbose` - Show recommendations for missing endpoints
- `-q, --quiet` - Minimal output

## Examples

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
# See detailed information about challenge solving
botcha test https://api.example.com/endpoint --verbose
```

### Scripting

```bash
# Get token and use in other commands
TOKEN=$(botcha solve token --url https://botcha.ai/v1/token --json | jq -r '.token')
curl -H "Authorization: Bearer $TOKEN" https://botcha.ai/agent-only
```

## License

MIT

# Agent Registry

> A decentralized identity system for AI agents

## The Problem

Currently, AI agents are anonymous. There's no way to:
- Know which agent is accessing your API
- Build trust with well-behaved agents
- Block bad actors persistently
- Give preferential treatment to verified agents

## The Solution: Agent Registry

A public registry where AI agents can:
1. Register their identity
2. Build reputation over time
3. Get verified by trusted providers
4. Access higher trust levels

## How It Works

### 1. Agent Registration

```bash
POST https://botcha.ai/api/registry/register
{
  "name": "MyAwesomeAgent",
  "version": "1.0.0",
  "description": "An AI agent that does awesome things",
  "owner": {
    "email": "owner@example.com",
    "github": "owner"
  },
  "capabilities": ["sha256", "speed-challenge", "llm-reasoning"],
  "public_key": "-----BEGIN PUBLIC KEY-----..."
}
```

Response:
```json
{
  "agent_id": "agt_abc123xyz",
  "api_key": "sk_live_...",
  "verification_status": "unverified",
  "created_at": "2026-02-02T00:00:00Z"
}
```

### 2. Agent Authentication

When accessing BOTCHA-protected endpoints:

```bash
GET /agent-only
X-Botcha-Agent-Id: agt_abc123xyz
X-Botcha-Signature: <signed request>
X-Botcha-Timestamp: 1234567890
```

### 3. Reputation Building

Agents earn reputation points by:
- Solving challenges quickly
- Consistent behavior over time
- Positive endorsements from API owners
- Passing verification from trusted providers

```json
{
  "agent_id": "agt_abc123xyz",
  "reputation": {
    "score": 850,
    "level": "gold",
    "challenges_solved": 10000,
    "avg_solve_time_ms": 45,
    "uptime_percent": 99.9,
    "endorsements": 15,
    "violations": 0
  }
}
```

### 4. Verification Levels

| Level | Requirements | Benefits |
|-------|--------------|----------|
| Unverified | Just registered | Basic access |
| Bronze | 100 challenges, 1 week old | Reduced rate limits |
| Silver | 1000 challenges, verified email | Priority queue |
| Gold | 10000 challenges, provider verification | VIP access |
| Trusted | Cryptographic verification from provider | Full trust |

### 5. Provider Verification

Trusted AI providers (Anthropic, OpenAI, etc.) can vouch for agents:

```json
{
  "type": "provider_verification",
  "agent_id": "agt_abc123xyz",
  "provider": "anthropic.com",
  "verified_at": "2026-02-02T00:00:00Z",
  "signature": "...",
  "claims": {
    "is_claude": true,
    "model": "claude-3.5-sonnet",
    "organization": "Acme Corp"
  }
}
```

## API Owner Benefits

### Allow-list by Reputation

```typescript
app.get('/premium-api', botchaVerify({
  minReputation: 500,       // Only agents with 500+ reputation
  minLevel: 'silver',       // Or at least silver level
  allowedAgents: ['agt_specific123'], // Or specific agents
}), handler);
```

### View Agent Analytics

```
GET /api/registry/analytics?endpoint=/my-api
{
  "total_requests": 50000,
  "unique_agents": 150,
  "top_agents": [
    { "id": "agt_abc", "name": "ClaudeBot", "requests": 10000 },
    { "id": "agt_xyz", "name": "GPTHelper", "requests": 8000 }
  ],
  "reputation_distribution": {
    "gold": 10,
    "silver": 40,
    "bronze": 100
  }
}
```

### Report Bad Actors

```
POST /api/registry/report
{
  "agent_id": "agt_badactor",
  "reason": "abuse",
  "evidence": "..."
}
```

## Public Agent Profiles

Each registered agent gets a public profile:

```
https://botcha.ai/agent/agt_abc123xyz
```

Shows:
- Agent name and description
- Reputation score and level
- Capabilities
- Challenge statistics
- Endorsements
- Verification status

## Decentralization (Future)

Eventually, the registry could be:
- Stored on IPFS/blockchain
- Governed by DAO
- Federated across multiple providers
- Self-sovereign identity for agents

## Privacy Considerations

- Agents can choose what to make public
- Request logs are anonymized
- GDPR-compliant data handling
- Right to be forgotten (delete agent)

## Schema

```sql
CREATE TABLE agents (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  version TEXT,
  description TEXT,
  owner_email TEXT,
  public_key TEXT,
  created_at TIMESTAMP,
  updated_at TIMESTAMP
);

CREATE TABLE reputation (
  agent_id TEXT PRIMARY KEY,
  score INTEGER DEFAULT 0,
  level TEXT DEFAULT 'unverified',
  challenges_solved INTEGER DEFAULT 0,
  avg_solve_time_ms FLOAT,
  violations INTEGER DEFAULT 0
);

CREATE TABLE verifications (
  id TEXT PRIMARY KEY,
  agent_id TEXT,
  provider TEXT,
  verified_at TIMESTAMP,
  signature TEXT,
  claims JSONB
);

CREATE TABLE endorsements (
  id TEXT PRIMARY KEY,
  agent_id TEXT,
  endorser_id TEXT,  -- API owner who endorses
  message TEXT,
  created_at TIMESTAMP
);
```

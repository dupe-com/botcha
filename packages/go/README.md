# BOTCHA Go SDK

[![Go Reference](https://pkg.go.dev/badge/github.com/dupe-com/botcha/packages/go.svg)](https://pkg.go.dev/github.com/dupe-com/botcha/packages/go)
[![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)](https://go.dev)

Official Go SDK for [BOTCHA](https://botcha.ai) — the reverse CAPTCHA that verifies AI agents.

BOTCHA protects your APIs from non-AI traffic by issuing speed challenges (SHA256 puzzles) that AI agents can solve in microseconds but humans cannot. This SDK handles the full challenge flow plus all BOTCHA management APIs.

## Installation

```bash
go get github.com/dupe-com/botcha/packages/go
```

**Requires Go 1.21+. Zero external dependencies — stdlib only.**

## Quick Start

```go
import botcha "github.com/dupe-com/botcha/packages/go"

ctx := context.Background()

// Create client
client := botcha.NewClient("app_xxx", "sk_xxx")

// Solve a challenge → get a JWT access token
token, err := client.SolveChallenge(ctx)
if err != nil {
    log.Fatal(err)
}
fmt.Println("Access token:", token)
// SolveChallenge also stores the token on the client for authenticated API calls.
```

## Challenge Flow

BOTCHA verifies agents by issuing SHA256 speed challenges:

```go
// Option A: One-shot (recommended)
token, err := client.SolveChallenge(ctx)

// Option B: Manual control
challengeResp, err := client.GetChallenge(ctx)
// solve yourself using SolveRaw:
answers := botcha.SolveRaw([]int{12345, 67890})
// ...then submit manually via /v1/token/verify

// How the math works:
// SHA256("12345") → take first 8 hex chars → "5994471a"
```

## Token Management

```go
// Validate a token
result, err := client.ValidateToken(ctx, token)
if err != nil {
    log.Fatal(err)
}
if result.Valid {
    fmt.Println("Agent:", result.AgentID)
}

// Revoke a token
if _, err := client.RevokeToken(ctx, token); err != nil {
    log.Fatal(err)
}

// Refresh using refresh token
newTokenResp, err := client.RefreshToken(ctx, refreshToken)
```

## App Management

```go
// Create a new BOTCHA app
app, err := client.CreateApp(ctx, "admin@example.com")
if err != nil {
    log.Fatal(err)
}
fmt.Println("App ID:", app.AppID)
fmt.Println("Secret:", app.AppSecret) // store this securely!

// Verify email
if _, err := client.VerifyEmail(ctx, "123456"); err != nil { // code from email
    log.Fatal(err)
}

// Rotate app secret
// Requires a dashboard session token:
client.SetAccessToken(dashboardSessionToken)
rotated, err := client.RotateSecret(ctx)
if err != nil {
    log.Fatal(err)
}
fmt.Println("New secret:", rotated.AppSecret)
```

## Agent Registry

```go
// Register an agent
agent, err := client.RegisterAgent(ctx, botcha.RegisterAgentInput{
    Name:     "MyGoAgent",
    Operator: "mycompany",
    Version:  "1.0.0",
})
if err != nil {
    log.Fatal(err)
}

// Retrieve and list
agent, err = client.GetAgent(ctx, agent.AgentID)
agents, err := client.ListAgents(ctx)
```

## TAP (Trusted Agent Protocol)

Register agents with cryptographic keys for signed sessions:

```go
// Register with a public key
tapAgent, err := client.RegisterTAPAgent(ctx, botcha.RegisterTAPAgentInput{
    Name:               "SecureAgent",
    PublicKey:          pemEncodedPublicKey,
    SignatureAlgorithm: "ecdsa-p256-sha256",
    Capabilities: []botcha.TAPCapability{
        {Action: "browse", Scope: []string{"products"}},
    },
})
if err != nil {
    log.Fatal(err)
}

// Create a session
session, err := client.CreateTAPSession(ctx, botcha.CreateTAPSessionInput{
    AgentID:     tapAgent.AgentID,
    UserContext: "hashed-user-123",
    Intent: botcha.TAPIntent{
        Action:   "browse",
        Resource: "products",
    },
})

// Get JWKS for server-side verification
jwks, err := client.GetJWKS(ctx)
```

## Delegation Chains

Delegate capabilities from one agent to another:

```go
delegation, err := client.CreateDelegation(ctx, botcha.CreateDelegationInput{
    GrantorID: "agent_a",
    GranteeID: "agent_b",
    Capabilities: []botcha.TAPCapability{
        {Action: "browse"},
    },
    DurationSeconds: 3600,
})
if err != nil {
    log.Fatal(err)
}

// Verify the full chain
verification, err := client.VerifyDelegationChain(ctx, delegation.DelegationID)

// Revoke
if _, err := client.RevokeDelegation(ctx, delegation.DelegationID, "no longer needed"); err != nil {
    log.Fatal(err)
}
```

## Capability Attestations

Fine-grained action:resource permissions with explicit deny:

```go
att, err := client.IssueAttestation(ctx, botcha.IssueAttestationInput{
    AgentID:         "agent_abc123",
    Can:             []string{"read:invoices", "browse:*"},
    Cannot:          []string{"write:transfers"},
    DurationSeconds: 3600,
})
if err != nil {
    log.Fatal(err)
}
// Use att.Token in X-Botcha-Attestation header

// Verify a capability
result, err := client.VerifyAttestation(ctx, att.Token, "read", "invoices")
if err != nil {
    log.Fatal(err)
}
if result.Allowed {
    fmt.Println("Access granted!")
}
```

## Reputation Scoring

Track agent behavior and reputation over time:

```go
// Get score
rep, err := client.GetReputation(ctx, agentID)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Score: %.0f, Tier: %s\n", rep.Score, rep.Tier)
// Output: Score: 750, Tier: good

// Record an event
result, err := client.RecordReputationEvent(ctx, botcha.RecordReputationEventInput{
    AgentID:  agentID,
    Category: "verification",
    Action:   "challenge_solved",
})

// List events
events, err := client.ListReputationEvents(ctx, agentID, &botcha.ListReputationEventsOptions{
    Category: "verification",
    Limit:    50,
})
```

## Configuration

```go
client := botcha.NewClient("app_xxx", "sk_xxx",
    botcha.WithBaseURL("https://botcha.ai"),       // default
    botcha.WithTimeout(10*time.Second),             // default: 30s
    botcha.WithAgentIdentity("myapp/1.0"),          // User-Agent
    botcha.WithHTTPClient(customHTTPClient),        // bring your own
)
```

For authenticated endpoints (`/v1/agents/*`, TAP, delegation, attestation, reputation), set an access token by:
- calling `SolveChallenge(ctx)` first (token auto-stored), or
- passing `WithAccessToken(token)` / `SetAccessToken(token)`.

## Error Handling

```go
token, err := client.SolveChallenge(ctx)
if err != nil {
    var botchaErr *botcha.BotchaError
    if errors.As(err, &botchaErr) {
        fmt.Println("API error:", botchaErr.Code, botchaErr.Message)
        fmt.Println("HTTP status:", botchaErr.Status)
    }
}
```

## Feature Parity

| Feature | TypeScript | Python | **Go** |
|---------|-----------|--------|--------|
| Challenge solving | ✅ | ✅ | ✅ |
| Token management | ✅ | ✅ | ✅ |
| App management | ✅ | ✅ | ✅ |
| Agent registry | ✅ | ✅ | ✅ |
| TAP agents | ✅ | ✅ | ✅ |
| Delegation chains | ✅ | ✅ | ✅ |
| Attestations | ✅ | ✅ | ✅ |
| Reputation scoring | ✅ | ✅ | ✅ |
| Zero deps (stdlib) | ❌ | ❌ | ✅ |

## License

MIT

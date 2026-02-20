package botcha

import (
	"context"
	"fmt"
	"net/url"
)

// RegisterTAPAgent registers a new TAP (Trusted Agent Protocol) agent.
// Optionally include a public key for cryptographic session signing.
func (c *Client) RegisterTAPAgent(ctx context.Context, input RegisterTAPAgentInput) (*TAPAgentResponse, error) {
	var resp TAPAgentResponse
	if err := c.post(ctx, "/v1/tap/agents", input, &resp); err != nil {
		return nil, fmt.Errorf("botcha: register TAP agent: %w", err)
	}
	return &resp, nil
}

// GetTAPAgent retrieves a TAP agent by its ID.
func (c *Client) GetTAPAgent(ctx context.Context, agentID string) (*TAPAgentResponse, error) {
	var resp TAPAgentResponse
	if err := c.get(ctx, "/v1/tap/agents/"+url.PathEscape(agentID), &resp); err != nil {
		return nil, fmt.Errorf("botcha: get TAP agent: %w", err)
	}
	return &resp, nil
}

// ListTAPAgents lists all TAP agents for the current app.
func (c *Client) ListTAPAgents(ctx context.Context) (*TAPAgentListResponse, error) {
	var resp TAPAgentListResponse
	if err := c.get(ctx, "/v1/tap/agents", &resp); err != nil {
		return nil, fmt.Errorf("botcha: list TAP agents: %w", err)
	}
	return &resp, nil
}

// CreateTAPSession creates a new TAP session for an agent with a specific intent.
// Sessions are short-lived and scoped to the declared intent.
func (c *Client) CreateTAPSession(ctx context.Context, input CreateTAPSessionInput) (*TAPSessionResponse, error) {
	var resp TAPSessionResponse
	if err := c.post(ctx, "/v1/tap/sessions", input, &resp); err != nil {
		return nil, fmt.Errorf("botcha: create TAP session: %w", err)
	}
	return &resp, nil
}

// GetTAPSession retrieves an existing TAP session by its ID.
func (c *Client) GetTAPSession(ctx context.Context, sessionID string) (*TAPSessionResponse, error) {
	var resp TAPSessionResponse
	if err := c.get(ctx, "/v1/tap/sessions/"+url.PathEscape(sessionID), &resp); err != nil {
		return nil, fmt.Errorf("botcha: get TAP session: %w", err)
	}
	return &resp, nil
}

// RotateKey rotates the public key for a TAP agent.
// The old key is immediately invalidated.
func (c *Client) RotateKey(ctx context.Context, agentID, publicKey, algorithm string) (*TAPAgentResponse, error) {
	req := map[string]string{
		"agent_id":            agentID,
		"public_key":          publicKey,
		"signature_algorithm": algorithm,
	}
	var resp TAPAgentResponse
	if err := c.post(ctx, "/v1/tap/agents/"+url.PathEscape(agentID)+"/rotate-key", req, &resp); err != nil {
		return nil, fmt.Errorf("botcha: rotate TAP key: %w", err)
	}
	return &resp, nil
}

// GetJWKS retrieves the public JWKS (JSON Web Key Set) for all TAP agents.
// Use this to verify TAP agent signatures server-side.
func (c *Client) GetJWKS(ctx context.Context) (*JWKSet, error) {
	var resp JWKSet
	if err := c.get(ctx, "/v1/tap/jwks", &resp); err != nil {
		return nil, fmt.Errorf("botcha: get JWKS: %w", err)
	}
	return &resp, nil
}

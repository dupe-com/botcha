package botcha

import (
	"context"
	"fmt"
	"net/url"
)

// RegisterAgent registers a new AI agent with BOTCHA.
// The agent gets a unique agent_id for identity tracking.
func (c *Client) RegisterAgent(ctx context.Context, input RegisterAgentInput) (*AgentResponse, error) {
	var resp AgentResponse
	if err := c.authPost(ctx, "/v1/agents/register", input, &resp); err != nil {
		return nil, fmt.Errorf("botcha: register agent: %w", err)
	}
	return &resp, nil
}

// GetAgent retrieves an agent by its ID.
func (c *Client) GetAgent(ctx context.Context, agentID string) (*AgentResponse, error) {
	var resp AgentResponse
	if err := c.authGet(ctx, "/v1/agents/"+url.PathEscape(agentID), &resp); err != nil {
		return nil, fmt.Errorf("botcha: get agent: %w", err)
	}
	return &resp, nil
}

// ListAgents lists all agents registered for the current app.
func (c *Client) ListAgents(ctx context.Context) (*AgentListResponse, error) {
	var resp AgentListResponse
	if err := c.authGet(ctx, "/v1/agents", &resp); err != nil {
		return nil, fmt.Errorf("botcha: list agents: %w", err)
	}
	return &resp, nil
}

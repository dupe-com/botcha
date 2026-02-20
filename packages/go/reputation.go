package botcha

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
)

// GetReputation retrieves the reputation score and tier for an agent.
//
// Example:
//
//	rep, err := client.GetReputation(ctx, "agent_abc123")
//	fmt.Printf("Score: %.0f, Tier: %s\n", rep.Score, rep.Tier)
func (c *Client) GetReputation(ctx context.Context, agentID string) (*ReputationScoreResponse, error) {
	var resp ReputationScoreResponse
	if err := c.get(ctx, "/v1/reputation/"+url.PathEscape(agentID), &resp); err != nil {
		return nil, fmt.Errorf("botcha: get reputation: %w", err)
	}
	return &resp, nil
}

// RecordReputationEvent records a reputation event for an agent.
// The event adjusts the agent's reputation score based on its category and action.
//
// Example:
//
//	result, err := client.RecordReputationEvent(ctx, botcha.RecordReputationEventInput{
//	    AgentID:  "agent_abc123",
//	    Category: "verification",
//	    Action:   "challenge_solved",
//	})
func (c *Client) RecordReputationEvent(ctx context.Context, input RecordReputationEventInput) (*ReputationEventResponse, error) {
	var resp ReputationEventResponse
	if err := c.post(ctx, "/v1/reputation/events", input, &resp); err != nil {
		return nil, fmt.Errorf("botcha: record reputation event: %w", err)
	}
	return &resp, nil
}

// ListReputationEventsOptions controls filtering for ListReputationEvents.
type ListReputationEventsOptions struct {
	Category string
	Limit    int
}

// ListReputationEvents lists reputation events for an agent.
func (c *Client) ListReputationEvents(ctx context.Context, agentID string, opts *ListReputationEventsOptions) (*ReputationEventListResponse, error) {
	params := url.Values{}
	if opts != nil {
		if opts.Category != "" {
			params.Set("category", opts.Category)
		}
		if opts.Limit > 0 {
			params.Set("limit", strconv.Itoa(opts.Limit))
		}
	}

	path := "/v1/reputation/" + url.PathEscape(agentID) + "/events"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var resp ReputationEventListResponse
	if err := c.get(ctx, path, &resp); err != nil {
		return nil, fmt.Errorf("botcha: list reputation events: %w", err)
	}
	return &resp, nil
}

// ResetReputation resets an agent's reputation to the default neutral score (500).
// This is an admin action that clears all event history.
func (c *Client) ResetReputation(ctx context.Context, agentID string) (*ReputationResetResponse, error) {
	var resp ReputationResetResponse
	if err := c.post(ctx, "/v1/reputation/"+url.PathEscape(agentID)+"/reset", map[string]string{}, &resp); err != nil {
		return nil, fmt.Errorf("botcha: reset reputation: %w", err)
	}
	return &resp, nil
}

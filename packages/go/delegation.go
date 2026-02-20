package botcha

import (
	"context"
	"fmt"
	"net/url"
)

// CreateDelegation creates a new capability delegation from one agent to another.
// Delegations can be chained up to max_depth levels deep.
func (c *Client) CreateDelegation(ctx context.Context, input CreateDelegationInput) (*DelegationResponse, error) {
	var resp DelegationResponse
	if err := c.authPost(ctx, "/v1/delegations", input, &resp); err != nil {
		return nil, fmt.Errorf("botcha: create delegation: %w", err)
	}
	return &resp, nil
}

// GetDelegation retrieves a delegation by its ID.
func (c *Client) GetDelegation(ctx context.Context, delegationID string) (*DelegationResponse, error) {
	var resp DelegationResponse
	if err := c.authGet(ctx, "/v1/delegations/"+url.PathEscape(delegationID), &resp); err != nil {
		return nil, fmt.Errorf("botcha: get delegation: %w", err)
	}
	return &resp, nil
}

// ListDelegationOptions controls filtering for ListDelegations.
type ListDelegationOptions struct {
	AgentID        string
	Direction      string // "in", "out", or "both"
	IncludeRevoked bool
	IncludeExpired bool
}

// ListDelegations lists delegations for an agent.
func (c *Client) ListDelegations(ctx context.Context, opts ListDelegationOptions) (*DelegationListResponse, error) {
	params := url.Values{}
	if opts.AgentID != "" {
		params.Set("agent_id", opts.AgentID)
	}
	if opts.Direction != "" {
		params.Set("direction", opts.Direction)
	}
	if opts.IncludeRevoked {
		params.Set("include_revoked", "true")
	}
	if opts.IncludeExpired {
		params.Set("include_expired", "true")
	}

	path := "/v1/delegations"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	var resp DelegationListResponse
	if err := c.authGet(ctx, path, &resp); err != nil {
		return nil, fmt.Errorf("botcha: list delegations: %w", err)
	}
	return &resp, nil
}

// RevokeDelegation revokes a delegation. Cascades to all sub-delegations.
func (c *Client) RevokeDelegation(ctx context.Context, delegationID, reason string) (*RevokeDelegationResponse, error) {
	var body any
	if reason != "" {
		body = map[string]string{"reason": reason}
	} else {
		body = map[string]string{}
	}

	var resp RevokeDelegationResponse
	if err := c.authPost(ctx, "/v1/delegations/"+url.PathEscape(delegationID)+"/revoke", body, &resp); err != nil {
		return nil, fmt.Errorf("botcha: revoke delegation: %w", err)
	}
	return &resp, nil
}

// VerifyDelegationChain verifies a delegation chain is valid.
// Returns the full chain and effective capabilities if valid.
func (c *Client) VerifyDelegationChain(ctx context.Context, delegationID string) (*DelegationVerifyResponse, error) {
	req := map[string]string{"delegation_id": delegationID}
	var resp DelegationVerifyResponse
	if err := c.authPost(ctx, "/v1/verify/delegation", req, &resp); err != nil {
		return nil, fmt.Errorf("botcha: verify delegation chain: %w", err)
	}
	return &resp, nil
}

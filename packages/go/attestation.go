package botcha

import (
	"context"
	"fmt"
	"net/url"
)

// IssueAttestation issues a capability attestation token for an agent.
// The token grants fine-grained action:resource permissions with explicit deny rules.
//
// Example:
//
//	att, err := client.IssueAttestation(ctx, botcha.IssueAttestationInput{
//	    AgentID:         "agent_abc123",
//	    Can:             []string{"read:invoices", "browse:*"},
//	    Cannot:          []string{"write:transfers"},
//	    DurationSeconds: 3600,
//	})
//	// Use att.Token in X-Botcha-Attestation header
func (c *Client) IssueAttestation(ctx context.Context, input IssueAttestationInput) (*AttestationResponse, error) {
	var resp AttestationResponse
	if err := c.authPost(ctx, "/v1/attestations", input, &resp); err != nil {
		return nil, fmt.Errorf("botcha: issue attestation: %w", err)
	}
	return &resp, nil
}

// GetAttestation retrieves an attestation by its ID.
func (c *Client) GetAttestation(ctx context.Context, attestationID string) (*AttestationResponse, error) {
	var resp AttestationResponse
	if err := c.authGet(ctx, "/v1/attestations/"+url.PathEscape(attestationID), &resp); err != nil {
		return nil, fmt.Errorf("botcha: get attestation: %w", err)
	}
	return &resp, nil
}

// ListAttestations lists attestations for a specific agent.
func (c *Client) ListAttestations(ctx context.Context, agentID string) (*AttestationListResponse, error) {
	params := url.Values{}
	params.Set("agent_id", agentID)

	var resp AttestationListResponse
	if err := c.authGet(ctx, "/v1/attestations?"+params.Encode(), &resp); err != nil {
		return nil, fmt.Errorf("botcha: list attestations: %w", err)
	}
	return &resp, nil
}

// RevokeAttestation revokes an attestation. The token will be rejected on future verification.
func (c *Client) RevokeAttestation(ctx context.Context, attestationID, reason string) (*RevokeAttestationResponse, error) {
	var body any
	if reason != "" {
		body = map[string]string{"reason": reason}
	} else {
		body = map[string]string{}
	}

	var resp RevokeAttestationResponse
	if err := c.authPost(ctx, "/v1/attestations/"+url.PathEscape(attestationID)+"/revoke", body, &resp); err != nil {
		return nil, fmt.Errorf("botcha: revoke attestation: %w", err)
	}
	return &resp, nil
}

// VerifyAttestation verifies an attestation token and optionally checks a specific capability.
// Pass action and resource to check whether the attestation grants that specific permission.
func (c *Client) VerifyAttestation(ctx context.Context, token, action, resource string) (*AttestationVerifyResponse, error) {
	body := map[string]string{"token": token}
	if action != "" {
		body["action"] = action
	}
	if resource != "" {
		body["resource"] = resource
	}

	var resp AttestationVerifyResponse
	if err := c.authPost(ctx, "/v1/verify/attestation", body, &resp); err != nil {
		return nil, fmt.Errorf("botcha: verify attestation: %w", err)
	}
	return &resp, nil
}

package botcha

import (
	"context"
	"fmt"
)

// ValidateToken validates a BOTCHA JWT access token.
// Returns validation details including the agent ID and expiry.
func (c *Client) ValidateToken(ctx context.Context, token string) (*ValidateTokenResponse, error) {
	req := ValidateTokenRequest{Token: token}
	var resp ValidateTokenResponse
	if err := c.post(ctx, "/v1/verify", req, &resp); err != nil {
		return nil, fmt.Errorf("botcha: validate token: %w", err)
	}
	return &resp, nil
}

// RevokeToken revokes an access token, making it invalid for future requests.
func (c *Client) RevokeToken(ctx context.Context, token string) (*RevokeTokenResponse, error) {
	req := RevokeTokenRequest{Token: token}
	var resp RevokeTokenResponse
	if err := c.post(ctx, "/v1/token/revoke", req, &resp); err != nil {
		return nil, fmt.Errorf("botcha: revoke token: %w", err)
	}
	return &resp, nil
}

// RefreshToken exchanges a refresh token for a new access token.
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	req := RefreshTokenRequest{
		RefreshToken: refreshToken,
		AppID:        c.appID,
	}
	var resp TokenResponse
	if err := c.post(ctx, "/v1/token/refresh", req, &resp); err != nil {
		return nil, fmt.Errorf("botcha: refresh token: %w", err)
	}
	return &resp, nil
}

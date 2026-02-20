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
	if err := c.post(ctx, "/v1/token/validate", req, &resp); err != nil {
		return nil, fmt.Errorf("botcha: validate token: %w", err)
	}
	return &resp, nil
}

// RevokeToken revokes an access token, making it invalid for future requests.
func (c *Client) RevokeToken(ctx context.Context, token string) (*RevokeTokenResponse, error) {
	appID, err := c.requireAppID()
	if err != nil {
		return nil, fmt.Errorf("botcha: revoke token: %w", err)
	}

	req := RevokeTokenRequest{
		Token: token,
		AppID: appID,
	}
	var resp RevokeTokenResponse
	if err := c.post(ctx, "/v1/token/revoke", req, &resp); err != nil {
		return nil, fmt.Errorf("botcha: revoke token: %w", err)
	}
	return &resp, nil
}

// RefreshToken exchanges a refresh token for a new access token.
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	appID, err := c.requireAppID()
	if err != nil {
		return nil, fmt.Errorf("botcha: refresh token: %w", err)
	}

	req := RefreshTokenRequest{
		RefreshToken: refreshToken,
		AppID:        appID,
	}
	var resp TokenResponse
	if err := c.post(ctx, "/v1/token/refresh", req, &resp); err != nil {
		return nil, fmt.Errorf("botcha: refresh token: %w", err)
	}
	// Keep client auth state in sync with successful refreshes.
	if resp.AccessToken != "" {
		c.accessToken = resp.AccessToken
	} else if resp.Token != "" {
		c.accessToken = resp.Token
	}
	return &resp, nil
}

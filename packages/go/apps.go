package botcha

import (
	"context"
	"fmt"
	"net/url"
)

// CreateApp creates a new multi-tenant BOTCHA application.
// Returns the app credentials including the app_secret (store this securely!).
func (c *Client) CreateApp(ctx context.Context, email string) (*CreateAppResponse, error) {
	req := map[string]string{"email": email}
	var resp CreateAppResponse
	if err := c.post(ctx, "/v1/apps", req, &resp); err != nil {
		return nil, fmt.Errorf("botcha: create app: %w", err)
	}
	return &resp, nil
}

// VerifyEmail verifies the email for an app using the code sent to the email address.
func (c *Client) VerifyEmail(ctx context.Context, code string) (*VerifyEmailResponse, error) {
	appID, err := c.requireAppID()
	if err != nil {
		return nil, fmt.Errorf("botcha: verify email: %w", err)
	}

	req := map[string]string{"code": code}
	if c.appSecret != "" {
		req["app_secret"] = c.appSecret
	}
	var resp VerifyEmailResponse
	if err := c.post(ctx, "/v1/apps/"+url.PathEscape(appID)+"/verify-email", req, &resp); err != nil {
		return nil, fmt.Errorf("botcha: verify email: %w", err)
	}
	return &resp, nil
}

// ResendVerification resends the email verification code.
func (c *Client) ResendVerification(ctx context.Context) (*ResendVerificationResponse, error) {
	appID, err := c.requireAppID()
	if err != nil {
		return nil, fmt.Errorf("botcha: resend verification: %w", err)
	}

	req := map[string]string{}
	if c.appSecret != "" {
		req["app_secret"] = c.appSecret
	}
	var resp ResendVerificationResponse
	if err := c.post(ctx, "/v1/apps/"+url.PathEscape(appID)+"/resend-verification", req, &resp); err != nil {
		return nil, fmt.Errorf("botcha: resend verification: %w", err)
	}
	return &resp, nil
}

// RotateSecret rotates the app secret. The old secret is immediately invalidated.
// This endpoint requires a dashboard session token in accessToken.
// Store the new secret securely!
func (c *Client) RotateSecret(ctx context.Context) (*RotateSecretResponse, error) {
	appID, err := c.requireAppID()
	if err != nil {
		return nil, fmt.Errorf("botcha: rotate secret: %w", err)
	}

	var resp RotateSecretResponse
	if err := c.authPost(ctx, "/v1/apps/"+url.PathEscape(appID)+"/rotate-secret", map[string]string{}, &resp); err != nil {
		return nil, fmt.Errorf("botcha: rotate secret: %w", err)
	}
	return &resp, nil
}

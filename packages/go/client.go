// Package botcha provides a Go client for the BOTCHA reverse CAPTCHA service.
//
// BOTCHA verifies AI agents by issuing speed challenges (SHA256 hashing puzzles).
// This SDK handles challenge solving, token management, agent registration,
// TAP protocol, delegation chains, capability attestations, and reputation scoring.
//
// Basic usage:
//
//	client := botcha.NewClient("app_xxx", "sk_xxx")
//	token, err := client.SolveChallenge(ctx)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println("Access token:", token)
package botcha

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	defaultBaseURL       = "https://botcha.ai"
	defaultAgentIdentity = "botcha-go/1.0.0"
	defaultTimeout       = 30 * time.Second
)

// Client is the BOTCHA API client.
type Client struct {
	appID         string
	appSecret     string
	baseURL       string
	agentIdentity string
	http          *http.Client
}

// NewClient creates a new BOTCHA client with the given app credentials.
// Use functional options to customize behaviour:
//
//	client := botcha.NewClient("app_xxx", "sk_xxx",
//	    botcha.WithBaseURL("https://botcha.ai"),
//	    botcha.WithTimeout(10*time.Second),
//	)
func NewClient(appID, appSecret string, opts ...Option) *Client {
	c := &Client{
		appID:         appID,
		appSecret:     appSecret,
		baseURL:       defaultBaseURL,
		agentIdentity: defaultAgentIdentity,
		http:          &http.Client{Timeout: defaultTimeout},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// do performs an authenticated HTTP request to the BOTCHA API.
// body (if non-nil) is JSON-encoded and sent as the request body.
// result (if non-nil) receives the JSON-decoded response body.
func (c *Client) do(ctx context.Context, method, path string, body, result any) error {
	var reqBody io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("botcha: marshal request: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return fmt.Errorf("botcha: create request: %w", err)
	}

	req.Header.Set("User-Agent", c.agentIdentity)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.appSecret != "" {
		req.Header.Set("Authorization", "Bearer "+c.appSecret)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("botcha: http: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("botcha: read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr BotchaError
		if err := json.Unmarshal(respBytes, &apiErr); err != nil {
			apiErr.Message = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(respBytes))
		}
		apiErr.Status = resp.StatusCode
		return &apiErr
	}

	if result != nil {
		if err := json.Unmarshal(respBytes, result); err != nil {
			return fmt.Errorf("botcha: decode response: %w", err)
		}
	}

	return nil
}

// get is a helper for GET requests without a body.
func (c *Client) get(ctx context.Context, path string, result any) error {
	return c.do(ctx, http.MethodGet, path, nil, result)
}

// post is a helper for POST requests.
func (c *Client) post(ctx context.Context, path string, body, result any) error {
	return c.do(ctx, http.MethodPost, path, body, result)
}

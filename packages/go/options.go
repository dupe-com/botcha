package botcha

import (
	"net/http"
	"time"
)

// Option is a functional option for configuring the Client.
type Option func(*Client)

// WithBaseURL overrides the default base URL (https://botcha.ai).
func WithBaseURL(baseURL string) Option {
	return func(c *Client) {
		c.baseURL = baseURL
	}
}

// WithHTTPClient sets a custom *http.Client.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		c.http = httpClient
	}
}

// WithTimeout sets the HTTP client timeout.
// If WithHTTPClient has already been called, this creates a new http.Client
// with the given timeout rather than mutating the provided client.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		if c.http == nil {
			c.http = &http.Client{Timeout: d}
			return
		}
		// Avoid mutating a user-provided client; create a shallow copy.
		clone := *c.http
		clone.Timeout = d
		c.http = &clone
	}
}

// WithAgentIdentity sets the User-Agent header value.
func WithAgentIdentity(identity string) Option {
	return func(c *Client) {
		c.agentIdentity = identity
	}
}

// WithAccessToken sets the bearer token used by authenticated endpoints.
func WithAccessToken(token string) Option {
	return func(c *Client) {
		c.accessToken = token
	}
}

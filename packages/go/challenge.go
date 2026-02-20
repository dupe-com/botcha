package botcha

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/url"
	"strconv"
)

// solveProblems computes SHA256 of each problem number and returns the first 8 hex chars.
// This is BOTCHA's core verification mechanism.
func solveProblems(problems []Problem) []string {
	answers := make([]string, len(problems))
	for i, p := range problems {
		h := sha256.Sum256([]byte(strconv.Itoa(p.Num)))
		answers[i] = fmt.Sprintf("%x", h[:4]) // first 8 hex chars (4 bytes)
	}
	return answers
}

// SolveRaw computes SHA256 answers for raw numbers. Useful for standalone challenge solving.
func SolveRaw(numbers []int) []string {
	answers := make([]string, len(numbers))
	for i, n := range numbers {
		h := sha256.Sum256([]byte(strconv.Itoa(n)))
		answers[i] = fmt.Sprintf("%x", h[:4])
	}
	return answers
}

// GetChallenge fetches a BOTCHA challenge from GET /v1/token.
// The returned Challenge must be solved and submitted via SolveChallenge or manually.
func (c *Client) GetChallenge(ctx context.Context) (*ChallengeResponse, error) {
	appID, err := c.requireAppID()
	if err != nil {
		return nil, fmt.Errorf("botcha: get challenge: %w", err)
	}

	params := url.Values{}
	params.Set("app_id", appID)
	path := "/v1/token?" + params.Encode()

	// GetChallenge does NOT send the Authorization header (it's a public endpoint).
	// We use a temporary client without the app secret for this request.
	tmp := &Client{
		baseURL:       c.baseURL,
		agentIdentity: c.agentIdentity,
		http:          c.http,
		// no appSecret for the challenge fetch
	}

	var resp ChallengeResponse
	if err := tmp.get(ctx, path, &resp); err != nil {
		return nil, fmt.Errorf("botcha: get challenge: %w", err)
	}
	return &resp, nil
}

// SolveChallenge fetches a challenge, solves it automatically, and returns a JWT access token.
// This is the main method most clients should use.
//
// Example:
//
//	token, err := client.SolveChallenge(ctx)
//	if err != nil {
//	    log.Fatal(err)
//	}
func (c *Client) SolveChallenge(ctx context.Context) (string, error) {
	// Step 1: Fetch challenge
	challengeResp, err := c.GetChallenge(ctx)
	if err != nil {
		return "", err
	}

	if challengeResp.Challenge.ID == "" {
		return "", fmt.Errorf("botcha: no challenge ID in response")
	}

	// Step 2: Solve
	answers := solveProblems(challengeResp.Challenge.Problems)

	// Step 3: Submit
	verifyReq := VerifyRequest{
		ID:      challengeResp.Challenge.ID,
		Answers: answers,
		AppID:   c.appID,
	}

	// Verify also goes without Authorization
	tmp := &Client{
		baseURL:       c.baseURL,
		agentIdentity: c.agentIdentity,
		http:          c.http,
	}

	var tokenResp TokenResponse
	if err := tmp.post(ctx, "/v1/token/verify", verifyReq, &tokenResp); err != nil {
		return "", fmt.Errorf("botcha: verify challenge: %w", err)
	}

	// Prefer access_token, fall back to token field
	token := tokenResp.AccessToken
	if token == "" {
		token = tokenResp.Token
	}
	if token == "" {
		return "", fmt.Errorf("botcha: no access token in verify response")
	}

	c.accessToken = token
	return token, nil
}

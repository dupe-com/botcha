package botcha

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestSolveProblems(t *testing.T) {
	tests := []struct {
		num      int
		expected string
	}{
		{12345, sha256hex(12345)},
		{0, sha256hex(0)},
		{99999, sha256hex(99999)},
	}

	for _, tt := range tests {
		problems := []Problem{{Num: tt.num}}
		answers := solveProblems(problems)
		if len(answers) != 1 {
			t.Errorf("expected 1 answer, got %d", len(answers))
			continue
		}
		if answers[0] != tt.expected {
			t.Errorf("num=%d: got %q, want %q", tt.num, answers[0], tt.expected)
		}
	}
}

func TestSolveRaw(t *testing.T) {
	nums := []int{1, 2, 3}
	answers := SolveRaw(nums)
	if len(answers) != 3 {
		t.Fatalf("expected 3 answers, got %d", len(answers))
	}
	for i, n := range nums {
		expected := sha256hex(n)
		if answers[i] != expected {
			t.Errorf("index %d: got %q, want %q", i, answers[i], expected)
		}
	}
}

func TestSolveChallenge(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/token":
			json.NewEncoder(w).Encode(ChallengeResponse{
				Success: true,
				Challenge: Challenge{
					ID:       "test-challenge-id",
					Problems: []Problem{{Num: 12345}, {Num: 67890}},
				},
			})
		case "/v1/token/verify":
			var req VerifyRequest
			json.NewDecoder(r.Body).Decode(&req)
			if req.ID != "test-challenge-id" {
				http.Error(w, "wrong challenge id", 400)
				return
			}
			if len(req.Answers) != 2 {
				http.Error(w, "wrong answer count", 400)
				return
			}
			// Verify the answers are correct SHA256 hashes
			if req.Answers[0] != sha256hex(12345) {
				http.Error(w, "wrong answer[0]", 400)
				return
			}
			json.NewEncoder(w).Encode(TokenResponse{
				Success:     true,
				Verified:    true,
				AccessToken: "access-token-abc123",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewClient("app_test", "sk_test", WithBaseURL(server.URL))
	token, err := client.SolveChallenge(context.Background())
	if err != nil {
		t.Fatalf("SolveChallenge error: %v", err)
	}
	if token != "access-token-abc123" {
		t.Errorf("expected token 'access-token-abc123', got %q", token)
	}
	if client.accessToken != "access-token-abc123" {
		t.Errorf("expected client access token to be set, got %q", client.accessToken)
	}
}

func TestGetChallenge(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/token" {
			json.NewEncoder(w).Encode(ChallengeResponse{
				Success: true,
				Challenge: Challenge{
					ID:           "chall-xyz",
					Problems:     []Problem{{Num: 42}},
					TimeLimit:    5000,
					Instructions: "Solve the SHA256 puzzle",
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient("app_test", "sk_test", WithBaseURL(server.URL))
	resp, err := client.GetChallenge(context.Background())
	if err != nil {
		t.Fatalf("GetChallenge error: %v", err)
	}
	if resp.Challenge.ID != "chall-xyz" {
		t.Errorf("expected ID 'chall-xyz', got %q", resp.Challenge.ID)
	}
	if len(resp.Challenge.Problems) != 1 {
		t.Errorf("expected 1 problem, got %d", len(resp.Challenge.Problems))
	}
}

func TestGetChallengeParsesStringTimeLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/token" {
			_, _ = w.Write([]byte(`{
				"success": true,
				"challenge": {
					"id": "chall-abc",
					"problems": [{"num": 42}],
					"timeLimit": "500ms",
					"instructions": "Solve the SHA256 puzzle"
				}
			}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient("app_test", "sk_test", WithBaseURL(server.URL))
	resp, err := client.GetChallenge(context.Background())
	if err != nil {
		t.Fatalf("GetChallenge error: %v", err)
	}
	if resp.Challenge.TimeLimit != 500 {
		t.Fatalf("expected timeLimit 500ms, got %d", resp.Challenge.TimeLimit)
	}
}

func TestSolveChallengeWithFallbackToken(t *testing.T) {
	// Test that SolveChallenge falls back to the "token" field if "access_token" is empty
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/token":
			json.NewEncoder(w).Encode(ChallengeResponse{
				Success:   true,
				Challenge: Challenge{ID: "c1", Problems: []Problem{{Num: 1}}},
			})
		case "/v1/token/verify":
			json.NewEncoder(w).Encode(TokenResponse{
				Success:  true,
				Verified: true,
				Token:    "legacy-token-format", // old field
			})
		}
	}))
	defer server.Close()

	client := NewClient("app_test", "", WithBaseURL(server.URL))
	token, err := client.SolveChallenge(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "legacy-token-format" {
		t.Errorf("expected legacy token, got %q", token)
	}
}

// sha256hex computes the expected answer for a given number.
func sha256hex(n int) string {
	h := sha256.Sum256([]byte(strconv.Itoa(n)))
	return fmt.Sprintf("%x", h[:4])
}

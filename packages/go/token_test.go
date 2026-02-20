package botcha

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/token/validate" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "" {
			http.Error(w, "unexpected auth header", 400)
			return
		}
		var req ValidateTokenRequest
		json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"valid": true,
			"payload": map[string]any{
				"sub":       "agent_123",
				"app_id":    "app_123",
				"iat":       int64(1700000000),
				"exp":       int64(1700003600),
				"solveTime": 142,
			},
		})
	}))
	defer server.Close()

	client := NewClient("app_test", "sk_test", WithBaseURL(server.URL))
	resp, err := client.ValidateToken(context.Background(), "my.jwt.token")
	if err != nil {
		t.Fatalf("ValidateToken error: %v", err)
	}
	if !resp.Valid {
		t.Error("expected Valid=true")
	}
	if resp.AgentID != "agent_123" {
		t.Errorf("expected agent_id 'agent_123', got %q", resp.AgentID)
	}
	if resp.AppID != "app_123" {
		t.Errorf("expected app_id 'app_123', got %q", resp.AppID)
	}
	if resp.Sub != "agent_123" {
		t.Errorf("expected sub 'agent_123', got %q", resp.Sub)
	}
}

func TestRevokeToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/token/revoke" {
			http.NotFound(w, r)
			return
		}
		var req RevokeTokenRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.AppID != "app_test" {
			http.Error(w, "missing app_id", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RevokeTokenResponse{
			Success: true,
			Message: "token revoked",
		})
	}))
	defer server.Close()

	client := NewClient("app_test", "sk_test", WithBaseURL(server.URL))
	resp, err := client.RevokeToken(context.Background(), "tok.to.revoke")
	if err != nil {
		t.Fatalf("RevokeToken error: %v", err)
	}
	if !resp.Success {
		t.Error("expected Success=true")
	}
}

func TestRefreshToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/token/refresh" {
			http.NotFound(w, r)
			return
		}
		var req RefreshTokenRequest
		json.NewDecoder(r.Body).Decode(&req)
		if req.RefreshToken != "refresh-tok" {
			http.Error(w, "wrong refresh token", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			Success:     true,
			AccessToken: "new-access-token",
		})
	}))
	defer server.Close()

	client := NewClient("app_test", "sk_test", WithBaseURL(server.URL))
	resp, err := client.RefreshToken(context.Background(), "refresh-tok")
	if err != nil {
		t.Fatalf("RefreshToken error: %v", err)
	}
	if resp.AccessToken != "new-access-token" {
		t.Errorf("expected 'new-access-token', got %q", resp.AccessToken)
	}
	if client.accessToken != "new-access-token" {
		t.Errorf("expected client access token 'new-access-token', got %q", client.accessToken)
	}
}

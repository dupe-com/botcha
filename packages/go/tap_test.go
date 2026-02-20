package botcha

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegisterTAPAgentUsesCurrentEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/agents/register/tap" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer access-token" {
			http.Error(w, "missing auth", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(TAPAgentResponse{
			Success: true,
			AgentID: "agent_tap_1",
		})
	}))
	defer server.Close()

	client := NewClient("app_123", "", WithBaseURL(server.URL), WithAccessToken("access-token"))
	resp, err := client.RegisterTAPAgent(context.Background(), RegisterTAPAgentInput{Name: "tap-agent"})
	if err != nil {
		t.Fatalf("RegisterTAPAgent error: %v", err)
	}
	if resp.AgentID != "agent_tap_1" {
		t.Fatalf("expected agent_tap_1, got %q", resp.AgentID)
	}
}

func TestGetJWKSUsesCurrentEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/keys" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer access-token" {
			http.Error(w, "missing auth", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(JWKSet{
			Keys: []JWK{{Kid: "k1", Kty: "EC"}},
		})
	}))
	defer server.Close()

	client := NewClient("app_123", "", WithBaseURL(server.URL), WithAccessToken("access-token"))
	resp, err := client.GetJWKS(context.Background())
	if err != nil {
		t.Fatalf("GetJWKS error: %v", err)
	}
	if len(resp.Keys) != 1 || resp.Keys[0].Kid != "k1" {
		t.Fatalf("unexpected keys: %+v", resp.Keys)
	}
}

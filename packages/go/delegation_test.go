package botcha

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCreateDelegation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/delegations" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer access-token" {
			http.Error(w, "missing auth", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DelegationResponse{
			Success:      true,
			DelegationID: "del_abc123",
			GrantorID:    "agent_a",
			GranteeID:    "agent_b",
		})
	}))
	defer server.Close()

	client := NewClient("app_123", "", WithBaseURL(server.URL), WithAccessToken("access-token"))
	resp, err := client.CreateDelegation(context.Background(), CreateDelegationInput{
		GrantorID:       "agent_a",
		GranteeID:       "agent_b",
		Capabilities:    []TAPCapability{{Action: "browse"}},
		DurationSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("CreateDelegation error: %v", err)
	}
	if resp.DelegationID != "del_abc123" {
		t.Fatalf("expected del_abc123, got %q", resp.DelegationID)
	}
}

func TestRevokeDelegation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/delegations/del_abc123/revoke" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer access-token" {
			http.Error(w, "missing auth", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(RevokeDelegationResponse{
			Success:      true,
			DelegationID: "del_abc123",
			Revoked:      true,
			Message:      "delegation revoked",
		})
	}))
	defer server.Close()

	client := NewClient("app_123", "", WithBaseURL(server.URL), WithAccessToken("access-token"))
	resp, err := client.RevokeDelegation(context.Background(), "del_abc123", "no longer needed")
	if err != nil {
		t.Fatalf("RevokeDelegation error: %v", err)
	}
	if !resp.Revoked {
		t.Fatal("expected revoked=true")
	}
}

func TestVerifyDelegationChain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/verify/delegation" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer access-token" {
			http.Error(w, "missing auth", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DelegationVerifyResponse{
			Success:     true,
			Valid:        true,
			ChainLength: 1,
		})
	}))
	defer server.Close()

	client := NewClient("app_123", "", WithBaseURL(server.URL), WithAccessToken("access-token"))
	resp, err := client.VerifyDelegationChain(context.Background(), "del_abc123")
	if err != nil {
		t.Fatalf("VerifyDelegationChain error: %v", err)
	}
	if !resp.Valid {
		t.Fatal("expected valid=true")
	}
}

func TestGetDelegation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/delegations/del_abc123" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DelegationResponse{
			Success:      true,
			DelegationID: "del_abc123",
		})
	}))
	defer server.Close()

	client := NewClient("app_123", "", WithBaseURL(server.URL), WithAccessToken("access-token"))
	resp, err := client.GetDelegation(context.Background(), "del_abc123")
	if err != nil {
		t.Fatalf("GetDelegation error: %v", err)
	}
	if resp.DelegationID != "del_abc123" {
		t.Fatalf("expected del_abc123, got %q", resp.DelegationID)
	}
}

func TestListDelegations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("agent_id") != "agent_a" {
			http.Error(w, "missing agent_id", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(DelegationListResponse{
			Success:     true,
			Delegations: []DelegationListEntry{{DelegationID: "del_abc123"}},
			Count:       1,
		})
	}))
	defer server.Close()

	client := NewClient("app_123", "", WithBaseURL(server.URL), WithAccessToken("access-token"))
	resp, err := client.ListDelegations(context.Background(), ListDelegationOptions{AgentID: "agent_a"})
	if err != nil {
		t.Fatalf("ListDelegations error: %v", err)
	}
	if resp.Count != 1 || resp.Delegations[0].DelegationID != "del_abc123" {
		t.Fatalf("unexpected delegations: %+v", resp.Delegations)
	}
}

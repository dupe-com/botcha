package botcha

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIssueAttestation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/attestations" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer access-token" {
			http.Error(w, "missing auth", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(AttestationResponse{
			Success:       true,
			AttestationID: "att_abc123",
			AgentID:       "agent_abc123",
			Token:         "eyJattestation",
			Can:           []string{"read:invoices"},
		})
	}))
	defer server.Close()

	client := NewClient("app_123", "", WithBaseURL(server.URL), WithAccessToken("access-token"))
	resp, err := client.IssueAttestation(context.Background(), IssueAttestationInput{
		AgentID:         "agent_abc123",
		Can:             []string{"read:invoices"},
		DurationSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("IssueAttestation error: %v", err)
	}
	if resp.AttestationID != "att_abc123" {
		t.Fatalf("expected att_abc123, got %q", resp.AttestationID)
	}
	if resp.Token == "" {
		t.Fatal("expected non-empty token")
	}
}

func TestVerifyAttestation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/verify/attestation" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer access-token" {
			http.Error(w, "missing auth", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(AttestationVerifyResponse{
			Success: true,
			Valid:   true,
			Allowed: true,
		})
	}))
	defer server.Close()

	client := NewClient("app_123", "", WithBaseURL(server.URL), WithAccessToken("access-token"))
	resp, err := client.VerifyAttestation(context.Background(), "eyJattestation", "read", "invoices")
	if err != nil {
		t.Fatalf("VerifyAttestation error: %v", err)
	}
	if !resp.Allowed {
		t.Fatal("expected allowed=true")
	}
}

func TestRevokeAttestation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/attestations/att_abc123/revoke" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer access-token" {
			http.Error(w, "missing auth", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(RevokeAttestationResponse{
			Success:       true,
			AttestationID: "att_abc123",
			Revoked:       true,
			Message:       "attestation revoked",
		})
	}))
	defer server.Close()

	client := NewClient("app_123", "", WithBaseURL(server.URL), WithAccessToken("access-token"))
	resp, err := client.RevokeAttestation(context.Background(), "att_abc123", "no longer needed")
	if err != nil {
		t.Fatalf("RevokeAttestation error: %v", err)
	}
	if !resp.Revoked {
		t.Fatal("expected revoked=true")
	}
}

func TestListAttestations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("agent_id") != "agent_abc123" {
			http.Error(w, "missing agent_id", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(AttestationListResponse{
			Success:      true,
			Attestations: []AttestationListEntry{{AttestationID: "att_abc123"}},
			Count:        1,
		})
	}))
	defer server.Close()

	client := NewClient("app_123", "", WithBaseURL(server.URL), WithAccessToken("access-token"))
	resp, err := client.ListAttestations(context.Background(), "agent_abc123")
	if err != nil {
		t.Fatalf("ListAttestations error: %v", err)
	}
	if resp.Count != 1 || resp.Attestations[0].AttestationID != "att_abc123" {
		t.Fatalf("unexpected attestations: %+v", resp.Attestations)
	}
}

package botcha

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetReputation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/reputation/agent_abc123" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer access-token" {
			http.Error(w, "missing auth", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ReputationScoreResponse{
			Success: true,
			AgentID: "agent_abc123",
			Score:   750,
			Tier:    "good",
		})
	}))
	defer server.Close()

	client := NewClient("app_123", "", WithBaseURL(server.URL), WithAccessToken("access-token"))
	resp, err := client.GetReputation(context.Background(), "agent_abc123")
	if err != nil {
		t.Fatalf("GetReputation error: %v", err)
	}
	if resp.Score != 750 {
		t.Fatalf("expected score 750, got %v", resp.Score)
	}
	if resp.Tier != "good" {
		t.Fatalf("expected tier good, got %q", resp.Tier)
	}
}

func TestRecordReputationEvent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/reputation/events" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer access-token" {
			http.Error(w, "missing auth", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ReputationEventResponse{
			Success: true,
			Event: ReputationEvent{
				EventID:  "evt_abc123",
				AgentID:  "agent_abc123",
				Category: "verification",
				Action:   "challenge_solved",
				Delta:    10,
			},
		})
	}))
	defer server.Close()

	client := NewClient("app_123", "", WithBaseURL(server.URL), WithAccessToken("access-token"))
	resp, err := client.RecordReputationEvent(context.Background(), RecordReputationEventInput{
		AgentID:  "agent_abc123",
		Category: "verification",
		Action:   "challenge_solved",
	})
	if err != nil {
		t.Fatalf("RecordReputationEvent error: %v", err)
	}
	if resp.Event.EventID != "evt_abc123" {
		t.Fatalf("expected evt_abc123, got %q", resp.Event.EventID)
	}
}

func TestListReputationEvents(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/reputation/agent_abc123/events" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("category") != "verification" {
			http.Error(w, "missing category", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ReputationEventListResponse{
			Success: true,
			Events:  []ReputationEvent{{EventID: "evt_abc123", Category: "verification"}},
			Count:   1,
			AgentID: "agent_abc123",
		})
	}))
	defer server.Close()

	client := NewClient("app_123", "", WithBaseURL(server.URL), WithAccessToken("access-token"))
	resp, err := client.ListReputationEvents(context.Background(), "agent_abc123", &ListReputationEventsOptions{
		Category: "verification",
		Limit:    50,
	})
	if err != nil {
		t.Fatalf("ListReputationEvents error: %v", err)
	}
	if resp.Count != 1 || resp.Events[0].EventID != "evt_abc123" {
		t.Fatalf("unexpected events: %+v", resp.Events)
	}
}

func TestResetReputation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/reputation/agent_abc123/reset" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer access-token" {
			http.Error(w, "missing auth", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ReputationResetResponse{
			Success: true,
			AgentID: "agent_abc123",
			Score:   500,
			Tier:    "neutral",
			Message: "reputation reset",
		})
	}))
	defer server.Close()

	client := NewClient("app_123", "", WithBaseURL(server.URL), WithAccessToken("access-token"))
	resp, err := client.ResetReputation(context.Background(), "agent_abc123")
	if err != nil {
		t.Fatalf("ResetReputation error: %v", err)
	}
	if resp.Score != 500 {
		t.Fatalf("expected score 500, got %v", resp.Score)
	}
}

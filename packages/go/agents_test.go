package botcha

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegisterAgent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/agents" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var req RegisterAgentInput
		json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(AgentResponse{
			Success:  true,
			AgentID:  "agent_newid",
			AppID:    "app_test",
			Name:     req.Name,
			Operator: req.Operator,
		})
	}))
	defer server.Close()

	client := NewClient("app_test", "sk_test", WithBaseURL(server.URL))
	resp, err := client.RegisterAgent(context.Background(), RegisterAgentInput{
		Name:     "MyGoAgent",
		Operator: "acme",
		Version:  "1.0.0",
	})
	if err != nil {
		t.Fatalf("RegisterAgent error: %v", err)
	}
	if resp.AgentID != "agent_newid" {
		t.Errorf("expected agent_id 'agent_newid', got %q", resp.AgentID)
	}
	if resp.Name != "MyGoAgent" {
		t.Errorf("expected name 'MyGoAgent', got %q", resp.Name)
	}
}

func TestListAgents(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/agents" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(AgentListResponse{
			Success: true,
			Agents: []AgentResponse{
				{AgentID: "agent_1", Name: "Alpha"},
				{AgentID: "agent_2", Name: "Beta"},
			},
			Count: 2,
		})
	}))
	defer server.Close()

	client := NewClient("app_test", "sk_test", WithBaseURL(server.URL))
	resp, err := client.ListAgents(context.Background())
	if err != nil {
		t.Fatalf("ListAgents error: %v", err)
	}
	if resp.Count != 2 {
		t.Errorf("expected count 2, got %d", resp.Count)
	}
}

func TestGetAgent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/agents/agent_xyz" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(AgentResponse{
			Success: true,
			AgentID: "agent_xyz",
			Name:    "XYZ Agent",
		})
	}))
	defer server.Close()

	client := NewClient("app_test", "sk_test", WithBaseURL(server.URL))
	resp, err := client.GetAgent(context.Background(), "agent_xyz")
	if err != nil {
		t.Fatalf("GetAgent error: %v", err)
	}
	if resp.AgentID != "agent_xyz" {
		t.Errorf("expected 'agent_xyz', got %q", resp.AgentID)
	}
}

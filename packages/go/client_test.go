package botcha

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewClient_defaults(t *testing.T) {
	c := NewClient("app_id", "sk_secret")
	if c.baseURL != defaultBaseURL {
		t.Errorf("expected default baseURL %q, got %q", defaultBaseURL, c.baseURL)
	}
	if c.appID != "app_id" {
		t.Errorf("expected appID 'app_id', got %q", c.appID)
	}
	if c.appSecret != "sk_secret" {
		t.Errorf("expected appSecret 'sk_secret', got %q", c.appSecret)
	}
}

func TestNewClient_withOptions(t *testing.T) {
	custom := &http.Client{Timeout: 5 * time.Second}
	c := NewClient("app", "sk",
		WithBaseURL("https://custom.botcha.ai"),
		WithHTTPClient(custom),
		WithAgentIdentity("myagent/2.0"),
	)
	if c.baseURL != "https://custom.botcha.ai" {
		t.Errorf("expected custom baseURL, got %q", c.baseURL)
	}
	if c.agentIdentity != "myagent/2.0" {
		t.Errorf("expected 'myagent/2.0', got %q", c.agentIdentity)
	}
	if c.http != custom {
		t.Error("expected custom http client")
	}
}

func TestDo_apiError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(BotchaError{
			Code:    "unauthorized",
			Message: "invalid credentials",
		})
	}))
	defer server.Close()

	c := NewClient("bad", "creds", WithBaseURL(server.URL))
	var result map[string]any
	err := c.get(context.Background(), "/v1/test", &result)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	botchaErr, ok := err.(*BotchaError)
	if !ok {
		t.Fatalf("expected *BotchaError, got %T: %v", err, err)
	}
	if botchaErr.Status != 401 {
		t.Errorf("expected status 401, got %d", botchaErr.Status)
	}
	if botchaErr.Code != "unauthorized" {
		t.Errorf("expected code 'unauthorized', got %q", botchaErr.Code)
	}
}

func TestBotchaError_Error(t *testing.T) {
	err := &BotchaError{Code: "not_found", Message: "resource not found", Status: 404}
	expected := "[not_found] resource not found"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}

	errNoCode := &BotchaError{Message: "something went wrong"}
	if errNoCode.Error() != "something went wrong" {
		t.Errorf("expected plain message, got %q", errNoCode.Error())
	}
}

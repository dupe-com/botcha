package botcha

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerifyEmailUsesAppScopedPathAndSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/apps/app_123/verify-email" {
			http.NotFound(w, r)
			return
		}
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["code"] != "123456" {
			http.Error(w, "missing code", 400)
			return
		}
		if req["app_secret"] != "sk_abc" {
			http.Error(w, "missing app_secret", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(VerifyEmailResponse{Success: true, EmailVerified: true})
	}))
	defer server.Close()

	client := NewClient("app_123", "sk_abc", WithBaseURL(server.URL))
	resp, err := client.VerifyEmail(context.Background(), "123456")
	if err != nil {
		t.Fatalf("VerifyEmail error: %v", err)
	}
	if !resp.EmailVerified {
		t.Fatal("expected email_verified=true")
	}
}

func TestResendVerificationUsesAppScopedPathAndSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/apps/app_123/resend-verification" {
			http.NotFound(w, r)
			return
		}
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["app_secret"] != "sk_abc" {
			http.Error(w, "missing app_secret", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ResendVerificationResponse{Success: true})
	}))
	defer server.Close()

	client := NewClient("app_123", "sk_abc", WithBaseURL(server.URL))
	resp, err := client.ResendVerification(context.Background())
	if err != nil {
		t.Fatalf("ResendVerification error: %v", err)
	}
	if !resp.Success {
		t.Fatal("expected success=true")
	}
}

func TestRotateSecretUsesAppScopedPathAndBearerToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/apps/app_123/rotate-secret" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer dashboard-session-token" {
			http.Error(w, "missing auth", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(RotateSecretResponse{
			Success:   true,
			AppID:     "app_123",
			AppSecret: "sk_new",
		})
	}))
	defer server.Close()

	client := NewClient("app_123", "sk_abc", WithBaseURL(server.URL), WithAccessToken("dashboard-session-token"))
	resp, err := client.RotateSecret(context.Background())
	if err != nil {
		t.Fatalf("RotateSecret error: %v", err)
	}
	if resp.AppSecret != "sk_new" {
		t.Fatalf("expected rotated secret, got %q", resp.AppSecret)
	}
}

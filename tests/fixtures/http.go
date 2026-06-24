package fixtures

import (
	"net/http"
	"testing"
)

const defaultBaseURL = "http://localhost:4001"

// AuthRequest creates an HTTP request with a Bearer token set.
func AuthRequest(t *testing.T, method, path, token string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, defaultBaseURL+path, nil)
	if err != nil {
		t.Fatalf("AuthRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	return req
}

// APIKeyRequest creates an HTTP request with an X-API-Key header.
func APIKeyRequest(t *testing.T, method, path, apiKey string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, defaultBaseURL+path, nil)
	if err != nil {
		t.Fatalf("APIKeyRequest: %v", err)
	}
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	return req
}

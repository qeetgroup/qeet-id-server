package security_test

import (
	"net/http"
	"testing"
)

const baseURL = "http://localhost:4001"

func TestSecurityHeaders(t *testing.T) {
	tests := []struct {
		header string
		want   string
	}{
		{"X-Content-Type-Options", "nosniff"},
		{"X-Frame-Options", "DENY"},
		{"Referrer-Policy", "strict-origin-when-cross-origin"},
	}

	resp, err := http.Get(baseURL + "/healthz")
	if err != nil {
		t.Skipf("backend not reachable: %v", err)
	}
	defer resp.Body.Close()

	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			got := resp.Header.Get(tt.header)
			if got != tt.want {
				t.Errorf("%s = %q; want %q", tt.header, got, tt.want)
			}
		})
	}
}

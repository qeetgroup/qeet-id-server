package audit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestActorOf checks who a request's audit events name: the system with no
// principal, a user for a principal naming no type, and otherwise its type.
func TestActorOf(t *testing.T) {
	userID := uuid.New()
	for _, c := range []struct {
		name      string
		principal *httpx.Principal
		wantType  string
		wantUser  *uuid.UUID
	}{
		{"no principal", nil, "system", nil},
		{"a principal naming no type", &httpx.Principal{UserID: &userID}, "user", &userID},
		{"an API key", &httpx.Principal{ActorType: "api_key"}, "api_key", nil},
	} {
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.Header.Set("User-Agent", "test-agent")
		if c.principal != nil {
			r = r.WithContext(httpx.WithPrincipal(r.Context(), c.principal))
		}
		a := ActorOf(r)
		if a.Type != c.wantType || a.UserID != c.wantUser || a.UserAgent != "test-agent" {
			t.Errorf("%s: %+v, want type %q and user %v", c.name, a, c.wantType, c.wantUser)
		}
	}
}

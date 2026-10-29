package idempotency

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestSealedAsReadsTheScope checks that the tenant a stored answer is sealed
// under can be read back from its scope alone, as re-encryption must: the
// caller's organisation, or the stand-in for a caller with none.
func TestSealedAsReadsTheScope(t *testing.T) {
	tenant, user := uuid.New(), uuid.New()
	for _, tc := range []struct {
		principal *httpx.Principal
		want      uuid.UUID
	}{
		{nil, platformScope},
		{&httpx.Principal{ActorType: "user", Subject: user.String(), UserID: &user}, platformScope},
		{&httpx.Principal{ActorType: "user", Subject: user.String(), UserID: &user, TenantID: &tenant}, tenant},
		{&httpx.Principal{ActorType: "api_key", Subject: "key|with|bars", TenantID: &tenant}, tenant},
	} {
		r := httptest.NewRequest(http.MethodPost, "/v1/things", nil)
		if tc.principal != nil {
			r = r.WithContext(httpx.WithPrincipal(r.Context(), tc.principal))
		}
		scope, sealAs := scopeOf(r)
		if sealAs != tc.want || SealedAs(scope) != tc.want {
			t.Errorf("scope %q: sealed as %s, SealedAs %s; want %s", scope, sealAs, SealedAs(scope), tc.want)
		}
	}
}

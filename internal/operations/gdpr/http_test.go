package gdpr

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestDeleteSelfRefusesAMalformedBody checks that a body which isn't valid JSON is refused before the
// password is checked (the handler has no password checker here), not read as "no password".
func TestDeleteSelfRefusesAMalformedBody(t *testing.T) {
	userID := uuid.New()
	for _, body := range []string{`{not json`, `{"password": 1}`, `{"unknown": "x"}`} {
		r := httptest.NewRequest(http.MethodPost, "/v1/account/delete", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r = r.WithContext(httpx.WithPrincipal(r.Context(), &httpx.Principal{UserID: &userID}))
		w := httptest.NewRecorder()
		(&Handler{}).deleteSelf(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s, want 400", body, w.Code, w.Body.String())
		}
	}
}

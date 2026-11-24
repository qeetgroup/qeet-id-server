package activity

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestListFilterRefusesWhatItCannotParse checks that a malformed actor, subject, from or to is
// refused, not dropped: dropping it would answer unfiltered events as if they matched.
func TestListFilterRefusesWhatItCannotParse(t *testing.T) {
	for _, query := range []string{"actor=nope", "subject=nope", "from=yesterday", "to=2026-13-45", "to=2026-11-18"} {
		if _, err := parseListFilter(httptest.NewRequest(http.MethodGet, "/?"+query, nil)); err == nil {
			t.Errorf("%s accepted, want 400", query)
		}
	}
	actor := uuid.New()
	f, err := parseListFilter(httptest.NewRequest(http.MethodGet, "/?actor="+actor.String()+"&from=2026-11-01T00:00:00Z&to=2026-11-18T10:00:00Z", nil))
	if err != nil || f.ActorID != actor || f.From == nil || !f.From.Equal(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)) || f.To == nil {
		t.Fatalf("filter %+v, %v; want the actor and both times", f, err)
	}
}

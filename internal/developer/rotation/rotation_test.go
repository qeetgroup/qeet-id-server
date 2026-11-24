package rotation

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

var errNotYours = errors.New("not yours")

// TestRequestChecksTheCredentialsScopes checks that a rotation goes ahead only
// when the check passes the credential's own scopes, and that without a check
// no caller rotates anything.
func TestRequestChecksTheCredentialsScopes(t *testing.T) {
	organization, id := uuid.New(), uuid.New()
	scopes := func(_ context.Context, o, i uuid.UUID) ([]string, error) {
		if o != organization || i != id {
			t.Errorf("scopes read for %s/%s, want %s/%s", o, i, organization, id)
		}
		return []string{"user.read", "role.write"}, nil
	}
	var checked []string
	allow := func(_ context.Context, _ *httpx.Principal, _ uuid.UUID, s []string) error { checked = s; return nil }
	refuse := func(context.Context, *httpx.Principal, uuid.UUID, []string) error { return errNotYours }

	if overlap, err := Request(post(""), organization, id, scopes, allow); err != nil || overlap != DefaultOverlap {
		t.Errorf("no body: %s, %v; want the default overlap", overlap, err)
	}
	if !slices.Equal(checked, []string{"user.read", "role.write"}) {
		t.Errorf("checked %v, want the credential's scopes", checked)
	}
	if overlap, err := Request(post(`{"overlap_hours": 2}`), organization, id, scopes, allow); err != nil || overlap != 2*time.Hour {
		t.Errorf("2 hours: %s, %v", overlap, err)
	}
	if _, err := Request(post(""), organization, id, scopes, refuse); !errors.Is(err, errNotYours) {
		t.Errorf("a refused caller: %v, want the check's refusal", err)
	}
	if _, err := Request(post(""), organization, id, scopes, nil); !errors.Is(err, errs.ErrNotImplemented) {
		t.Errorf("no check: %v, want ErrNotImplemented", err)
	}
	missing := func(context.Context, uuid.UUID, uuid.UUID) ([]string, error) { return nil, errs.ErrAPIKeyNotFound }
	if _, err := Request(post(""), organization, id, missing, allow); !errors.Is(err, errs.ErrAPIKeyNotFound) {
		t.Errorf("an unknown credential: %v, want its not-found error", err)
	}
}

// TestCheckOverlap checks the overlap's bounds.
func TestCheckOverlap(t *testing.T) {
	for overlap, ok := range map[time.Duration]bool{0: true, MaxOverlap: true, -time.Second: false, MaxOverlap + time.Second: false} {
		if err := CheckOverlap(overlap, "key"); (err == nil) != ok {
			t.Errorf("CheckOverlap(%s) = %v, want ok %v", overlap, err, ok)
		}
	}
}

// TestPreviousSecretWorks checks that a replaced secret works only until its
// overlap ends.
func TestPreviousSecretWorks(t *testing.T) {
	hash := password.HashSecret("old")
	later := new(time.Now().Add(time.Hour))
	earlier := new(time.Now().Add(-time.Second))
	for _, c := range []struct {
		name   string
		hash   *string
		until  *time.Time
		secret string
		want   bool
	}{
		{"within the overlap", &hash, later, "old", true},
		{"another secret", &hash, later, "other", false},
		{"after the overlap", &hash, earlier, "old", false},
		{"no overlap", &hash, nil, "old", false},
		{"no previous secret", nil, later, "old", false},
	} {
		if ok := PreviousSecretWorks(c.hash, c.until, c.secret); ok != c.want {
			t.Errorf("%s: %v; want %v", c.name, ok, c.want)
		}
	}
}

// post is a rotation request with body.
func post(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/rotate", strings.NewReader(body))
	if body == "" {
		r.ContentLength = 0
	}
	return r
}

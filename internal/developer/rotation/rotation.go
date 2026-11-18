// Package rotation holds what rotating a machine credential (an API key, or
// the secret of a service principal or agent) works the same way for: the
// request, the check that the caller may hold the credential's scopes, and the
// overlap during which the replaced secret goes on working.
package rotation

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// How long a replaced credential goes on working beside its replacement.
const (
	DefaultOverlap = 24 * time.Hour     // when the request names none
	MaxOverlap     = 7 * 24 * time.Hour // the longest a request may ask for
)

// GrantCheck refuses a credential carrying a scope the caller doesn't hold.
type GrantCheck func(ctx context.Context, caller *httpx.Principal, organizationID uuid.UUID, scopes []string) error

// ScopesOf reads the scopes of credential id of organizationID, or its
// not-found error.
type ScopesOf func(ctx context.Context, organizationID, id uuid.UUID) ([]string, error)

// Request reads a request to rotate credential id of organizationID and returns its overlap
// (overlap_hours, DefaultOverlap when absent). The new credential keeps the old one's scopes, so the
// caller must hold them: check refuses otherwise, and with no check every caller is refused.
func Request(r *http.Request, organizationID, id uuid.UUID, scopes ScopesOf, check GrantCheck) (time.Duration, error) {
	var in struct {
		OverlapHours *int `json:"overlap_hours"`
	}
	if r.ContentLength != 0 {
		if err := httpx.DecodeJSON(r, &in); err != nil {
			return 0, err
		}
	}
	if check == nil {
		return 0, errs.ErrNotImplemented
	}
	held, err := scopes(r.Context(), organizationID, id)
	if err != nil {
		return 0, err
	}
	if err := check(r.Context(), httpx.PrincipalFromCtx(r.Context()), organizationID, held); err != nil {
		return 0, err
	}
	if in.OverlapHours == nil {
		return DefaultOverlap, nil
	}
	return time.Duration(*in.OverlapHours) * time.Hour, nil
}

// CheckOverlap refuses an overlap outside 0..MaxOverlap; what names the
// credential in the message ("key", "secret").
func CheckOverlap(overlap time.Duration, what string) error {
	if overlap < 0 || overlap > MaxOverlap {
		return errs.ErrValidationFailed.WithFields([]errs.FieldError{{
			Field: "overlap_hours", Code: "out_of_range", Message: fmt.Sprintf("Keep the old %s working for 0 to 168 hours.", what),
		}})
	}
	return nil
}

// PreviousSecretWorks reports whether secret is the one replaced at the last
// rotation, stored as hash, and its overlap (until) hasn't ended.
func PreviousSecretWorks(hash *string, until *time.Time, secret string) bool {
	return hash != nil && until != nil && until.After(time.Now()) && password.VerifySecret(*hash, secret)
}

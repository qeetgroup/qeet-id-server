package oidc

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// pkceExemptionMax is the furthest ahead an application's PKCE exemption may
// end: long enough to update an integration, short enough not to become the
// way it stays.
const pkceExemptionMax = 90 * 24 * time.Hour

// maxNonceLength bounds the nonce stored with a code and echoed into the ID
// token.
const maxNonceLength = 255

// validateSignInRequest enforces the OAuth 2.1 (RFC 9700) rules on an
// authorization request: an S256 PKCE challenge, and a nonce whenever openid is
// requested. A confidential client's active PKCE exemption waives both; values
// that are sent are always checked.
func validateSignInRequest(clientType string, exempt bool, scopes []string, nonce, challenge, method string) error {
	waived := exempt && clientType == "confidential"
	if challenge == "" {
		if method != "" {
			return errs.ErrOIDCCodeChallengeInvalid
		}
		if !waived {
			return errs.ErrOIDCCodeChallengeRequired
		}
	} else {
		if method != "S256" {
			return errs.ErrOIDCCodeChallengeMethodUnsupported
		}
		if !validPKCEValue(challenge, 43, 43) {
			return errs.ErrOIDCCodeChallengeInvalid
		}
	}
	if len(nonce) > maxNonceLength {
		return errs.ErrOIDCNonceInvalid
	}
	if nonce == "" && contains(scopes, "openid") && !waived {
		return errs.ErrOIDCNonceRequired
	}
	return nil
}

// validPKCEExemption checks an exemption an admin sets: a confidential
// application, ending after now and no more than pkceExemptionMax from now.
// nil clears it and is always valid.
func validPKCEExemption(clientType string, until *time.Time, now time.Time) error {
	if until == nil {
		return nil
	}
	if clientType != "confidential" || !until.After(now) || until.After(now.Add(pkceExemptionMax)) {
		return errs.ErrOIDCPKCEExemptionInvalid
	}
	return nil
}

// OptionalTime is a PATCH field that tells "left out" (Set false: unchanged)
// from null (Set, At nil: cleared) and a time (Set, At: that time).
type OptionalTime struct {
	Set bool
	At  *time.Time
}

// UnmarshalJSON implements json.Unmarshaler.
func (o *OptionalTime) UnmarshalJSON(b []byte) error {
	o.Set = true
	if string(b) == "null" {
		o.At = nil
		return nil
	}
	var t time.Time
	if err := json.Unmarshal(b, &t); err != nil {
		return err
	}
	o.At = &t
	return nil
}

// timePtr is a nullable timestamp as the API reports it (nil for NULL).
func timePtr(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time
	return &v
}

// pgTime is a nullable timestamp for a query (NULL for nil).
func pgTime(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: *t, Valid: true}
}

// optionalTime is a nullable timestamp for a query (NULL for the zero time).
func optionalTime(t time.Time) pgtype.Timestamptz {
	if t.IsZero() {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: t, Valid: true}
}

// timeOrZero is a nullable timestamp as a time (zero for NULL).
func timeOrZero(t pgtype.Timestamptz) time.Time {
	if !t.Valid {
		return time.Time{}
	}
	return t.Time
}

// uuidOrNil is a nullable UUID as a uuid (uuid.Nil for NULL).
func uuidOrNil(u pgtype.UUID) uuid.UUID {
	if !u.Valid {
		return uuid.Nil
	}
	return uuid.UUID(u.Bytes)
}

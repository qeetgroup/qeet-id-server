package oidc

import (
	"encoding/json"
	"time"
)

// pkceExemptionMax is the furthest ahead an application's PKCE exemption may
// end: long enough to update an integration, short enough not to become the
// way it stays.
const pkceExemptionMax = 90 * 24 * time.Hour

// maxNonceLength bounds the nonce stored with a code and echoed into the ID
// token.
const maxNonceLength = 255

// validateSignInRequest enforces the OAuth 2.1 (RFC 9700) rules on an authorization request: an S256
// PKCE challenge, which binds the code to the request, so a nonce is optional (OIDC Core 3.1.2.1). A
// confidential client's active PKCE exemption waives the challenge; values sent are always checked.
func validateSignInRequest(clientType string, exempt bool, nonce, challenge, method string) error {
	waived := exempt && clientType == "confidential"
	if challenge == "" {
		if method != "" {
			return ErrCodeChallengeInvalid
		}
		if !waived {
			return ErrCodeChallengeRequired
		}
	} else {
		if method != "S256" {
			return ErrCodeChallengeMethodUnsupported
		}
		if !validPKCEValue(challenge, 43, 43) {
			return ErrCodeChallengeInvalid
		}
	}
	if len(nonce) > maxNonceLength {
		return ErrNonceInvalid
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
		return ErrPKCEExemptionInvalid
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

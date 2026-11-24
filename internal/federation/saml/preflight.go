package saml

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
)

// TestCheck is one preflight check in a connection test.
type TestCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// TestResult is the outcome of a SAML connection preflight: OK only when every
// check passed.
type TestResult struct {
	OK     bool        `json:"ok"`
	Checks []TestCheck `json:"checks"`
}

// TestConnection runs an offline preflight over a SAML connection's config so an
// admin can catch the common misconfigurations (missing entity ID, a non-https
// SSO URL, an unparseable or expired signing certificate, no email mapping)
// before turning the connection on for real logins. It performs no network I/O.
func (s *Service) TestConnection(ctx context.Context, id, organizationID uuid.UUID) (*TestResult, error) {
	c, err := s.Get(ctx, id, organizationID)
	if err != nil {
		return nil, err
	}
	res := &TestResult{OK: true}
	add := func(name string, ok bool, detail string) {
		res.Checks = append(res.Checks, TestCheck{Name: name, OK: ok, Detail: detail})
		if !ok {
			res.OK = false
		}
	}

	add("IdP entity ID", strings.TrimSpace(c.IdpEntityID) != "", "The IdP's entity ID (issuer) must be set.")
	add("IdP SSO URL", validIdPSSOURL(strings.TrimSpace(c.IdpSSOURL)), "Must be an absolute https:// URL.")

	parsed := len(c.Certificates) > 0
	for _, cert := range c.Certificates {
		parsed = parsed && cert.NotAfter != nil
	}
	add("Signing certificate", parsed, "Each must be a valid PEM block or base64-encoded DER certificate.")
	if parsed {
		// Valid while any certificate is; report the furthest expiry.
		now := time.Now()
		var valid bool
		var until, latest time.Time
		for _, cert := range c.Certificates {
			if now.After(*cert.NotBefore) && now.Before(*cert.NotAfter) {
				valid = true
				until = later(until, *cert.NotAfter)
			}
			latest = later(latest, *cert.NotAfter)
		}
		detail := "Valid until " + until.Format("2006-01-02") + "."
		if !valid {
			detail = "Certificate is expired or not yet valid (expires " + latest.Format("2006-01-02") + ")."
		}
		add("Certificate validity period", valid, detail)
	}

	add("Email attribute mapping", strings.TrimSpace(c.EmailAttribute) != "", "Needed to resolve each user's email from the SAML assertion.")

	return res, nil
}

// later returns whichever of a and b is later.
func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

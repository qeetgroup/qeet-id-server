package social

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/logincode"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// loginCodeRefusals are the errors an organization's social login code is
// refused with: one of a provider since switched off reads as not set up.
var loginCodeRefusals = logincode.Refusals{
	Required: ErrCodeRequired,
	Invalid:  ErrLoginCodeInvalid,
	Used:     ErrLoginCodeUsed,
	Expired:  ErrLoginCodeExpired,
	Disabled: ErrProviderNotConfigured,
}

// ExchangeLogin trades a one-time social login code for a Qeet token pair, or
// the second-factor challenge to complete first, while the provider that
// issued it is still on: a code of one since switched off or deleted is refused.
func (s *Service) ExchangeLogin(ctx context.Context, rawCode, ip, ua string) (*authentication.LoginResult, error) {
	code, err := logincode.Consume(ctx, s.pool, logincode.KindSocial, rawCode, loginCodeRefusals)
	if err != nil {
		return nil, err
	}
	return s.auth.BeginSocialSignIn(ctx, code.UserID, code.OrganizationID, ip, ua)
}

type exchangeInput struct {
	Code string `json:"code"`
}

// challengeFragment encodes a hosted social sign-in's second-factor challenge
// for the hosted login's URL fragment: mfa_token, methods, factors (JSON, as a
// password sign-in lists them) and, for an enrolment, enrollment_required and
// enrollment_due_at.
func challengeFragment(c authentication.MFAChallenge) string {
	v := url.Values{"mfa_token": {c.MFAToken}, "methods": {strings.Join(c.Methods, ",")}}
	if len(c.Factors) > 0 {
		if factors, err := json.Marshal(c.Factors); err == nil {
			v.Set("factors", string(factors))
		}
	}
	if c.EnrollmentRequired {
		v.Set("enrollment_required", "true")
		if c.EnrollmentDueAt != nil {
			v.Set("enrollment_due_at", c.EnrollmentDueAt.UTC().Format(time.RFC3339))
		}
	}
	return v.Encode()
}

// writeSignIn answers a social code exchange: the token pair, or the
// second-factor challenge shaped as a password sign-in's, met at /v1/auth/mfa.
func writeSignIn(w http.ResponseWriter, res *authentication.LoginResult) {
	if res.MFARequired {
		httpx.WriteJSON(w, http.StatusOK, res.Body())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res.Pair)
}

// exchange trades a one-time social login code for a token pair.
func (h *Handler) exchange(w http.ResponseWriter, r *http.Request) {
	var in exchangeInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Platform (organization-less) code first; fall back to the organization exchange when
	// the code isn't a platform one.
	if res, perr := h.Service.ExchangePlatformLogin(r.Context(), in.Code, httpx.ClientIP(r), r.UserAgent()); perr == nil {
		writeSignIn(w, res)
		return
	} else if !errors.Is(perr, ErrLoginCodeInvalid) {
		httpx.WriteError(w, r, perr)
		return
	}
	res, err := h.Service.ExchangeLogin(r.Context(), in.Code, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	writeSignIn(w, res)
}

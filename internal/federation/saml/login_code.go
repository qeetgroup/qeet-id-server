package saml

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/federation/logincode"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// ExchangeLogin trades a one-time SAML login code for a Qeet token pair, while
// the connection that issued it is still active.
func (s *Service) ExchangeLogin(ctx context.Context, rawCode, ip, ua string) (*auth.TokenPair, error) {
	code, err := s.consumeLoginCode(ctx, rawCode)
	if err != nil {
		return nil, err
	}
	return s.auth.IssuePair(ctx, code.UserID, code.OrganizationID, ip, ua, provider)
}

// loginCodeRefusals are the errors a SAML login code is refused with.
var loginCodeRefusals = logincode.Refusals{
	Required: ErrLoginCodeRequired,
	Invalid:  ErrLoginCodeInvalid,
	Used:     ErrLoginCodeUsed,
	Expired:  ErrLoginCodeExpired,
	Draft:    ErrConnectionDraft,
	Disabled: ErrConnectionDisabled,
}

// consumeLoginCode spends a one-time code the ACS issued, once, and returns
// whom it signs in. A code of a connection since disabled, put back to draft
// or deleted is refused.
func (s *Service) consumeLoginCode(ctx context.Context, rawCode string) (logincode.Code, error) {
	return logincode.Consume(ctx, s.pool, logincode.KindSAML, rawCode, loginCodeRefusals)
}

// touchLastLogin stamps last_login_at on the SP connection after a successful
// ACS assertion. Fire-and-forget.
func (s *Service) touchLastLogin(ctx context.Context, connID uuid.UUID) {
	_ = s.q.TouchSamlLastLogin(ctx, connID)
}

// session trades a sign-in the hosted login started for the hosted login session: the one-time
// code from the identity provider's answer, then the organization's address rules. It answers as
// POST /v1/auth/session does, with the session cookie and the user's id.
func (h *Handler) session(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	code, err := h.Service.consumeLoginCode(r.Context(), body.Code)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	raw, err := h.Service.auth.BeginSSOLoginSession(r.Context(), code.UserID, code.OrganizationID, provider, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	auth.SetLoginSessionCookie(w, raw, h.CookieSecure)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"user_id": code.UserID})
}

func (h *Handler) exchange(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	pair, err := h.Service.ExchangeLogin(r.Context(), body.Code, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, pair)
}

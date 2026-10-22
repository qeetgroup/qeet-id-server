package oidc

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// userinfoClaims is every claim userinfo and the ID token can carry beyond
// sub, by the scope that grants it, as discovery advertises (claims_supported).
var userinfoClaims = map[string][]string{
	"email":   {"email", "email_verified"},
	"profile": {"name", "picture", "locale", "updated_at"},
	"phone":   {"phone_number", "phone_number_verified"},
}

// claimsSupported is discovery's claims_supported list.
func claimsSupported() []string {
	out := []string{"sub", "iss", "aud", "exp", "iat", "nonce", "tenant_id"}
	for _, scope := range []string{"profile", "email", "phone"} {
		out = append(out, userinfoClaims[scope]...)
	}
	return out
}

// errAccountGone: the account a token names is deleted or suspended.
var errAccountGone = errors.New("account no longer active")

// userClaims returns the OpenID Connect standard claims the scopes grant
// about a live account: email → email, email_verified; profile → name,
// picture, locale, updated_at (where known); phone → phone_number,
// phone_number_verified. Nothing else is ever returned.
func (s *Service) userClaims(ctx context.Context, userID uuid.UUID, scopes []string) (map[string]any, error) {
	u, err := s.q.GetUserinfo(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errAccountGone
	}
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if slices.Contains(scopes, "email") {
		out["email"] = u.Email
		out["email_verified"] = u.EmailVerifiedAt.Valid
	}
	if slices.Contains(scopes, "profile") {
		if u.DisplayName != nil && *u.DisplayName != "" {
			out["name"] = *u.DisplayName
		}
		if u.AvatarUrl != nil && *u.AvatarUrl != "" {
			out["picture"] = *u.AvatarUrl
		}
		if u.Locale != "" {
			out["locale"] = u.Locale
		}
		out["updated_at"] = u.UpdatedAt.Unix()
	}
	if slices.Contains(scopes, "phone") && u.Phone != nil && *u.Phone != "" {
		out["phone_number"] = *u.Phone
		out["phone_number_verified"] = u.PhoneVerifiedAt.Valid
	}
	return out, nil
}

// bearerChallenge sets the RFC 6750 WWW-Authenticate challenge.
func bearerChallenge(w http.ResponseWriter, code string) {
	v := `Bearer realm="qeet"`
	if code != "" {
		v += `, error="` + code + `"`
	}
	if code == "insufficient_scope" {
		v += `, scope="openid"`
	}
	w.Header().Set("WWW-Authenticate", v)
}

// userinfo handles GET and POST /v1/oauth/userinfo, returning sub, the tenant
// and the standard claims the token's scopes grant. A token without openid gets
// 403 insufficient_scope; a suspended or deleted account gets 401 invalid_token.
func (h *Handler) userinfo(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		bearerChallenge(w, "invalid_token")
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	if !slices.Contains(p.Scopes, "openid") {
		bearerChallenge(w, "insufficient_scope")
		httpx.WriteError(w, r, errs.ErrOIDCInsufficientScope)
		return
	}
	claims, err := h.Service.userClaims(r.Context(), *p.UserID, p.Scopes)
	if errors.Is(err, errAccountGone) {
		bearerChallenge(w, "invalid_token")
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	claims["sub"] = p.UserID
	if p.TenantID != nil {
		claims["tenant_id"] = p.TenantID
	}
	httpx.WriteJSON(w, http.StatusOK, claims)
}

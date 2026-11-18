package adminportal

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/adminportal/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Exchange atomically consumes a one-time link token and creates a separately
// hashed, short-lived portal session. Concurrent redemption has one winner.
func (s *Service) Exchange(ctx context.Context, rawToken string) (*Link, string, time.Time, error) {
	if rawToken == "" {
		return nil, "", time.Time{}, ErrTokenMissing
	}
	hash := codes.Hash(rawToken)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	row, err := q.LockAdminPortalLinkByHash(ctx, hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", time.Time{}, ErrLinkInvalid
	}
	if err != nil {
		return nil, "", time.Time{}, err
	}
	l := &Link{
		ID:             row.ID,
		OrganizationID: row.OrganizationID,
		Capabilities:   row.Capabilities,
		CreatedBy:      row.CreatedBy,
		ExpiresAt:      row.ExpiresAt,
		RevokedAt:      row.RevokedAt,
		LastUsedAt:     row.LastUsedAt,
		CreatedAt:      row.CreatedAt,
	}
	if l.RevokedAt != nil {
		return nil, "", time.Time{}, ErrLinkRevoked
	}
	if time.Now().After(l.ExpiresAt) {
		return nil, "", time.Time{}, ErrLinkExpired
	}
	if row.RedeemedAt != nil {
		return nil, "", time.Time{}, ErrLinkInvalid
	}
	rawSession, sessionHash, err := codes.URLToken()
	if err != nil {
		return nil, "", time.Time{}, err
	}
	sessionExpires := time.Now().UTC().Add(portalSessionTTL)
	if l.ExpiresAt.Before(sessionExpires) {
		sessionExpires = l.ExpiresAt
	}
	if err := q.InsertAdminPortalSession(ctx, dbgen.InsertAdminPortalSessionParams{LinkID: l.ID, TokenHash: sessionHash, ExpiresAt: sessionExpires}); err != nil {
		return nil, "", time.Time{}, err
	}
	if err := q.MarkAdminPortalLinkRedeemed(ctx, dbgen.MarkAdminPortalLinkRedeemedParams{ID: l.ID, OrganizationID: l.OrganizationID}); err != nil {
		return nil, "", time.Time{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, "", time.Time{}, err
	}
	l.ExpiresAt = sessionExpires
	return l, rawSession, sessionExpires, nil
}

// ResolveSession validates a portal session and its parent link on every
// request so expiry or administrator revocation takes effect immediately.
func (s *Service) ResolveSession(ctx context.Context, rawSession string) (*Link, error) {
	if rawSession == "" {
		return nil, ErrSessionMissing
	}
	r, err := s.q.GetAdminPortalSessionByHash(ctx, codes.Hash(rawSession))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSessionInvalid
	}
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if r.SessionRevokedAt != nil || r.RevokedAt != nil {
		return nil, ErrSessionInvalid
	}
	if now.After(r.SessionExpiresAt) || now.After(r.ExpiresAt) {
		return nil, ErrSessionInvalid
	}
	_ = s.q.TouchAdminPortalSession(ctx, r.SessionID)
	return &Link{
		ID: r.ID, OrganizationID: r.OrganizationID, Capabilities: r.Capabilities, CreatedBy: r.CreatedBy,
		ExpiresAt: r.SessionExpiresAt, RevokedAt: r.RevokedAt, LastUsedAt: r.LastUsedAt, CreatedAt: r.CreatedAt,
	}, nil
}

// RevokeSession ends the portal session the raw cookie value names.
func (s *Service) RevokeSession(ctx context.Context, rawSession string) error {
	if rawSession == "" {
		return ErrSessionMissing
	}
	n, err := s.q.RevokeAdminPortalSession(ctx, codes.Hash(rawSession))
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrSessionInvalid
	}
	return nil
}

// resolve authenticates the short-lived portal session cookie and enforces the
// capability required by the requested operation.
func (h *Handler) resolve(r *http.Request, capability string) (*Link, error) {
	cookie, err := r.Cookie(portalSessionCookie)
	if err != nil || cookie.Value == "" {
		return nil, ErrSessionMissing
	}
	l, err := h.Service.ResolveSession(r.Context(), cookie.Value)
	if err != nil {
		return nil, err
	}
	if capability != "" && !l.Has(capability) {
		return nil, ErrCapabilityNotGranted
	}
	return l, nil
}

func bearerCredential(r *http.Request) string {
	const prefix = "Bearer "
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
}

func (h *Handler) setSessionCookie(w http.ResponseWriter, raw string, expiresAt time.Time) {
	maxAge := int(time.Until(expiresAt).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure is off only in dev
		Name: portalSessionCookie, Value: raw, Path: portalCookiePath,
		Expires: expiresAt, MaxAge: maxAge, HttpOnly: true,
		Secure: h.CookieSecure, SameSite: http.SameSiteStrictMode,
	})
}

func (h *Handler) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure is off only in dev
		Name: portalSessionCookie, Path: portalCookiePath,
		Expires: time.Unix(1, 0), MaxAge: -1, HttpOnly: true,
		Secure: h.CookieSecure, SameSite: http.SameSiteStrictMode,
	})
}

func (h *Handler) exchange(w http.ResponseWriter, r *http.Request) {
	link, rawSession, expiresAt, err := h.Service.Exchange(r.Context(), bearerCredential(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	portalContext, err := h.portalContext(r, link)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.setSessionCookie(w, rawSession, expiresAt)
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"context": portalContext, "expires_at": expiresAt, "redirect_url": h.Service.PortalURL(),
	})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(portalSessionCookie)
	if err != nil || cookie.Value == "" {
		httpx.WriteError(w, r, ErrSessionMissing)
		return
	}
	if err := h.Service.RevokeSession(r.Context(), cookie.Value); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

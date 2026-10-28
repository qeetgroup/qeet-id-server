// Package adminportal implements capability-scoped, account-less SAML, SCIM
// and domain administration. A one-time link token is exchanged for a
// short-lived browser session cookie; subsequent requests never carry
// credentials in their URL.
package adminportal

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/federation/adminportal/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/federation/saml"
	"github.com/qeetgroup/qeet-id-server/internal/federation/scim"
	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

const (
	CapabilitySAML               = "saml"
	CapabilitySCIM               = "scim"
	CapabilityDomainVerification = "domain_verification" // prove the organisation owns a domain

	minTTL              = 15 * time.Minute
	maxTTL              = 24 * time.Hour
	defaultTTL          = time.Hour
	portalSessionTTL    = 30 * time.Minute
	portalSessionCookie = "qeet_admin_portal_session"
	portalCookiePath    = "/v1/admin-portal"
)

var validCapabilities = []string{CapabilitySAML, CapabilitySCIM, CapabilityDomainVerification}

// Link is an admin-portal link, without its token.
type Link struct {
	ID           uuid.UUID  `json:"id"`
	TenantID     uuid.UUID  `json:"tenant_id"`
	Capabilities []string   `json:"capabilities"`
	CreatedBy    *uuid.UUID `json:"created_by"`
	ExpiresAt    time.Time  `json:"expires_at"`
	RevokedAt    *time.Time `json:"revoked_at"`
	LastUsedAt   *time.Time `json:"last_used_at"`
	CreatedAt    time.Time  `json:"created_at"`
}

// Has reports whether the link authorizes the given capability.
func (l Link) Has(capability string) bool { return slices.Contains(l.Capabilities, capability) }

// Service manages the portal links.
type Service struct {
	pool         *pgxpool.Pool
	q            *dbgen.Queries
	brandingRepo brandingLister
	loginBaseURL string
}

// brandingLister is the slice of branding.Repository this package needs — an
// interface so adminportal doesn't import the branding types, matching the
// one-way dependency oidc.BrandingLister already establishes.
type brandingLister interface {
	LoginBranding(ctx context.Context, tenantID uuid.UUID) (logoURL, primaryColor, secondaryColor, backgroundColor string)
}

// NewService returns the admin portal service.
func NewService(pool *pgxpool.Pool, brandingRepo brandingLister, loginBaseURL string) *Service {
	return &Service{
		pool:         pool,
		q:            dbgen.New(pool),
		brandingRepo: brandingRepo,
		loginBaseURL: strings.TrimRight(loginBaseURL, "/"),
	}
}

// pgUUIDToPtr converts a pgtype.UUID (nullable) to *uuid.UUID.
func pgUUIDToPtr(u pgtype.UUID) *uuid.UUID {
	if !u.Valid {
		return nil
	}
	id := uuid.UUID(u.Bytes)
	return &id
}

// pgTimeToPtr converts a pgtype.Timestamptz (nullable) to *time.Time.
func pgTimeToPtr(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time
	return &v
}

// Pool returns the connection pool, for handlers that run their own transaction.
func (s *Service) Pool() *pgxpool.Pool { return s.pool }

func normalizeCapabilities(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, errs.ErrAdminPortalCapabilitiesRequired
	}
	var out []string
	for _, c := range in {
		c = strings.ToLower(strings.TrimSpace(c))
		if !slices.Contains(validCapabilities, c) {
			return nil, errs.ErrAdminPortalCapabilityUnknown
		}
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return out, nil
}

func clampTTL(d time.Duration) time.Duration {
	if d <= 0 {
		return defaultTTL
	}
	if d < minTTL {
		return minTTL
	}
	if d > maxTTL {
		return maxTTL
	}
	return d
}

// Generate mints a new admin portal link. The raw token is returned exactly
// once — only the hash is persisted.
func (s *Service) Generate(ctx context.Context, tx pgx.Tx, tenantID, createdBy uuid.UUID, capabilities []string, ttl time.Duration) (*Link, string, error) {
	caps, err := normalizeCapabilities(capabilities)
	if err != nil {
		return nil, "", err
	}
	raw, hash, err := codes.URLToken()
	if err != nil {
		return nil, "", err
	}
	expires := time.Now().UTC().Add(clampTTL(ttl))
	row, err := s.q.WithTx(tx).InsertAdminPortalLink(ctx, dbgen.InsertAdminPortalLinkParams{
		TenantID:     tenantID,
		TokenHash:    hash,
		Capabilities: caps,
		CreatedBy:    pgtype.UUID{Bytes: createdBy, Valid: createdBy != uuid.Nil},
		ExpiresAt:    expires,
	})
	if err != nil {
		return nil, "", err
	}
	l := &Link{
		ID:           row.ID,
		TenantID:     row.TenantID,
		Capabilities: row.Capabilities,
		CreatedBy:    pgUUIDToPtr(row.CreatedBy),
		ExpiresAt:    row.ExpiresAt,
		RevokedAt:    pgTimeToPtr(row.RevokedAt),
		LastUsedAt:   pgTimeToPtr(row.LastUsedAt),
		CreatedAt:    row.CreatedAt,
	}
	return l, raw, nil
}

// URL builds the shareable link for a freshly-generated raw token: the hosted
// enterprise-setup page, with the token in the fragment so it never reaches a
// server log.
func (s *Service) URL(rawToken string) string {
	return s.PortalURL() + "#token=" + rawToken
}

// PortalURL returns the hosted enterprise-setup page's address.
func (s *Service) PortalURL() string { return s.loginBaseURL + "/enterprise-setup" }

// List returns the tenant's portal links.
func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Link, error) {
	rows, err := s.q.ListAdminPortalLinksByTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Link, len(rows))
	for i, r := range rows {
		out[i] = Link{
			ID:           r.ID,
			TenantID:     r.TenantID,
			Capabilities: r.Capabilities,
			CreatedBy:    pgUUIDToPtr(r.CreatedBy),
			ExpiresAt:    r.ExpiresAt,
			RevokedAt:    pgTimeToPtr(r.RevokedAt),
			LastUsedAt:   pgTimeToPtr(r.LastUsedAt),
			CreatedAt:    r.CreatedAt,
		}
	}
	return out, nil
}

// Revoke revokes one of the tenant's portal links.
func (s *Service) Revoke(ctx context.Context, tx pgx.Tx, tenantID, id uuid.UUID) error {
	n, err := s.q.WithTx(tx).RevokeAdminPortalLink(ctx, dbgen.RevokeAdminPortalLinkParams{
		ID:       id,
		TenantID: tenantID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrAdminPortalLinkNotFound
	}
	return nil
}

// Exchange atomically consumes a one-time link token and creates a separately
// hashed, short-lived portal session. Concurrent redemption has one winner.
func (s *Service) Exchange(ctx context.Context, rawToken string) (*Link, string, time.Time, error) {
	if rawToken == "" {
		return nil, "", time.Time{}, errs.ErrAdminPortalTokenMissing
	}
	hash := codes.Hash(rawToken)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	defer tx.Rollback(ctx)
	var row struct {
		ID           uuid.UUID
		TenantID     uuid.UUID
		Capabilities []string
		CreatedBy    pgtype.UUID
		ExpiresAt    time.Time
		RevokedAt    pgtype.Timestamptz
		LastUsedAt   pgtype.Timestamptz
		CreatedAt    time.Time
		RedeemedAt   pgtype.Timestamptz
	}
	err = tx.QueryRow(ctx, `
		SELECT id, tenant_id, capabilities, created_by, expires_at, revoked_at,
		       last_used_at, created_at, redeemed_at
		FROM tenant.admin_portal_links
		WHERE token_hash = $1
		FOR UPDATE
	`, hash).Scan(&row.ID, &row.TenantID, &row.Capabilities, &row.CreatedBy, &row.ExpiresAt,
		&row.RevokedAt, &row.LastUsedAt, &row.CreatedAt, &row.RedeemedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", time.Time{}, errs.ErrAdminPortalLinkInvalid
	}
	if err != nil {
		return nil, "", time.Time{}, err
	}
	l := &Link{
		ID:           row.ID,
		TenantID:     row.TenantID,
		Capabilities: row.Capabilities,
		CreatedBy:    pgUUIDToPtr(row.CreatedBy),
		ExpiresAt:    row.ExpiresAt,
		RevokedAt:    pgTimeToPtr(row.RevokedAt),
		LastUsedAt:   pgTimeToPtr(row.LastUsedAt),
		CreatedAt:    row.CreatedAt,
	}
	if l.RevokedAt != nil {
		return nil, "", time.Time{}, errs.ErrAdminPortalLinkRevoked
	}
	if time.Now().After(l.ExpiresAt) {
		return nil, "", time.Time{}, errs.ErrAdminPortalLinkExpired
	}
	if row.RedeemedAt.Valid {
		return nil, "", time.Time{}, errs.ErrAdminPortalLinkInvalid
	}
	rawSession, sessionHash, err := codes.URLToken()
	if err != nil {
		return nil, "", time.Time{}, err
	}
	sessionExpires := time.Now().UTC().Add(portalSessionTTL)
	if l.ExpiresAt.Before(sessionExpires) {
		sessionExpires = l.ExpiresAt
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO auth.admin_portal_sessions (link_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`, l.ID, sessionHash, sessionExpires); err != nil {
		return nil, "", time.Time{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE tenant.admin_portal_links
		SET redeemed_at = NOW(), last_used_at = NOW()
		WHERE id = $1
	`, l.ID); err != nil {
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
		return nil, errs.ErrAdminPortalSessionMissing
	}
	var l Link
	var createdBy pgtype.UUID
	var linkRevoked, sessionRevoked pgtype.Timestamptz
	var sessionID uuid.UUID
	var sessionExpires time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT s.id, s.expires_at, s.revoked_at,
		       l.id, l.tenant_id, l.capabilities, l.created_by, l.expires_at,
		       l.revoked_at, l.last_used_at, l.created_at
		FROM auth.admin_portal_sessions s
		JOIN tenant.admin_portal_links l ON l.id = s.link_id
		WHERE s.token_hash = $1
	`, codes.Hash(rawSession)).Scan(&sessionID, &sessionExpires, &sessionRevoked,
		&l.ID, &l.TenantID, &l.Capabilities, &createdBy, &l.ExpiresAt,
		&linkRevoked, &l.LastUsedAt, &l.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrAdminPortalSessionInvalid
	}
	if err != nil {
		return nil, err
	}
	l.CreatedBy = pgUUIDToPtr(createdBy)
	l.RevokedAt = pgTimeToPtr(linkRevoked)
	now := time.Now()
	if sessionRevoked.Valid || linkRevoked.Valid {
		return nil, errs.ErrAdminPortalSessionInvalid
	}
	if now.After(sessionExpires) || now.After(l.ExpiresAt) {
		return nil, errs.ErrAdminPortalSessionInvalid
	}
	l.ExpiresAt = sessionExpires
	_, _ = s.pool.Exec(ctx, `
		UPDATE auth.admin_portal_sessions SET last_used_at = NOW() WHERE id = $1
	`, sessionID)
	return &l, nil
}

// RevokeSession ends the portal session the raw cookie value names.
func (s *Service) RevokeSession(ctx context.Context, rawSession string) error {
	if rawSession == "" {
		return errs.ErrAdminPortalSessionMissing
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE auth.admin_portal_sessions SET revoked_at = NOW()
		WHERE token_hash = $1 AND revoked_at IS NULL
	`, codes.Hash(rawSession))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errs.ErrAdminPortalSessionInvalid
	}
	return nil
}

func (s *Service) tenantName(ctx context.Context, tenantID uuid.UUID) (string, error) {
	return s.q.GetTenantNameByID(ctx, tenantID)
}

// PortalBranding is the subset of branding.Branding a hosted, unauthenticated
// page needs to render on first paint — mirrors oidc's login-context shape.
type PortalBranding struct {
	LogoURL         string `json:"logo_url,omitempty"`
	PrimaryColor    string `json:"primary_color,omitempty"`
	SecondaryColor  string `json:"secondary_color,omitempty"`
	BackgroundColor string `json:"background_color,omitempty"`
}

// PortalContext is what the hosted admin-portal page fetches before rendering
// the SAML/SCIM forms: who it's configuring for, what it may touch, and how
// long it has left. SCIMBaseURL, where the IdP provisions to, is set only for
// a link that may set up SCIM.
type PortalContext struct {
	TenantName   string          `json:"tenant_name"`
	Capabilities []string        `json:"capabilities"`
	ExpiresAt    time.Time       `json:"expires_at"`
	Branding     *PortalBranding `json:"branding,omitempty"`
	SCIMBaseURL  string          `json:"scim_base_url,omitempty"`
}

// Context returns what the portal shows for a link: the tenant's name, the
// link's capabilities and when it expires.
func (s *Service) Context(ctx context.Context, l *Link) (*PortalContext, error) {
	name, err := s.tenantName(ctx, l.TenantID)
	if err != nil {
		return nil, err
	}
	pc := &PortalContext{TenantName: name, Capabilities: l.Capabilities, ExpiresAt: l.ExpiresAt}
	logo, primary, secondary, background := s.brandingRepo.LoginBranding(ctx, l.TenantID)
	if logo != "" || primary != "" || secondary != "" || background != "" {
		pc.Branding = &PortalBranding{LogoURL: logo, PrimaryColor: primary, SecondaryColor: secondary, BackgroundColor: background}
	}
	return pc, nil
}

// samlService is the slice of saml.Service the portal needs to let an IT
// admin manage their tenant's SP-side connection(s).
type samlService interface {
	List(ctx context.Context, tenantID uuid.UUID) ([]saml.Connection, error)
	Create(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, in saml.CreateInput) (*saml.Connection, error)
	Get(ctx context.Context, id, tenantID uuid.UUID) (*saml.Connection, error)
	Update(ctx context.Context, tx pgx.Tx, id, tenantID uuid.UUID, in saml.UpdateInput) (*saml.Connection, error)
	Delete(ctx context.Context, tx pgx.Tx, id, tenantID uuid.UUID) error
	TestConnection(ctx context.Context, id, tenantID uuid.UUID) (*saml.TestResult, error)
	TestSignIn(ctx context.Context, id, connectionID, tenantID uuid.UUID) (*saml.TestSignIn, error)
	Pool() *pgxpool.Pool
}

// samlSignIn is the slice of saml.Handler the portal needs to begin a test
// sign-in in the IT admin's browser.
type samlSignIn interface {
	BeginTestSignIn(w http.ResponseWriter, r *http.Request, tx pgx.Tx, tenantID, id uuid.UUID, returnURL string) (*saml.TestSignIn, error)
}

// domainService is the slice of domainverify.Service the portal needs to
// claim and verify the tenant's domains.
type domainService interface {
	List(ctx context.Context, tenantID uuid.UUID) ([]domainverify.Domain, error)
	Add(ctx context.Context, tenantID uuid.UUID, raw string, actor audit.Actor) (*domainverify.Domain, error)
	Verify(ctx context.Context, id, tenantID uuid.UUID, actor audit.Actor) (*domainverify.Domain, error)
}

// scimService is the slice of scim.Service the portal needs to manage the
// tenant's SCIM bearer token — never the provisioned-users list.
type scimService interface {
	Config(ctx context.Context, tenantID uuid.UUID) (*scim.ConfigView, error)
	Rotate(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) (string, error)
	Revoke(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) error
	Pool() *pgxpool.Pool
}

// Handler serves the admin portal HTTP API. PublicBaseURL is this API's
// public origin, or "" to build the addresses an IdP needs from the request's
// Host, as the SAML and SCIM handlers do.
type Handler struct {
	Service       *Service
	SAML          samlService
	SAMLSignIn    samlSignIn
	SCIM          scimService
	Domains       domainService
	PublicBaseURL string
	CookieSecure  bool
}

// Mount registers the authed link-management endpoints (generate/list/revoke)
// under the normal /v1/tenants/{tenantID} group — this is the tenant admin's
// own action, gated by connection.write/connection.read like the rest of SSO
// config.
func (h *Handler) Mount(r chi.Router) {
	r.Post("/tenants/{tenantID}/admin-portal/links", h.generate)
	r.Get("/tenants/{tenantID}/admin-portal/links", h.list)
	r.Delete("/tenants/{tenantID}/admin-portal/links/{id}", h.revoke)
}

// MountPublic registers the one-time link exchange and the cookie-authenticated,
// token-free portal endpoints used by the external IT administrator.
func (h *Handler) MountPublic(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(adminPortalHeaders)
		r.Post("/admin-portal/session", h.exchange)
		r.Delete("/admin-portal/session", h.logout)
		r.Get("/admin-portal/context", h.context)

		r.Get("/admin-portal/saml", h.samlList)
		r.Post("/admin-portal/saml", h.samlCreate)
		r.Get("/admin-portal/saml/{id}", h.samlGet)
		r.Patch("/admin-portal/saml/{id}", h.samlUpdate)
		r.Post("/admin-portal/saml/{id}/test", h.samlTest)
		r.Post("/admin-portal/saml/{id}/test-sign-ins", h.samlTestSignInBegin)
		r.Get("/admin-portal/saml/{id}/test-sign-ins/{testID}", h.samlTestSignInGet)
		r.Delete("/admin-portal/saml/{id}", h.samlDelete)

		r.Get("/admin-portal/scim", h.scimConfig)
		r.Post("/admin-portal/scim/token", h.scimRotate)
		r.Delete("/admin-portal/scim/token", h.scimRevoke)

		r.Get("/admin-portal/domains", h.domainList)
		r.Post("/admin-portal/domains", h.domainAdd)
		r.Post("/admin-portal/domains/{id}/verify", h.domainVerify)
	})
}

func adminPortalHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func requirePathTenant(r *http.Request) (uuid.UUID, error) {
	return httpx.PathTenantOr(r, errs.ErrAdminPortalTenantIDInvalid, errs.ErrAdminPortalTenantMismatch)
}

func (h *Handler) recordAudit(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, action string, resourceID *uuid.UUID, actorID *uuid.UUID, actorType, ip, ua, requestID string, meta map[string]any) error {
	tid := tenantID
	return audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       action,
		ResourceType: "admin_portal_link",
		ResourceID:   resourceID,
		IP:           ip,
		UserAgent:    ua,
		RequestID:    requestID,
		Metadata:     meta,
	})
}

// --- authed: link management ---

func (h *Handler) generate(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrAdminPortalActorRequired)
		return
	}
	var in struct {
		Capabilities []string `json:"capabilities"`
		TTLSeconds   int      `json:"ttl_seconds"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	link, raw, err := h.Service.Generate(ctx, tx, tenantID, *p.UserID, in.Capabilities, time.Duration(in.TTLSeconds)*time.Second)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := audit.ActorOf(r).Identity()
	if err := h.recordAudit(ctx, tx, tenantID, "admin_portal.link_generated", &link.ID, actorID, actorType,
		httpx.ClientIP(r), r.UserAgent(), httpx.RequestID(r), map[string]any{"capabilities": link.Capabilities}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"link":  link,
		"token": raw,
		"url":   h.Service.URL(raw),
	})
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Service.List(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrAdminPortalIDInvalid)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	if err := h.Service.Revoke(ctx, tx, tenantID, id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := audit.ActorOf(r).Identity()
	if err := h.recordAudit(ctx, tx, tenantID, "admin_portal.link_revoked", &id, actorID, actorType,
		httpx.ClientIP(r), r.UserAgent(), httpx.RequestID(r), nil); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- public: resolve helpers ---

// resolve authenticates the short-lived portal session cookie and enforces the
// capability required by the requested operation.
func (h *Handler) resolve(r *http.Request, capability string) (*Link, error) {
	cookie, err := r.Cookie(portalSessionCookie)
	if err != nil || cookie.Value == "" {
		return nil, errs.ErrAdminPortalSessionMissing
	}
	l, err := h.Service.ResolveSession(r.Context(), cookie.Value)
	if err != nil {
		return nil, err
	}
	if capability != "" && !l.Has(capability) {
		return nil, errs.ErrAdminPortalCapabilityNotGranted
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
		httpx.WriteError(w, r, errs.ErrAdminPortalSessionMissing)
		return
	}
	if err := h.Service.RevokeSession(r.Context(), cookie.Value); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func portalAudit(action string, resourceID *uuid.UUID) func(ctx context.Context, tx pgx.Tx, l *Link, r *http.Request, meta map[string]any) error {
	return func(ctx context.Context, tx pgx.Tx, l *Link, r *http.Request, meta map[string]any) error {
		tid := l.TenantID
		return audit.Record(ctx, tx, audit.Event{
			TenantID:     &tid,
			ActorUserID:  l.CreatedBy,
			ActorType:    "admin_portal",
			Action:       action,
			ResourceType: "saml_connection",
			ResourceID:   resourceID,
			IP:           httpx.ClientIP(r),
			UserAgent:    r.UserAgent(),
			RequestID:    httpx.RequestID(r),
			Metadata:     meta,
		})
	}
}

// --- public: context ---

func (h *Handler) context(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, "")
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	pc, err := h.portalContext(r, l)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, pc)
}

// portalContext returns link l's context, with the SCIM base URL when l may
// set up SCIM.
func (h *Handler) portalContext(r *http.Request, l *Link) (*PortalContext, error) {
	pc, err := h.Service.Context(r.Context(), l)
	if err != nil {
		return nil, err
	}
	if l.Has(CapabilitySCIM) {
		pc.SCIMBaseURL = scim.BaseURL(h.origin(r))
	}
	return pc, nil
}

// origin returns the API's public origin, which the SAML and SCIM addresses
// are built on.
func (h *Handler) origin(r *http.Request) string {
	return httpx.PublicOrigin(r, h.PublicBaseURL)
}

// portalActor is who acts through link l in an audit event: the portal, on
// behalf of the link's creator.
func portalActor(l *Link, r *http.Request) audit.Actor {
	return audit.Actor{UserID: l.CreatedBy, Type: "admin_portal", IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r)}
}

// --- public: SAML ---

// portalConnection is a SAML connection as the portal shows it: with the
// addresses the IT admin enters at their IdP.
type portalConnection struct {
	saml.Connection
	saml.SPAddresses
}

func (h *Handler) withAddresses(r *http.Request, c *saml.Connection) portalConnection {
	return portalConnection{Connection: *c, SPAddresses: saml.Addresses(h.origin(r), c.ID)}
}

func (h *Handler) samlList(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilitySAML)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	conns, err := h.SAML.List(r.Context(), l.TenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out := make([]portalConnection, len(conns))
	for i := range conns {
		out[i] = h.withAddresses(r, &conns[i])
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) samlCreate(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilitySAML)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in saml.CreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.IdpEntityID = strings.TrimSpace(in.IdpEntityID)
	in.IdpSSOURL = strings.TrimSpace(in.IdpSSOURL)
	if in.Name == "" || in.IdpEntityID == "" || in.IdpSSOURL == "" || strings.TrimSpace(in.IdpCertificate) == "" {
		httpx.WriteError(w, r, errs.ErrAdminPortalSAMLFieldsRequired)
		return
	}
	ctx := r.Context()
	tx, err := h.SAML.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	conn, err := h.SAML.Create(ctx, tx, l.TenantID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := portalAudit("saml.connection_created", &conn.ID)(ctx, tx, l, r, map[string]any{"name": conn.Name, "idp": conn.IdpEntityID}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, conn)
}

func (h *Handler) samlGet(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilitySAML)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrAdminPortalIDInvalid)
		return
	}
	conn, err := h.SAML.Get(r.Context(), id, l.TenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.withAddresses(r, conn))
}

func (h *Handler) samlUpdate(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilitySAML)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrAdminPortalIDInvalid)
		return
	}
	var in saml.UpdateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.Status != nil && *in.Status != "draft" && *in.Status != "active" && *in.Status != "disabled" {
		httpx.WriteError(w, r, errs.ErrAdminPortalSAMLStatusInvalid)
		return
	}
	ctx := r.Context()
	tx, err := h.SAML.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	conn, err := h.SAML.Update(ctx, tx, id, l.TenantID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := portalAudit("saml.connection_updated", &conn.ID)(ctx, tx, l, r, map[string]any{"status": conn.Status}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.withAddresses(r, conn))
}

func (h *Handler) samlTest(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilitySAML)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrAdminPortalIDInvalid)
		return
	}
	res, err := h.SAML.TestConnection(r.Context(), id, l.TenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// samlTestSignInBegin starts a test sign-in through a connection in this
// browser: it answers with the IdP address to send the browser to, and the
// IdP's answer returns the browser to the portal page to read the result.
func (h *Handler) samlTestSignInBegin(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilitySAML)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrAdminPortalIDInvalid)
		return
	}
	ctx := r.Context()
	tx, err := h.SAML.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	test, err := h.SAMLSignIn.BeginTestSignIn(w, r, tx, l.TenantID, id, h.Service.PortalURL())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := portalAudit("saml.test_sign_in_started", &id)(ctx, tx, l, r, map[string]any{"test_sign_in_id": test.ID}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, test)
}

func (h *Handler) samlTestSignInGet(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilitySAML)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrAdminPortalIDInvalid)
		return
	}
	testID, err := uuid.Parse(chi.URLParam(r, "testID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrAdminPortalIDInvalid)
		return
	}
	test, err := h.SAML.TestSignIn(r.Context(), testID, id, l.TenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, test)
}

func (h *Handler) samlDelete(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilitySAML)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrAdminPortalIDInvalid)
		return
	}
	ctx := r.Context()
	tx, err := h.SAML.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	if err := h.SAML.Delete(ctx, tx, id, l.TenantID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := portalAudit("saml.connection_deleted", &id)(ctx, tx, l, r, nil); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- public: SCIM ---

func (h *Handler) scimConfig(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilitySCIM)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	cfg, err := h.SCIM.Config(r.Context(), l.TenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, cfg)
}

func (h *Handler) scimRotate(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilitySCIM)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	tx, err := h.SCIM.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	full, err := h.SCIM.Rotate(ctx, tx, l.TenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &l.TenantID,
		ActorUserID:  l.CreatedBy,
		ActorType:    "admin_portal",
		Action:       "scim.token_rotated",
		ResourceType: "scim_token",
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	cfg, err := h.SCIM.Config(ctx, l.TenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"token": full, "config": cfg})
}

func (h *Handler) scimRevoke(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilitySCIM)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	tx, err := h.SCIM.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	if err := h.SCIM.Revoke(ctx, tx, l.TenantID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &l.TenantID,
		ActorUserID:  l.CreatedBy,
		ActorType:    "admin_portal",
		Action:       "scim.token_revoked",
		ResourceType: "scim_token",
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- public: domains ---

func (h *Handler) domainList(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilityDomainVerification)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Domains.List(r.Context(), l.TenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

// domainAdd claims a domain for the tenant and answers with the DNS record to
// publish, as the admin API does.
func (h *Handler) domainAdd(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilityDomainVerification)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		Domain string `json:"domain"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	d, err := h.Domains.Add(r.Context(), l.TenantID, in.Domain, portalActor(l, r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, d)
}

// domainVerify checks the DNS record of the tenant's domain, as the admin API
// does: a domain another organisation verified stays theirs.
func (h *Handler) domainVerify(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilityDomainVerification)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrAdminPortalIDInvalid)
		return
	}
	d, err := h.Domains.Verify(r.Context(), id, l.TenantID, portalActor(l, r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, d)
}

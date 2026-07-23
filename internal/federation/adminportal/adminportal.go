// Package adminportal implements a WorkOS-style Admin Portal: a unique,
// time-limited, capability-scoped link a tenant admin hands to their (account-less)
// IT admin to configure the tenant's SAML connection and/or rotate its SCIM token
// without logging in. The link carries no identity — only a capability set
// ("saml"/"scim") and an expiry; the raw token (hashed at rest) is the sole
// credential, so redemption bypasses the connection.* RBAC check. Unlike an invite
// it is reusable until it expires or is revoked. Out of scope: the SCIM
// provisioned-users list (PII) and the SAML IdP-side registry.
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
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

const (
	CapabilitySAML = "saml"
	CapabilitySCIM = "scim"

	minTTL     = 15 * time.Minute
	maxTTL     = 7 * 24 * time.Hour
	defaultTTL = 24 * time.Hour
)

var validCapabilities = []string{CapabilitySAML, CapabilitySCIM}

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
	LoginBranding(ctx context.Context, tenantID uuid.UUID) (logoURL, primaryColor, secondaryColor string)
}

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

func (s *Service) Pool() *pgxpool.Pool { return s.pool }

func normalizeCapabilities(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, errs.ErrUnprocessable.WithDetail(`capabilities is required ("saml", "scim", or both)`)
	}
	var out []string
	for _, c := range in {
		c = strings.ToLower(strings.TrimSpace(c))
		if !slices.Contains(validCapabilities, c) {
			return nil, errs.ErrUnprocessable.WithDetail("unknown capability \"" + c + "\" (must be \"saml\" or \"scim\")")
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

// URL builds the shareable link for a freshly-generated raw token.
func (s *Service) URL(rawToken string) string {
	return s.loginBaseURL + "/admin-portal/" + rawToken
}

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

func (s *Service) Revoke(ctx context.Context, tx pgx.Tx, tenantID, id uuid.UUID) error {
	n, err := s.q.WithTx(tx).RevokeAdminPortalLink(ctx, dbgen.RevokeAdminPortalLinkParams{
		ID:       id,
		TenantID: tenantID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

// Resolve maps a presented raw token to its Link, rejecting a revoked or
// expired one, and stamps last_used_at. Every public redemption endpoint
// calls this first.
func (s *Service) Resolve(ctx context.Context, rawToken string) (*Link, error) {
	if rawToken == "" {
		return nil, errs.ErrUnauthorized.WithDetail("missing admin portal token")
	}
	hash := codes.Hash(rawToken)
	row, err := s.q.GetAdminPortalLinkByHash(ctx, hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrUnauthorized.WithDetail("invalid admin portal link")
	}
	if err != nil {
		return nil, err
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
		return nil, errs.ErrUnauthorized.WithDetail("this admin portal link has been revoked")
	}
	if time.Now().After(l.ExpiresAt) {
		return nil, errs.ErrUnauthorized.WithDetail("this admin portal link has expired")
	}
	_ = s.q.TouchAdminPortalLinkUsed(ctx, l.ID)
	return l, nil
}

func (s *Service) tenantName(ctx context.Context, tenantID uuid.UUID) (string, error) {
	return s.q.GetTenantNameByID(ctx, tenantID)
}

// PortalBranding is the subset of branding.Branding a hosted, unauthenticated
// page needs to render on first paint — mirrors oidc's login-context shape.
type PortalBranding struct {
	LogoURL        string `json:"logo_url,omitempty"`
	PrimaryColor   string `json:"primary_color,omitempty"`
	SecondaryColor string `json:"secondary_color,omitempty"`
}

// PortalContext is what the hosted admin-portal page fetches before rendering
// the SAML/SCIM forms: who it's configuring for, what it may touch, and how
// long it has left.
type PortalContext struct {
	TenantName   string          `json:"tenant_name"`
	Capabilities []string        `json:"capabilities"`
	ExpiresAt    time.Time       `json:"expires_at"`
	Branding     *PortalBranding `json:"branding,omitempty"`
}

func (s *Service) Context(ctx context.Context, l *Link) (*PortalContext, error) {
	name, err := s.tenantName(ctx, l.TenantID)
	if err != nil {
		return nil, err
	}
	pc := &PortalContext{TenantName: name, Capabilities: l.Capabilities, ExpiresAt: l.ExpiresAt}
	logo, primary, secondary := s.brandingRepo.LoginBranding(ctx, l.TenantID)
	if logo != "" || primary != "" || secondary != "" {
		pc.Branding = &PortalBranding{LogoURL: logo, PrimaryColor: primary, SecondaryColor: secondary}
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
	Pool() *pgxpool.Pool
}

// scimService is the slice of scim.Service the portal needs to manage the
// tenant's SCIM bearer token — never the provisioned-users list.
type scimService interface {
	Config(ctx context.Context, tenantID uuid.UUID) (*scim.ConfigView, error)
	Rotate(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) (string, error)
	Revoke(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) error
	Pool() *pgxpool.Pool
}

type Handler struct {
	Service *Service
	SAML    samlService
	SCIM    scimService
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

// MountPublic registers the token-gated redemption endpoints the external IT
// admin's browser calls — no user JWT, no RBAC, no cookie session. The
// {token} path segment is the sole credential.
func (h *Handler) MountPublic(r chi.Router) {
	r.Get("/admin-portal/{token}/context", h.context)

	r.Get("/admin-portal/{token}/saml", h.samlList)
	r.Post("/admin-portal/{token}/saml", h.samlCreate)
	r.Get("/admin-portal/{token}/saml/{id}", h.samlGet)
	r.Patch("/admin-portal/{token}/saml/{id}", h.samlUpdate)
	r.Post("/admin-portal/{token}/saml/{id}/test", h.samlTest)
	r.Delete("/admin-portal/{token}/saml/{id}", h.samlDelete)

	r.Get("/admin-portal/{token}/scim", h.scimConfig)
	r.Post("/admin-portal/{token}/scim/token", h.scimRotate)
	r.Delete("/admin-portal/{token}/scim/token", h.scimRevoke)
}

func requirePathTenant(r *http.Request) (uuid.UUID, error) {
	pathTenant, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		return uuid.Nil, errs.ErrBadRequest.WithDetail("invalid tenantID")
	}
	scope, err := httpx.RequireTenant(r)
	if err != nil {
		return uuid.Nil, err
	}
	if pathTenant != scope {
		return uuid.Nil, errs.ErrForbidden.WithDetail("tenant mismatch")
	}
	return scope, nil
}

func auditActor(r *http.Request) (*uuid.UUID, string) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil {
		return nil, "system"
	}
	at := p.ActorType
	if at == "" {
		at = "user"
	}
	return p.UserID, at
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
		httpx.WriteError(w, r, errs.ErrUnauthorized.WithDetail("must be attributed to a human"))
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
	actorID, actorType := auditActor(r)
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
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
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
	actorID, actorType := auditActor(r)
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

// resolve loads the link for the {token} path param and, if capability is
// non-empty, rejects the request when the link doesn't authorize it.
func (h *Handler) resolve(r *http.Request, capability string) (*Link, error) {
	l, err := h.Service.Resolve(r.Context(), chi.URLParam(r, "token"))
	if err != nil {
		return nil, err
	}
	if capability != "" && !l.Has(capability) {
		return nil, errs.ErrForbidden.WithDetail("this admin portal link does not include " + capability + " access")
	}
	return l, nil
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
	ctx, err := h.Service.Context(r.Context(), l)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, ctx)
}

// --- public: SAML ---

func (h *Handler) samlList(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilitySAML)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.SAML.List(r.Context(), l.TenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
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
		httpx.WriteError(w, r, errs.ErrUnprocessable.WithDetail("name, idp_entity_id, idp_sso_url and idp_certificate are required"))
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
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	conn, err := h.SAML.Get(r.Context(), id, l.TenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, conn)
}

func (h *Handler) samlUpdate(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilitySAML)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	var in saml.UpdateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.Status != nil && *in.Status != "draft" && *in.Status != "active" && *in.Status != "disabled" {
		httpx.WriteError(w, r, errs.ErrUnprocessable.WithDetail("status must be draft, active or disabled"))
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
	httpx.WriteJSON(w, http.StatusOK, conn)
}

func (h *Handler) samlTest(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilitySAML)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	res, err := h.SAML.TestConnection(r.Context(), id, l.TenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

func (h *Handler) samlDelete(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilitySAML)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
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

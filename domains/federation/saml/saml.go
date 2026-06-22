// Package saml implements SP-initiated SAML 2.0 single sign-on. A tenant
// registers an IdP connection (issuer, SSO URL, signing certificate); users
// are sent to the IdP, the signed assertion returns to the ACS, and a Qeet ID
// user is JIT-provisioned and issued a session.
//
// Assertion signature/condition validation is delegated to gosaml2 +
// goxmldsig (a vetted implementation) — we never hand-roll XML-DSig. The flow
// mirrors social login: the ACS hands the SPA a one-time code (never a token
// in a URL), which it trades at /saml/exchange for a token pair.
//
// Surfaces:
//   - Admin  (/v1/tenants/{id}/saml, user-JWT): connection CRUD.
//   - Public (/saml/..., no JWT): metadata, login redirect, ACS, exchange.
package saml

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/qeetgroup/qeet-id/domains/access/authentication"
	"github.com/qeetgroup/qeet-id/domains/operations/audit"
	"github.com/qeetgroup/qeet-id/platform/codes"
	"github.com/qeetgroup/qeet-id/platform/errs"
	"github.com/qeetgroup/qeet-id/platform/httpx"
)

const (
	provider     = "saml"
	loginCodeTTL = 5 * time.Minute
)

type Connection struct {
	ID             uuid.UUID  `json:"id"`
	TenantID       uuid.UUID  `json:"tenant_id"`
	Name           string     `json:"name"`
	IdpEntityID    string     `json:"idp_entity_id"`
	IdpSSOURL      string     `json:"idp_sso_url"`
	IdpCertificate string     `json:"idp_certificate"`
	EmailAttribute string     `json:"email_attribute"`
	NameAttribute  string     `json:"name_attribute"`
	Status         string     `json:"status"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	LastLoginAt    *time.Time `json:"last_login_at"`
}

type Service struct {
	pool       *pgxpool.Pool
	auth       *auth.Service
	appBaseURL string
}

func NewService(pool *pgxpool.Pool, authSvc *auth.Service, appBaseURL string) *Service {
	return &Service{pool: pool, auth: authSvc, appBaseURL: strings.TrimRight(appBaseURL, "/")}
}

func (s *Service) Pool() *pgxpool.Pool { return s.pool }

const connCols = `id, tenant_id, name, idp_entity_id, idp_sso_url, idp_certificate,
                  email_attribute, name_attribute, status, created_at, updated_at, last_login_at`

func scanConn(row pgx.Row) (*Connection, error) {
	var c Connection
	if err := row.Scan(&c.ID, &c.TenantID, &c.Name, &c.IdpEntityID, &c.IdpSSOURL, &c.IdpCertificate,
		&c.EmailAttribute, &c.NameAttribute, &c.Status, &c.CreatedAt, &c.UpdatedAt, &c.LastLoginAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrNotFound
		}
		return nil, err
	}
	return &c, nil
}

type CreateInput struct {
	Name           string `json:"name"`
	IdpEntityID    string `json:"idp_entity_id"`
	IdpSSOURL      string `json:"idp_sso_url"`
	IdpCertificate string `json:"idp_certificate"`
	EmailAttribute string `json:"email_attribute"`
	NameAttribute  string `json:"name_attribute"`
	Status         string `json:"status"`
}

func (s *Service) Create(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, in CreateInput) (*Connection, error) {
	status := in.Status
	if status == "" {
		status = "draft"
	}
	row := tx.QueryRow(ctx, `
		INSERT INTO tenant.saml_connections
			(tenant_id, name, idp_entity_id, idp_sso_url, idp_certificate, email_attribute, name_attribute, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING `+connCols,
		tenantID, in.Name, in.IdpEntityID, in.IdpSSOURL, in.IdpCertificate,
		in.EmailAttribute, in.NameAttribute, status)
	return scanConn(row)
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Connection, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+connCols+` FROM tenant.saml_connections WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Connection
	for rows.Next() {
		var c Connection
		if err := rows.Scan(&c.ID, &c.TenantID, &c.Name, &c.IdpEntityID, &c.IdpSSOURL, &c.IdpCertificate,
			&c.EmailAttribute, &c.NameAttribute, &c.Status, &c.CreatedAt, &c.UpdatedAt, &c.LastLoginAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Service) Get(ctx context.Context, id, tenantID uuid.UUID) (*Connection, error) {
	return scanConn(s.pool.QueryRow(ctx, `SELECT `+connCols+` FROM tenant.saml_connections WHERE id = $1 AND tenant_id = $2`, id, tenantID))
}

// getByID loads a connection without tenant scoping — used by the public SSO
// endpoints, where the (unguessable) connection UUID in the path is the key.
func (s *Service) getByID(ctx context.Context, id uuid.UUID) (*Connection, error) {
	return scanConn(s.pool.QueryRow(ctx, `SELECT `+connCols+` FROM tenant.saml_connections WHERE id = $1`, id))
}

type UpdateInput struct {
	Name           *string `json:"name"`
	IdpEntityID    *string `json:"idp_entity_id"`
	IdpSSOURL      *string `json:"idp_sso_url"`
	IdpCertificate *string `json:"idp_certificate"`
	EmailAttribute *string `json:"email_attribute"`
	NameAttribute  *string `json:"name_attribute"`
	Status         *string `json:"status"`
}

func (s *Service) Update(ctx context.Context, tx pgx.Tx, id, tenantID uuid.UUID, in UpdateInput) (*Connection, error) {
	row := tx.QueryRow(ctx, `
		UPDATE tenant.saml_connections SET
			name            = COALESCE($3, name),
			idp_entity_id   = COALESCE($4, idp_entity_id),
			idp_sso_url     = COALESCE($5, idp_sso_url),
			idp_certificate = COALESCE($6, idp_certificate),
			email_attribute = COALESCE($7, email_attribute),
			name_attribute  = COALESCE($8, name_attribute),
			status          = COALESCE($9, status),
			updated_at      = NOW()
		WHERE id = $1 AND tenant_id = $2
		RETURNING `+connCols,
		id, tenantID, in.Name, in.IdpEntityID, in.IdpSSOURL, in.IdpCertificate,
		in.EmailAttribute, in.NameAttribute, in.Status)
	return scanConn(row)
}

func (s *Service) Delete(ctx context.Context, tx pgx.Tx, id, tenantID uuid.UUID) error {
	ct, err := tx.Exec(ctx, `DELETE FROM tenant.saml_connections WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errs.ErrNotFound
	}
	return nil
}

// --- SAML SP construction ---

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
func (s *Service) TestConnection(ctx context.Context, id, tenantID uuid.UUID) (*TestResult, error) {
	c, err := s.Get(ctx, id, tenantID)
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

	u, perr := url.Parse(strings.TrimSpace(c.IdpSSOURL))
	ssoOK := perr == nil && u.Scheme == "https" && u.Host != ""
	add("IdP SSO URL", ssoOK, "Must be an absolute https:// URL.")

	cert, cerr := parseCertificate(c.IdpCertificate)
	add("Signing certificate", cerr == nil, "Must be a valid PEM block or base64-encoded DER certificate.")
	if cerr == nil {
		now := time.Now()
		valid := now.After(cert.NotBefore) && now.Before(cert.NotAfter)
		detail := "Valid until " + cert.NotAfter.Format("2006-01-02") + "."
		if !valid {
			detail = "Certificate is expired or not yet valid (expires " + cert.NotAfter.Format("2006-01-02") + ")."
		}
		add("Certificate validity period", valid, detail)
	}

	add("Email attribute mapping", strings.TrimSpace(c.EmailAttribute) != "", "Needed to resolve each user's email from the SAML assertion.")

	return res, nil
}

// parseCertificate accepts a PEM block or bare base64 DER and returns the cert.
func parseCertificate(raw string) (*x509.Certificate, error) {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "-----BEGIN") {
		block, _ := pem.Decode([]byte(raw))
		if block == nil {
			return nil, errors.New("invalid PEM certificate")
		}
		return x509.ParseCertificate(block.Bytes)
	}
	// Bare base64 DER (as found in IdP metadata <X509Certificate>): strip
	// any whitespace the copy-paste introduced.
	clean := strings.NewReplacer("\n", "", "\r", "", " ", "", "\t", "").Replace(raw)
	der, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("certificate is neither PEM nor base64 DER: %w", err)
	}
	return x509.ParseCertificate(der)
}

func publicBase(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil && (strings.HasPrefix(r.Host, "localhost") || strings.HasPrefix(r.Host, "127.0.0.1")) {
		scheme = "http"
	}
	return scheme + "://" + r.Host
}

func spEntityID(r *http.Request, id uuid.UUID) string {
	return publicBase(r) + "/saml/metadata/" + id.String()
}
func acsURL(r *http.Request, id uuid.UUID) string { return publicBase(r) + "/saml/acs/" + id.String() }

func (s *Service) buildSP(r *http.Request, conn *Connection) (*saml2.SAMLServiceProvider, error) {
	cert, err := parseCertificate(conn.IdpCertificate)
	if err != nil {
		return nil, err
	}
	return &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      conn.IdpSSOURL,
		IdentityProviderIssuer:      conn.IdpEntityID,
		ServiceProviderIssuer:       spEntityID(r, conn.ID),
		AssertionConsumerServiceURL: acsURL(r, conn.ID),
		AudienceURI:                 spEntityID(r, conn.ID),
		SignAuthnRequests:           false,
		IDPCertificateStore: &dsig.MemoryX509CertificateStore{
			Roots: []*x509.Certificate{cert},
		},
	}, nil
}

// findOrCreateUser links the SAML NameID to an existing user (by linked
// identity, then by globally-unique email) or provisions a new one. Mirrors
// social.findOrCreateUser; one tx so concurrent logins can't duplicate rows.
func (s *Service) findOrCreateUser(ctx context.Context, tenantID uuid.UUID, subject, email, name string) (uuid.UUID, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)

	var userID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT user_id FROM "user".external_identities
		WHERE tenant_id = $1 AND provider = $2 AND subject = $3
	`, tenantID, provider, subject).Scan(&userID)
	if err == nil {
		return userID, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, err
	}

	err = tx.QueryRow(ctx, `
		SELECT id FROM "user".users WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL
	`, email).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		var displayName any
		if name != "" {
			displayName = name
		}
		if err := tx.QueryRow(ctx, `
			INSERT INTO "user".users (tenant_id, email, email_verified_at, display_name, status)
			VALUES ($1, $2, NOW(), $3, 'active')
			RETURNING id
		`, tenantID, email, displayName).Scan(&userID); err != nil {
			return uuid.Nil, err
		}
	} else if err != nil {
		return uuid.Nil, err
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO "user".external_identities (user_id, tenant_id, provider, subject, email)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, provider, subject) DO NOTHING
	`, userID, tenantID, provider, subject, email); err != nil {
		return uuid.Nil, err
	}
	return userID, tx.Commit(ctx)
}

// ExchangeLogin trades a one-time SAML login code for a Qeet token pair.
func (s *Service) ExchangeLogin(ctx context.Context, rawCode, ip, ua string) (*auth.TokenPair, error) {
	if rawCode == "" {
		return nil, errs.ErrBadRequest.WithDetail("code required")
	}
	codeHash := codes.Hash(rawCode)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var (
		userID    uuid.UUID
		tenantID  uuid.UUID
		expiresAt time.Time
		usedAt    *time.Time
	)
	err = tx.QueryRow(ctx, `
		SELECT user_id, tenant_id, expires_at, used_at
		FROM auth.saml_login_codes WHERE code_hash = $1 FOR UPDATE
	`, codeHash).Scan(&userID, &tenantID, &expiresAt, &usedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrUnauthorized.WithDetail("invalid code")
	}
	if err != nil {
		return nil, err
	}
	if usedAt != nil {
		return nil, errs.ErrUnauthorized.WithDetail("code already used")
	}
	if time.Now().After(expiresAt) {
		return nil, errs.ErrUnauthorized.WithDetail("code expired")
	}
	if _, err := tx.Exec(ctx, `UPDATE auth.saml_login_codes SET used_at = NOW() WHERE code_hash = $1`, codeHash); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.auth.IssuePair(ctx, userID, tenantID, ip, ua, provider)
}

// =====================================================================
// Handler
// =====================================================================

type Handler struct {
	Service *Service
	// IdP is the SAML *identity-provider* side (Qeet as an SSO source). Optional;
	// when nil the /saml/idp/* endpoints report 501 and the SP-registry admin
	// routes are not mounted.
	IdP *IdP
	// CookieSecure marks browser cookies Secure; set from SERVICE_ENV != "dev".
	CookieSecure bool
}

func (h *Handler) Mount(r chi.Router) {
	// SP side: external-IdP connections Qeet consumes.
	r.Get("/tenants/{tenantID}/saml", h.list)
	r.Post("/tenants/{tenantID}/saml", h.create)
	r.Get("/tenants/{tenantID}/saml/{id}", h.get)
	r.Patch("/tenants/{tenantID}/saml/{id}", h.update)
	r.Post("/tenants/{tenantID}/saml/{id}/test", h.test)
	r.Delete("/tenants/{tenantID}/saml/{id}", h.del)

	// IdP side: downstream Service Providers that consume Qeet as their IdP.
	if h.IdP != nil {
		r.Get("/tenants/{tenantID}/saml-providers", h.listSP)
		r.Post("/tenants/{tenantID}/saml-providers", h.createSP)
		r.Get("/tenants/{tenantID}/saml-providers/{id}", h.getSP)
		r.Patch("/tenants/{tenantID}/saml-providers/{id}", h.updateSP)
		r.Delete("/tenants/{tenantID}/saml-providers/{id}", h.delSP)
	}
}

// MountPublic registers the browser/IdP-facing SSO ceremony (no user JWT).
func (h *Handler) MountPublic(r chi.Router) {
	// SP side (Qeet as SP): metadata, login redirect, ACS, code exchange.
	r.Get("/saml/metadata/{id}", h.metadata)
	r.Get("/saml/login/{id}", h.login)
	r.Post("/saml/acs/{id}", h.acs) // CSRF-exempt (see router.go); validated by signature
	r.Post("/saml/exchange", h.exchange)

	// IdP side (Qeet as IdP): metadata + SingleSignOnService (redirect + POST).
	r.Get("/saml/idp/metadata", h.idpMetadata)
	r.Get("/saml/idp/sso", h.idpSSO)
	r.Post("/saml/idp/sso", h.idpSSO) // CSRF-exempt (see router.go); SP-initiated cross-origin POST
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

func (h *Handler) recordAudit(ctx context.Context, tx pgx.Tx, r *http.Request, tenantID, resourceID uuid.UUID, action string, meta map[string]any) error {
	actorID, actorType := auditActor(r)
	tid := tenantID
	rid := resourceID
	return audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       action,
		ResourceType: "saml_connection",
		ResourceID:   &rid,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     meta,
	})
}

// --- admin CRUD handlers ---

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

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in CreateInput
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
	if _, err := parseCertificate(in.IdpCertificate); err != nil {
		httpx.WriteError(w, r, errs.ErrUnprocessable.WithDetail("idp_certificate is not a valid X.509 certificate"))
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	conn, err := h.Service.Create(ctx, tx, tenantID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.recordAudit(ctx, tx, r, tenantID, conn.ID, "saml.connection_created", map[string]any{"name": conn.Name, "idp": conn.IdpEntityID}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, conn)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
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
	conn, err := h.Service.Get(r.Context(), id, tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, conn)
}

// test runs a config preflight over a SAML connection and returns per-check
// results so the admin can fix issues before enabling it.
func (h *Handler) test(w http.ResponseWriter, r *http.Request) {
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
	res, err := h.Service.TestConnection(r.Context(), id, tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
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
	var in UpdateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.Status != nil && *in.Status != "draft" && *in.Status != "active" && *in.Status != "disabled" {
		httpx.WriteError(w, r, errs.ErrUnprocessable.WithDetail("status must be draft, active or disabled"))
		return
	}
	if in.IdpCertificate != nil {
		if _, err := parseCertificate(*in.IdpCertificate); err != nil {
			httpx.WriteError(w, r, errs.ErrUnprocessable.WithDetail("idp_certificate is not a valid X.509 certificate"))
			return
		}
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	conn, err := h.Service.Update(ctx, tx, id, tenantID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.recordAudit(ctx, tx, r, tenantID, conn.ID, "saml.connection_updated", map[string]any{"status": conn.Status}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, conn)
}

func (h *Handler) del(w http.ResponseWriter, r *http.Request) {
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
	if err := h.Service.Delete(ctx, tx, id, tenantID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.recordAudit(ctx, tx, r, tenantID, id, "saml.connection_deleted", nil); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- public SSO ceremony ---
//
// These endpoints are browser/IdP-facing. Success paths return SAML XML or a
// 302 redirect (kept as-is). Error paths emit the standard JSON error envelope
// via httpx.WriteError — consistent with the rest of the API and carrying a
// request_id for support — rather than bare http.Error plain text.

func (h *Handler) metadata(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	if _, err := h.Service.getByID(r.Context(), id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	xml := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s" index="1" isDefault="true"/>
  </SPSSODescriptor>
</EntityDescriptor>`, spEntityID(r, id), acsURL(r, id))
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("Content-Disposition", `attachment; filename="sp-metadata.xml"`)
	_, _ = w.Write([]byte(xml))
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	conn, err := h.Service.getByID(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if conn.Status == "disabled" {
		httpx.WriteError(w, r, errs.ErrForbidden.WithDetail("connection disabled"))
		return
	}
	sp, err := h.Service.buildSP(r, conn)
	if err != nil {
		slog.Error("saml login: build SP", "err", err, "connection", conn.ID)
		httpx.WriteError(w, r, errs.ErrInternal.WithDetail("connection misconfigured"))
		return
	}
	authURL, err := sp.BuildAuthURL(r.URL.Query().Get("relay"))
	if err != nil {
		slog.Error("saml login: build auth url", "err", err, "connection", conn.ID)
		httpx.WriteError(w, r, errs.ErrInternal)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *Handler) acs(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	conn, err := h.Service.getByID(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if conn.Status == "disabled" {
		httpx.WriteError(w, r, errs.ErrForbidden.WithDetail("connection disabled"))
		return
	}
	if err := r.ParseForm(); err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid form"))
		return
	}
	encoded := r.PostFormValue("SAMLResponse")
	if encoded == "" {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("missing SAMLResponse"))
		return
	}
	sp, err := h.Service.buildSP(r, conn)
	if err != nil {
		slog.Error("saml acs: build SP", "err", err, "connection", conn.ID)
		httpx.WriteError(w, r, errs.ErrInternal.WithDetail("connection misconfigured"))
		return
	}
	info, err := sp.RetrieveAssertionInfo(encoded)
	if err != nil {
		slog.Warn("saml acs: assertion validation failed", "err", err, "connection", conn.ID)
		httpx.WriteError(w, r, errs.ErrUnauthorized.WithDetail("assertion validation failed"))
		return
	}
	if info.WarningInfo != nil && (info.WarningInfo.InvalidTime || info.WarningInfo.NotInAudience) {
		slog.Warn("saml acs: assertion conditions not met", "connection", conn.ID,
			"invalid_time", info.WarningInfo.InvalidTime, "not_in_audience", info.WarningInfo.NotInAudience)
		httpx.WriteError(w, r, errs.ErrUnauthorized.WithDetail("assertion conditions not met"))
		return
	}

	email := info.NameID
	if conn.EmailAttribute != "" {
		if v := info.Values.Get(conn.EmailAttribute); v != "" {
			email = v
		}
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("assertion did not yield an email"))
		return
	}
	name := ""
	if conn.NameAttribute != "" {
		name = info.Values.Get(conn.NameAttribute)
	}

	ctx := r.Context()
	userID, err := h.Service.findOrCreateUser(ctx, conn.TenantID, info.NameID, email, name)
	if err != nil {
		slog.Error("saml acs: provisioning failed", "err", err, "connection", conn.ID)
		httpx.WriteError(w, r, errs.ErrInternal)
		return
	}

	rawCode, codeHash, err := codes.URLToken()
	if err != nil {
		slog.Error("saml acs: generate login code", "err", err)
		httpx.WriteError(w, r, errs.ErrInternal)
		return
	}
	if _, err := h.Service.Pool().Exec(ctx, `
		INSERT INTO auth.saml_login_codes (code_hash, user_id, tenant_id, expires_at)
		VALUES ($1, $2, $3, $4)
	`, codeHash, userID, conn.TenantID, time.Now().UTC().Add(loginCodeTTL)); err != nil {
		slog.Error("saml acs: persist login code", "err", err)
		httpx.WriteError(w, r, errs.ErrInternal)
		return
	}
	_, _ = h.Service.Pool().Exec(ctx, `UPDATE tenant.saml_connections SET last_login_at = NOW() WHERE id = $1`, conn.ID)

	// Hand the SPA the one-time code in the URL fragment (never sent to a
	// server / proxy log); the SPA trades it at /saml/exchange.
	target := h.Service.appBaseURL + "/sso/callback#saml_code=" + rawCode
	http.Redirect(w, r, target, http.StatusFound)
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

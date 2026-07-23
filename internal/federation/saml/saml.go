// Package saml implements SP-initiated SAML 2.0 single sign-on. A tenant registers
// an IdP connection (issuer, SSO URL, signing cert); users are sent to the IdP, the
// signed assertion returns to the ACS, and a Qeet ID user is JIT-provisioned.
// Signature/condition validation is delegated to gosaml2 + goxmldsig — we never
// hand-roll XML-DSig. Like social login, the ACS hands the SPA a one-time code
// (never a token in a URL) to trade at /saml/exchange for a token pair.
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
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/saml/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
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
	q          *dbgen.Queries
	auth       *auth.Service
	appBaseURL string
}

func NewService(pool *pgxpool.Pool, authSvc *auth.Service, appBaseURL string) *Service {
	return &Service{
		pool:       pool,
		q:          dbgen.New(pool),
		auth:       authSvc,
		appBaseURL: strings.TrimRight(appBaseURL, "/"),
	}
}

func (s *Service) Pool() *pgxpool.Pool { return s.pool }

// toConnection maps a sqlc-generated row to the API-facing Connection type.
func toConnection(r dbgen.TenantSamlConnection) *Connection {
	var lastLogin *time.Time
	if r.LastLoginAt.Valid {
		v := r.LastLoginAt.Time
		lastLogin = &v
	}
	return &Connection{
		ID:             r.ID,
		TenantID:       r.TenantID,
		Name:           r.Name,
		IdpEntityID:    r.IdpEntityID,
		IdpSSOURL:      r.IdpSsoUrl,
		IdpCertificate: r.IdpCertificate,
		EmailAttribute: r.EmailAttribute,
		NameAttribute:  r.NameAttribute,
		Status:         r.Status,
		CreatedAt:      r.CreatedAt,
		UpdatedAt:      r.UpdatedAt,
		LastLoginAt:    lastLogin,
	}
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
	row, err := s.q.WithTx(tx).InsertSamlConnection(ctx, dbgen.InsertSamlConnectionParams{
		TenantID:       tenantID,
		Name:           in.Name,
		IdpEntityID:    in.IdpEntityID,
		IdpSsoUrl:      in.IdpSSOURL,
		IdpCertificate: in.IdpCertificate,
		EmailAttribute: in.EmailAttribute,
		NameAttribute:  in.NameAttribute,
		Status:         status,
	})
	if err != nil {
		return nil, err
	}
	return toConnection(row), nil
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Connection, error) {
	rows, err := s.q.ListSamlConnections(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Connection, len(rows))
	for i, r := range rows {
		out[i] = *toConnection(r)
	}
	return out, nil
}

func (s *Service) Get(ctx context.Context, id, tenantID uuid.UUID) (*Connection, error) {
	r, err := s.q.GetSamlConnection(ctx, dbgen.GetSamlConnectionParams{ID: id, TenantID: tenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return toConnection(r), nil
}

// getByID loads a connection without tenant scoping — used by the public SSO
// endpoints, where the (unguessable) connection UUID in the path is the key.
func (s *Service) getByID(ctx context.Context, id uuid.UUID) (*Connection, error) {
	r, err := s.q.GetSamlConnectionByID(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return toConnection(r), nil
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
	r, err := s.q.WithTx(tx).UpdateSamlConnection(ctx, dbgen.UpdateSamlConnectionParams{
		ID:             id,
		TenantID:       tenantID,
		Name:           in.Name,
		IdpEntityID:    in.IdpEntityID,
		IdpSsoUrl:      in.IdpSSOURL,
		IdpCertificate: in.IdpCertificate,
		EmailAttribute: in.EmailAttribute,
		NameAttribute:  in.NameAttribute,
		Status:         in.Status,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return toConnection(r), nil
}

func (s *Service) Delete(ctx context.Context, tx pgx.Tx, id, tenantID uuid.UUID) error {
	n, err := s.q.WithTx(tx).DeleteSamlConnection(ctx, dbgen.DeleteSamlConnectionParams{ID: id, TenantID: tenantID})
	if err != nil {
		return err
	}
	if n == 0 {
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
	q := s.q.WithTx(tx)

	userID, err := q.GetExternalIdentityUser(ctx, dbgen.GetExternalIdentityUserParams{
		TenantID: tenantID,
		Provider: provider,
		Subject:  subject,
	})
	if err == nil {
		return userID, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, err
	}

	userID, err = q.GetUserByEmail(ctx, email)
	if errors.Is(err, pgx.ErrNoRows) {
		var displayName *string
		if name != "" {
			displayName = &name
		}
		userID, err = q.InsertUserWithEmail(ctx, dbgen.InsertUserWithEmailParams{
			TenantID:    pgtype.UUID{Bytes: tenantID, Valid: true},
			Email:       email,
			DisplayName: displayName,
		})
		if err != nil {
			return uuid.Nil, err
		}
	} else if err != nil {
		return uuid.Nil, err
	}

	if err := q.LinkExternalIdentity(ctx, dbgen.LinkExternalIdentityParams{
		UserID:   userID,
		TenantID: tenantID,
		Provider: provider,
		Subject:  subject,
		Email:    &email,
	}); err != nil {
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
	q := s.q.WithTx(tx)

	row, err := q.ConsumeSamlLoginCode(ctx, codeHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrUnauthorized.WithDetail("invalid code")
	}
	if err != nil {
		return nil, err
	}
	if row.UsedAt.Valid {
		return nil, errs.ErrUnauthorized.WithDetail("code already used")
	}
	if time.Now().After(row.ExpiresAt) {
		return nil, errs.ErrUnauthorized.WithDetail("code expired")
	}
	if err := q.MarkSamlLoginCodeUsed(ctx, codeHash); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.auth.IssuePair(ctx, row.UserID, row.TenantID, ip, ua, provider)
}

// insertLoginCode persists a one-time code issued at the ACS endpoint.
func (s *Service) insertLoginCode(ctx context.Context, codeHash string, userID, tenantID uuid.UUID, expiresAt time.Time) error {
	return s.q.InsertSamlLoginCode(ctx, dbgen.InsertSamlLoginCodeParams{
		CodeHash:  codeHash,
		UserID:    userID,
		TenantID:  tenantID,
		ExpiresAt: expiresAt,
	})
}

// touchLastLogin stamps last_login_at on the SP connection after a successful
// ACS assertion. Fire-and-forget.
func (s *Service) touchLastLogin(ctx context.Context, connID uuid.UUID) {
	_ = s.q.TouchSamlLastLogin(ctx, connID)
}

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
	if err := h.Service.insertLoginCode(ctx, codeHash, userID, conn.TenantID, time.Now().UTC().Add(loginCodeTTL)); err != nil {
		slog.Error("saml acs: persist login code", "err", err)
		httpx.WriteError(w, r, errs.ErrInternal)
		return
	}
	h.Service.touchLastLogin(ctx, conn.ID)

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

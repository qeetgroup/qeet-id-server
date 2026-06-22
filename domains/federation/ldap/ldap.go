// Package ldap bridges on-prem Active Directory / LDAPv3 directories. A user
// authenticates with username + password: Qeet ID binds with the connection's
// service account, searches for the user under the base DN, then re-binds as
// that user's DN to verify the password — JIT-provisioning a Qeet ID user and
// issuing a session on success.
//
// Surfaces:
//   - Admin  (/v1/tenants/{id}/ldap, user-JWT): connection CRUD + test bind.
//   - Public (/ldap/{id}/authenticate, no JWT): username/password login.
package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	goldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id/domains/access/authentication"
	"github.com/qeetgroup/qeet-id/domains/operations/audit"
	"github.com/qeetgroup/qeet-id/platform/errs"
	"github.com/qeetgroup/qeet-id/platform/httpx"
)

const (
	provider    = "ldap"
	dialTimeout = 6 * time.Second
)

// Connection is the API-facing view — bind_password is deliberately omitted.
type Connection struct {
	ID             uuid.UUID  `json:"id"`
	TenantID       uuid.UUID  `json:"tenant_id"`
	Name           string     `json:"name"`
	ServerURL      string     `json:"server_url"`
	StartTLS       bool       `json:"start_tls"`
	SkipTLSVerify  bool       `json:"skip_tls_verify"`
	BindDN         string     `json:"bind_dn"`
	BaseDN         string     `json:"base_dn"`
	UserFilter     string     `json:"user_filter"`
	EmailAttribute string     `json:"email_attribute"`
	NameAttribute  string     `json:"name_attribute"`
	Status         string     `json:"status"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	LastLoginAt    *time.Time `json:"last_login_at"`
}

// connFull adds the service-account secret needed to dial; never serialised.
type connFull struct {
	Connection
	BindPassword string
}

type Service struct {
	pool *pgxpool.Pool
	auth *auth.Service
}

func NewService(pool *pgxpool.Pool, authSvc *auth.Service) *Service {
	return &Service{pool: pool, auth: authSvc}
}

func (s *Service) Pool() *pgxpool.Pool { return s.pool }

const pubCols = `id, tenant_id, name, server_url, start_tls, skip_tls_verify, bind_dn,
                 base_dn, user_filter, email_attribute, name_attribute, status,
                 created_at, updated_at, last_login_at`

func scanConn(row pgx.Row) (*Connection, error) {
	var c Connection
	if err := row.Scan(&c.ID, &c.TenantID, &c.Name, &c.ServerURL, &c.StartTLS, &c.SkipTLSVerify,
		&c.BindDN, &c.BaseDN, &c.UserFilter, &c.EmailAttribute, &c.NameAttribute, &c.Status,
		&c.CreatedAt, &c.UpdatedAt, &c.LastLoginAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrNotFound
		}
		return nil, err
	}
	return &c, nil
}

type CreateInput struct {
	Name           string `json:"name"`
	ServerURL      string `json:"server_url"`
	StartTLS       bool   `json:"start_tls"`
	SkipTLSVerify  bool   `json:"skip_tls_verify"`
	BindDN         string `json:"bind_dn"`
	BindPassword   string `json:"bind_password"`
	BaseDN         string `json:"base_dn"`
	UserFilter     string `json:"user_filter"`
	EmailAttribute string `json:"email_attribute"`
	NameAttribute  string `json:"name_attribute"`
	Status         string `json:"status"`
}

func defaulted(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func (s *Service) Create(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, in CreateInput) (*Connection, error) {
	row := tx.QueryRow(ctx, `
		INSERT INTO tenant.ldap_connections
			(tenant_id, name, server_url, start_tls, skip_tls_verify, bind_dn, bind_password,
			 base_dn, user_filter, email_attribute, name_attribute, status)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING `+pubCols,
		tenantID, in.Name, in.ServerURL, in.StartTLS, in.SkipTLSVerify, in.BindDN, in.BindPassword,
		in.BaseDN, defaulted(in.UserFilter, "(uid=%s)"), defaulted(in.EmailAttribute, "mail"),
		defaulted(in.NameAttribute, "cn"), defaulted(in.Status, "draft"))
	return scanConn(row)
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Connection, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+pubCols+` FROM tenant.ldap_connections WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Connection
	for rows.Next() {
		var c Connection
		if err := rows.Scan(&c.ID, &c.TenantID, &c.Name, &c.ServerURL, &c.StartTLS, &c.SkipTLSVerify,
			&c.BindDN, &c.BaseDN, &c.UserFilter, &c.EmailAttribute, &c.NameAttribute, &c.Status,
			&c.CreatedAt, &c.UpdatedAt, &c.LastLoginAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Service) Get(ctx context.Context, id, tenantID uuid.UUID) (*Connection, error) {
	return scanConn(s.pool.QueryRow(ctx, `SELECT `+pubCols+` FROM tenant.ldap_connections WHERE id = $1 AND tenant_id = $2`, id, tenantID))
}

// getFull loads a connection including its bind secret. tenantID may be uuid.Nil
// to skip tenant scoping (the public authenticate path keys off the connection
// UUID in the URL).
func (s *Service) getFull(ctx context.Context, id, tenantID uuid.UUID) (*connFull, error) {
	q := `SELECT ` + pubCols + `, bind_password FROM tenant.ldap_connections WHERE id = $1`
	args := []any{id}
	if tenantID != uuid.Nil {
		q += ` AND tenant_id = $2`
		args = append(args, tenantID)
	}
	var c connFull
	err := s.pool.QueryRow(ctx, q, args...).Scan(&c.ID, &c.TenantID, &c.Name, &c.ServerURL, &c.StartTLS,
		&c.SkipTLSVerify, &c.BindDN, &c.BaseDN, &c.UserFilter, &c.EmailAttribute, &c.NameAttribute,
		&c.Status, &c.CreatedAt, &c.UpdatedAt, &c.LastLoginAt, &c.BindPassword)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

type UpdateInput struct {
	Name           *string `json:"name"`
	ServerURL      *string `json:"server_url"`
	StartTLS       *bool   `json:"start_tls"`
	SkipTLSVerify  *bool   `json:"skip_tls_verify"`
	BindDN         *string `json:"bind_dn"`
	BindPassword   *string `json:"bind_password"`
	BaseDN         *string `json:"base_dn"`
	UserFilter     *string `json:"user_filter"`
	EmailAttribute *string `json:"email_attribute"`
	NameAttribute  *string `json:"name_attribute"`
	Status         *string `json:"status"`
}

func (s *Service) Update(ctx context.Context, tx pgx.Tx, id, tenantID uuid.UUID, in UpdateInput) (*Connection, error) {
	row := tx.QueryRow(ctx, `
		UPDATE tenant.ldap_connections SET
			name            = COALESCE($3, name),
			server_url      = COALESCE($4, server_url),
			start_tls       = COALESCE($5, start_tls),
			skip_tls_verify = COALESCE($6, skip_tls_verify),
			bind_dn         = COALESCE($7, bind_dn),
			bind_password   = COALESCE($8, bind_password),
			base_dn         = COALESCE($9, base_dn),
			user_filter     = COALESCE($10, user_filter),
			email_attribute = COALESCE($11, email_attribute),
			name_attribute  = COALESCE($12, name_attribute),
			status          = COALESCE($13, status),
			updated_at      = NOW()
		WHERE id = $1 AND tenant_id = $2
		RETURNING `+pubCols,
		id, tenantID, in.Name, in.ServerURL, in.StartTLS, in.SkipTLSVerify, in.BindDN, in.BindPassword,
		in.BaseDN, in.UserFilter, in.EmailAttribute, in.NameAttribute, in.Status)
	return scanConn(row)
}

func (s *Service) Delete(ctx context.Context, tx pgx.Tx, id, tenantID uuid.UUID) error {
	ct, err := tx.Exec(ctx, `DELETE FROM tenant.ldap_connections WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errs.ErrNotFound
	}
	return nil
}

// --- LDAP protocol ---

func (c *connFull) tlsConfig() *tls.Config {
	cfg := &tls.Config{InsecureSkipVerify: c.SkipTLSVerify} //nolint:gosec // operator opt-in for self-signed labs
	if host := hostOnly(c.ServerURL); host != "" {
		cfg.ServerName = host
	}
	return cfg
}

func hostOnly(serverURL string) string {
	u, err := url.Parse(serverURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// dial opens a connection, applying LDAPS or StartTLS as configured.
func (c *connFull) dial() (*goldap.Conn, error) {
	conn, err := goldap.DialURL(c.ServerURL, goldap.DialWithDialer(&net.Dialer{Timeout: dialTimeout}), goldap.DialWithTLSConfig(c.tlsConfig()))
	if err != nil {
		return nil, err
	}
	if c.StartTLS && strings.HasPrefix(strings.ToLower(c.ServerURL), "ldap://") {
		if err := conn.StartTLS(c.tlsConfig()); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

// TestBind dials and binds with the service account — proving the connection
// settings are correct without authenticating any end user.
func (s *Service) TestBind(c *connFull) error {
	conn, err := c.dial()
	if err != nil {
		return errs.ErrUnprocessable.WithDetail("dial failed: " + err.Error())
	}
	defer conn.Close()
	if err := conn.Bind(c.BindDN, c.BindPassword); err != nil {
		return errs.ErrUnprocessable.WithDetail("service-account bind failed")
	}
	return nil
}

type ldapUser struct {
	DN    string
	Email string
	Name  string
}

// authenticate binds the service account, finds the user, then verifies the
// password by binding as the user's DN. Returns the resolved directory user.
func (s *Service) authenticate(c *connFull, username, password string) (*ldapUser, error) {
	if username == "" || password == "" {
		return nil, errs.ErrBadRequest.WithDetail("username and password required")
	}
	conn, err := c.dial()
	if err != nil {
		return nil, errs.ErrUnprocessable.WithDetail("directory unreachable")
	}
	defer conn.Close()

	if err := conn.Bind(c.BindDN, c.BindPassword); err != nil {
		return nil, errs.ErrUnprocessable.WithDetail("service-account bind failed")
	}

	filter := strings.ReplaceAll(c.UserFilter, "%s", goldap.EscapeFilter(username))
	req := goldap.NewSearchRequest(
		c.BaseDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, 2, int(dialTimeout.Seconds()), false,
		filter, []string{c.EmailAttribute, c.NameAttribute}, nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, errs.ErrUnauthorized.WithDetail("invalid credentials")
	}
	if len(res.Entries) != 1 {
		// Zero or ambiguous match — don't reveal which.
		return nil, errs.ErrUnauthorized.WithDetail("invalid credentials")
	}
	entry := res.Entries[0]

	// Verify the password by binding as the user. A fresh conn keeps the
	// service-account binding intact and side-steps connection-state quirks.
	userConn, err := c.dial()
	if err != nil {
		return nil, errs.ErrUnprocessable.WithDetail("directory unreachable")
	}
	defer userConn.Close()
	if err := userConn.Bind(entry.DN, password); err != nil {
		return nil, errs.ErrUnauthorized.WithDetail("invalid credentials")
	}

	email := strings.ToLower(strings.TrimSpace(entry.GetAttributeValue(c.EmailAttribute)))
	if email == "" {
		return nil, errs.ErrUnprocessable.WithDetail("directory entry has no email attribute")
	}
	return &ldapUser{DN: entry.DN, Email: email, Name: entry.GetAttributeValue(c.NameAttribute)}, nil
}

// findOrCreateUser links the directory DN to a user (by linked identity, then
// globally-unique email) or provisions a new one. Mirrors social/saml.
func (s *Service) findOrCreateUser(ctx context.Context, tenantID uuid.UUID, u *ldapUser) (uuid.UUID, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)

	var userID uuid.UUID
	err = tx.QueryRow(ctx, `
		SELECT user_id FROM "user".external_identities
		WHERE tenant_id = $1 AND provider = $2 AND subject = $3
	`, tenantID, provider, u.DN).Scan(&userID)
	if err == nil {
		return userID, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, err
	}

	err = tx.QueryRow(ctx, `
		SELECT id FROM "user".users WHERE LOWER(email) = LOWER($1) AND deleted_at IS NULL
	`, u.Email).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		var displayName any
		if u.Name != "" {
			displayName = u.Name
		}
		if err := tx.QueryRow(ctx, `
			INSERT INTO "user".users (tenant_id, email, email_verified_at, display_name, status)
			VALUES ($1, $2, NOW(), $3, 'active')
			RETURNING id
		`, tenantID, u.Email, displayName).Scan(&userID); err != nil {
			return uuid.Nil, err
		}
	} else if err != nil {
		return uuid.Nil, err
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO "user".external_identities (user_id, tenant_id, provider, subject, email)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, provider, subject) DO NOTHING
	`, userID, tenantID, provider, u.DN, u.Email); err != nil {
		return uuid.Nil, err
	}
	return userID, tx.Commit(ctx)
}

// Login runs the full directory authentication and issues a token pair.
func (s *Service) Login(ctx context.Context, connID uuid.UUID, username, password, ip, ua string) (*auth.TokenPair, error) {
	c, err := s.getFull(ctx, connID, uuid.Nil)
	if err != nil {
		return nil, err
	}
	if c.Status == "disabled" {
		return nil, errs.ErrForbidden.WithDetail("connection disabled")
	}
	du, err := s.authenticate(c, username, password)
	if err != nil {
		return nil, err
	}
	userID, err := s.findOrCreateUser(ctx, c.TenantID, du)
	if err != nil {
		return nil, err
	}
	_, _ = s.pool.Exec(ctx, `UPDATE tenant.ldap_connections SET last_login_at = NOW() WHERE id = $1`, connID)
	return s.auth.IssuePair(ctx, userID, c.TenantID, ip, ua, provider)
}

// =====================================================================
// Handler
// =====================================================================

type Handler struct {
	Service *Service
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/ldap", h.list)
	r.Post("/tenants/{tenantID}/ldap", h.create)
	r.Get("/tenants/{tenantID}/ldap/{id}", h.get)
	r.Patch("/tenants/{tenantID}/ldap/{id}", h.update)
	r.Delete("/tenants/{tenantID}/ldap/{id}", h.del)
	r.Post("/tenants/{tenantID}/ldap/{id}/test", h.test)
}

func (h *Handler) MountPublic(r chi.Router) {
	r.Post("/ldap/{id}/authenticate", h.authenticateHTTP)
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
		ResourceType: "ldap_connection",
		ResourceID:   &rid,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     meta,
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
	in.ServerURL = strings.TrimSpace(in.ServerURL)
	if in.Name == "" || in.ServerURL == "" || strings.TrimSpace(in.BindDN) == "" ||
		in.BindPassword == "" || strings.TrimSpace(in.BaseDN) == "" {
		httpx.WriteError(w, r, errs.ErrUnprocessable.WithDetail("name, server_url, bind_dn, bind_password and base_dn are required"))
		return
	}
	if !strings.HasPrefix(strings.ToLower(in.ServerURL), "ldap://") && !strings.HasPrefix(strings.ToLower(in.ServerURL), "ldaps://") {
		httpx.WriteError(w, r, errs.ErrUnprocessable.WithDetail("server_url must start with ldap:// or ldaps://"))
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
	if err := h.recordAudit(ctx, tx, r, tenantID, conn.ID, "ldap.connection_created", map[string]any{"name": conn.Name, "server": conn.ServerURL}); err != nil {
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
	if err := h.recordAudit(ctx, tx, r, tenantID, conn.ID, "ldap.connection_updated", map[string]any{"status": conn.Status}); err != nil {
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
	if err := h.recordAudit(ctx, tx, r, tenantID, id, "ldap.connection_deleted", nil); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

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
	c, err := h.Service.getFull(r.Context(), id, tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.TestBind(c); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (h *Handler) authenticateHTTP(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	pair, err := h.Service.Login(r.Context(), id, body.Username, body.Password, httpx.ClientIP(r), r.UserAgent())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, pair)
}

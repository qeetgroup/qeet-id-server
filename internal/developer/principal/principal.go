// Package principal manages OAuth-style service principals — non-human
// callers that authenticate via client_credentials grant and receive a
// short-lived service JWT scoped to a single organization.
package principal

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/developer/principal/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Service manages the service principals.
type Service struct {
	pool   *pgxpool.Pool
	q      *dbgen.Queries
	issuer *tokens.Issuer
}

// NewService returns the service-principal Service.
func NewService(pool *pgxpool.Pool, issuer *tokens.Issuer) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), issuer: issuer}
}

// Pool returns the connection pool, for handlers that run their own transaction.
func (s *Service) Pool() *pgxpool.Pool { return s.pool }

// tsPtr converts a pgtype.Timestamptz to *time.Time (nil when not valid).
func tsPtr(p pgtype.Timestamptz) *time.Time {
	if !p.Valid {
		return nil
	}
	t := p.Time
	return &t
}

// Principal is a service principal, without its secret. LastUsedAt is when it
// was last issued a token, to the minute; PreviousSecretExpiresAt, when the
// secret it replaced at its last rotation stops working.
type Principal struct {
	ID                      uuid.UUID  `json:"id"`
	OrganizationID          uuid.UUID  `json:"tenant_id"`
	Name                    string     `json:"name"`
	Description             string     `json:"description"`
	Scopes                  []string   `json:"scopes"`
	DisabledAt              *time.Time `json:"disabled_at"`
	LastUsedAt              *time.Time `json:"last_used_at"`
	PreviousSecretExpiresAt *time.Time `json:"previous_secret_expires_at,omitempty"`
	CreatedAt               time.Time  `json:"created_at"`
}

// CreateInput is what Create takes.
type CreateInput struct {
	OrganizationID uuid.UUID `json:"tenant_id"`
	Name           string    `json:"name"`
	Description    string    `json:"description"`
	Scopes         []string  `json:"scopes"`
}

// Create adds a service principal and returns it with its plaintext secret,
// shown only now.
func (s *Service) Create(ctx context.Context, tx pgx.Tx, in CreateInput) (*Principal, string, error) {
	if err := rbac.ValidateMachineScopes(in.Scopes); err != nil {
		return nil, "", err
	}
	raw, _, err := codes.URLToken()
	if err != nil {
		return nil, "", err
	}
	hash := password.HashSecret(raw)
	row, err := s.q.WithTx(tx).CreateServicePrincipal(ctx, dbgen.CreateServicePrincipalParams{
		OrganizationID: in.OrganizationID,
		Name:           in.Name,
		Description:    in.Description,
		SecretHash:     hash,
		Scopes:         in.Scopes,
		CreatedBy:      httpx.PrincipalUserID(ctx),
	})
	if err != nil {
		return nil, "", err
	}
	p := &Principal{
		ID: row.ID, OrganizationID: row.OrganizationID, Name: row.Name, Description: row.Description,
		Scopes: row.Scopes, DisabledAt: tsPtr(row.DisabledAt), CreatedAt: row.CreatedAt,
	}
	return p, raw, nil
}

// List returns the organization's service principals.
func (s *Service) List(ctx context.Context, organizationID uuid.UUID) ([]Principal, error) {
	rows, err := s.q.ListServicePrincipals(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]Principal, 0, len(rows))
	for _, row := range rows {
		p := Principal{
			ID: row.ID, OrganizationID: row.OrganizationID, Name: row.Name, Description: row.Description,
			Scopes: row.Scopes, DisabledAt: tsPtr(row.DisabledAt), LastUsedAt: tsPtr(row.LastUsedAt), CreatedAt: row.CreatedAt,
		}
		if until := tsPtr(row.PreviousSecretExpiresAt); until != nil && until.After(time.Now()) {
			p.PreviousSecretExpiresAt = until
		}
		out = append(out, p)
	}
	return out, nil
}

// PrincipalLive reports whether service principal id exists and isn't
// disabled.
func (s *Service) PrincipalLive(ctx context.Context, id uuid.UUID) (bool, error) {
	live, err := s.q.PrincipalLive(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return live, err
}

// Disable marks a service principal disabled. Returns the (organizationID,
// name) for the audit row so the caller doesn't have to re-query.
func (s *Service) Disable(ctx context.Context, tx pgx.Tx, organizationID, id uuid.UUID) (uuid.UUID, string, error) {
	row, err := s.q.WithTx(tx).DisableServicePrincipal(ctx, dbgen.DisableServicePrincipalParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, "", errs.ErrPrincipalNotFound
	}
	if err != nil {
		return uuid.Nil, "", err
	}
	return row.OrganizationID, row.Name, nil
}

// TokenResponse is a client-credentials token. ExpiresIn is the RFC 6749
// lifetime in seconds, which OAuth clients read; ExpiresAt is the same moment.
type TokenResponse struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresIn   int64     `json:"expires_in"`
	ExpiresAt   time.Time `json:"expires_at"`
	Scope       string    `json:"scope"`
}

// IssueClientCredentials verifies (client_id, client_secret) and returns
// a service JWT signed with the platform issuer's secret.
func (s *Service) IssueClientCredentials(ctx context.Context, clientID, clientSecret string) (*TokenResponse, error) {
	pid, err := uuid.Parse(clientID)
	if err != nil {
		return nil, errs.ErrPrincipalInvalidCredentials
	}
	row, err := s.q.GetServicePrincipalForAuth(ctx, pid)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrPrincipalInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	// The secret first, so only its holder learns that it is disabled.
	ok, rehash, err := password.VerifySecret(ctx, row.SecretHash, clientSecret)
	if err != nil {
		return nil, err
	}
	if !ok {
		previous, err := previousSecretWorks(ctx, row.PreviousSecretHash, row.PreviousSecretExpiresAt, clientSecret)
		if err != nil {
			return nil, err
		}
		if !previous {
			return nil, errs.ErrPrincipalInvalidCredentials
		}
		rehash = false
	}
	if rehash {
		if err := s.q.UpgradeServicePrincipalSecretHash(ctx, dbgen.UpgradeServicePrincipalSecretHashParams{
			NewHash: password.HashSecret(clientSecret), ID: row.ID, OrganizationID: row.OrganizationID, OldHash: row.SecretHash,
		}); err != nil {
			slog.Warn("service principal hash upgrade failed", "err", err, "principal_id", row.ID)
		}
	}
	if row.DisabledAt.Valid {
		return nil, errs.ErrPrincipalDisabled
	}
	if err := s.q.TouchServicePrincipal(ctx, dbgen.TouchServicePrincipalParams{ID: row.ID, OrganizationID: row.OrganizationID}); err != nil {
		slog.Warn("service principal last use not recorded", "err", err, "principal_id", row.ID)
	}
	id, organizationID, scopes := row.ID, row.OrganizationID, row.Scopes
	now := time.Now().UTC()
	exp := now.Add(s.issuer.AccessTTL())
	scope := joinScopes(scopes)

	// Reuse the platform issuer secret/issuer/audience for compatibility
	// with the same verifier the user endpoints use. ActorType comes from
	// a custom claim so the verifier can distinguish.
	type svcClaims struct {
		OrganizationID uuid.UUID `json:"tenant_id"`
		Scope          string    `json:"scope,omitempty"`
		ActorType      string    `json:"actor_type"`
		jwt.RegisteredClaims
	}
	claims := svcClaims{
		OrganizationID: organizationID,
		Scope:          scope,
		ActorType:      "service",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer.JWTIssuer(),
			Audience:  jwt.ClaimStrings{s.issuer.JWTAudience()},
			Subject:   id.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        uuid.NewString(),
		},
	}
	signed, err := s.issuer.Sign(claims)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return &TokenResponse{
		AccessToken: signed,
		TokenType:   "Bearer",
		ExpiresIn:   int64(exp.Sub(now).Seconds()),
		ExpiresAt:   exp,
		Scope:       scope,
	}, nil
}

func joinScopes(in []string) string {
	out := ""
	for i, s := range in {
		if i > 0 {
			out += " "
		}
		out += s
	}
	return out
}

// Handler serves the service principal HTTP API.
type Handler struct {
	Service *Service
	// GrantCheck refuses a credential carrying a scope the caller doesn't hold
	// (rbac.Repository.CheckGrantScopes). Without it creating one is refused.
	GrantCheck func(ctx context.Context, caller *httpx.Principal, organizationID uuid.UUID, scopes []string) error
}

// Mount registers the service principal routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Post("/service-principals", h.create)
	r.Get("/tenants/{tenantID}/service-principals", h.list)
	r.Delete("/service-principals/{id}", h.disable)
	r.Post("/tenants/{tenantID}/service-principals/{id}/rotate-secret", h.rotateSecret)
	r.Post("/tenants/{tenantID}/service-principals/{id}/enable", h.enable)
}

// MountToken registers the client-credentials token endpoint, which the router
// rate-limits as machine traffic.
func (h *Handler) MountToken(r chi.Router) {
	r.Post("/oauth/token", h.tokenEndpoint)
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in CreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in.OrganizationID = tid
	if h.GrantCheck == nil {
		httpx.WriteError(w, r, errs.ErrNotImplemented)
		return
	}
	if err := h.GrantCheck(r.Context(), httpx.PrincipalFromCtx(r.Context()), tid, in.Scopes); err != nil {
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
	p, secret, err := h.Service.Create(ctx, tx, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := audit.ActorOf(r).Identity()
	organizationID := p.OrganizationID
	resID := p.ID
	if err := audit.Record(ctx, tx, audit.Event{
		OrganizationID: &organizationID,
		ActorUserID:    actorID,
		ActorType:      actorType,
		Action:         "service_principal.created",
		ResourceType:   "service_principal",
		ResourceID:     &resID,
		IP:             httpx.ClientIP(r),
		UserAgent:      r.UserAgent(),
		RequestID:      httpx.RequestID(r),
		Metadata:       map[string]any{"name": p.Name, "scopes": p.Scopes},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"service_principal": p,
		"client_id":         p.ID,
		"client_secret":     secret,
		"warning":           "secret shown once",
	})
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrPrincipalInvalidID)
		return
	}
	out, err := h.Service.List(r.Context(), tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) disable(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrPrincipalInvalidID)
		return
	}
	callerOrganization, err := httpx.RequireOrganization(r)
	if err != nil {
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
	organizationID, name, err := h.Service.Disable(ctx, tx, callerOrganization, id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := audit.ActorOf(r).Identity()
	resID := id
	if err := audit.Record(ctx, tx, audit.Event{
		OrganizationID: &organizationID,
		ActorUserID:    actorID,
		ActorType:      actorType,
		Action:         "service_principal.disabled",
		ResourceType:   "service_principal",
		ResourceID:     &resID,
		IP:             httpx.ClientIP(r),
		UserAgent:      r.UserAgent(),
		RequestID:      httpx.RequestID(r),
		Metadata:       map[string]any{"name": name},
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

// tokenEndpoint implements RFC 6749 client_credentials grant. Form-encoded
// per spec, accepts grant_type=client_credentials with client_id and
// client_secret either in the body or in Basic auth.
func (h *Handler) tokenEndpoint(w http.ResponseWriter, r *http.Request) {
	if err := httpx.ParseForm(r, httpx.MaxFormBodyBytes); err != nil {
		writeTokenError(w, r, err)
		return
	}
	switch r.Form.Get("grant_type") {
	case "client_credentials":
	case "":
		writeTokenError(w, r, errs.ErrBadRequest.WithMessage("grant_type is required."))
		return
	default:
		writeTokenError(w, r, errs.ErrPrincipalGrantUnsupported)
		return
	}
	clientID := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")
	if u, p, ok := httpx.ClientBasicAuth(r); ok {
		clientID, clientSecret = u, p
	}
	if clientID == "" || clientSecret == "" {
		writeTokenError(w, r, errs.ErrPrincipalInvalidCredentials)
		return
	}
	resp, err := h.Service.IssueClientCredentials(r.Context(), clientID, clientSecret)
	if err != nil {
		writeTokenError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// writeTokenError answers a failed token request in the RFC 6749 §5.2 shape:
// invalid_client is 401, with a Basic challenge when the client sent Basic
// credentials, and every other code 400. An internal error keeps the generic
// answer.
func writeTokenError(w http.ResponseWriter, r *http.Request, err error) {
	e := errs.As(err)
	if e == nil || e.Code == errs.CodeInternal {
		httpx.WriteError(w, r, err)
		return
	}
	code, status := "invalid_request", http.StatusBadRequest
	switch e.Code {
	case errs.CodePrincipalInvalidCredentials:
		code, status = "invalid_client", http.StatusUnauthorized
		if _, _, basic := r.BasicAuth(); basic {
			w.Header().Set("WWW-Authenticate", `Basic realm="qeet"`)
		}
	case errs.CodePrincipalDisabled:
		code = "unauthorized_client"
	case errs.CodePrincipalGrantUnsupported:
		code = "unsupported_grant_type"
	}
	httpx.WriteJSON(w, status, map[string]string{"error": code, "error_description": e.Message})
}

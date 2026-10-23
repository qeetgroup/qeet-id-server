// Package vc issues and verifies W3C Verifiable Credentials in the JWT
// serialization (JWT-VC): ES256-signed by the platform issuer (verifiable via the
// same JWKS), tracked in auth.credentials for listing/revocation. Verification
// checks signature + issuer + expiry, then the revocation registry.
package vc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/vc/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

const vcContext = "https://www.w3.org/ns/credentials/v2"

type Service struct {
	pool   *pgxpool.Pool
	q      *dbgen.Queries
	issuer *tokens.Issuer
}

func NewService(pool *pgxpool.Pool, issuer *tokens.Issuer) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), issuer: issuer}
}

type Credential struct {
	ID        uuid.UUID  `json:"id"`
	Subject   string     `json:"subject"`
	Type      string     `json:"type"`
	IssuedAt  time.Time  `json:"issued_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Revoked   bool       `json:"revoked"`
}

type IssueResult struct {
	CredentialID uuid.UUID  `json:"credential_id"`
	JWT          string     `json:"jwt"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

// pgtTS converts a *time.Time to pgtype.Timestamptz (null when nil).
func pgtTS(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: *t, Valid: true}
}

// tsPtr converts a pgtype.Timestamptz to *time.Time (nil when not valid).
func tsPtr(p pgtype.Timestamptz) *time.Time {
	if !p.Valid {
		return nil
	}
	t := p.Time
	return &t
}

// Issue records a credential and returns its signed JWT-VC. ttlSeconds <= 0
// issues a non-expiring credential.
func (s *Service) Issue(ctx context.Context, tenantID uuid.UUID, subject, credType string, claims map[string]any, ttlSeconds int) (*IssueResult, error) {
	return s.IssueWithActor(ctx, tenantID, subject, credType, claims, ttlSeconds, audit.Actor{Type: "system"})
}

func (s *Service) IssueWithActor(ctx context.Context, tenantID uuid.UUID, subject, credType string, claims map[string]any, ttlSeconds int, actor audit.Actor) (*IssueResult, error) {
	subject = strings.TrimSpace(subject)
	credType = strings.TrimSpace(credType)
	if subject == "" || credType == "" {
		return nil, errs.ErrVCSubjectTypeRequired
	}
	if claims == nil {
		claims = map[string]any{}
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return nil, errs.ErrVCClaimsInvalid
	}
	now := time.Now().UTC()
	var expiresAt *time.Time
	if ttlSeconds > 0 {
		e := now.Add(time.Duration(ttlSeconds) * time.Second)
		expiresAt = &e
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	row, err := s.q.WithTx(tx).CreateCredential(ctx, dbgen.CreateCredentialParams{
		TenantID:  tenantID,
		Subject:   subject,
		Type:      credType,
		Claims:    claimsJSON,
		ExpiresAt: pgtTS(expiresAt),
	})
	if err != nil {
		return nil, err
	}
	id, issuedAt := row.ID, row.IssuedAt

	// credentialSubject = { id: <subject>, ...claims }.
	subjectObj := map[string]any{"id": subject}
	for k, v := range claims {
		if k != "id" {
			subjectObj[k] = v
		}
	}
	reg := jwt.RegisteredClaims{
		Issuer:    s.issuer.JWTIssuer(),
		Subject:   subject,
		ID:        id.String(), // jti — the revocation key
		IssuedAt:  jwt.NewNumericDate(issuedAt),
		NotBefore: jwt.NewNumericDate(issuedAt),
	}
	if expiresAt != nil {
		reg.ExpiresAt = jwt.NewNumericDate(*expiresAt)
	}
	type vcClaims struct {
		VC map[string]any `json:"vc"`
		jwt.RegisteredClaims
	}
	signed, err := s.issuer.Sign(vcClaims{
		VC: map[string]any{
			"@context":          []string{vcContext},
			"type":              []string{"VerifiableCredential", credType},
			"issuer":            s.issuer.JWTIssuer(),
			"credentialSubject": subjectObj,
		},
		RegisteredClaims: reg,
	})
	if err != nil {
		return nil, err
	}
	result := &IssueResult{CredentialID: id, JWT: signed, ExpiresAt: expiresAt}
	metadata := map[string]any{"subject": subject, "type": credType, "expires_at": expiresAt}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "credential.issued", "credential", id, metadata)); err != nil {
		return nil, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: id, Topic: "credential.events", EventType: "credential.issued", Payload: map[string]any{"credential_id": id, "tenant_id": tenantID, "subject": subject, "type": credType, "expires_at": expiresAt}}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return result, nil
}

type VerifyResult struct {
	Valid   bool           `json:"valid"`
	Reason  string         `json:"reason,omitempty"`
	Subject string         `json:"subject,omitempty"`
	Issuer  string         `json:"issuer,omitempty"`
	VC      map[string]any `json:"vc,omitempty"`
}

// Verify checks a presented JWT-VC: signature + issuer + expiry (cryptographic)
// then the revocation registry. Only verifies credentials this server issued.
func (s *Service) Verify(ctx context.Context, raw string) (*VerifyResult, error) {
	claims, err := s.issuer.VerifyVC(raw)
	if errors.Is(err, tokens.ErrNotCredential) {
		return &VerifyResult{Valid: false, Reason: "not a verifiable credential"}, nil
	}
	if err != nil {
		return &VerifyResult{Valid: false, Reason: "signature or expiry invalid"}, nil //nolint:nilerr // an invalid credential is a result, not an error
	}
	res := &VerifyResult{Valid: true}
	if sub, _ := claims["sub"].(string); sub != "" {
		res.Subject = sub
	}
	if iss, _ := claims["iss"].(string); iss != "" {
		res.Issuer = iss
	}
	if vcObj, ok := claims["vc"].(map[string]any); ok {
		res.VC = vcObj
	}
	// jti is the credential's id in the registry. Every credential this server
	// issues has a record, so one without is not ours to vouch for.
	jti, _ := claims["jti"].(string)
	id, err := uuid.Parse(jti)
	if err != nil {
		return &VerifyResult{Valid: false, Reason: "unknown credential"}, nil //nolint:nilerr // an invalid credential is a result, not an error
	}
	revokedAt, err := s.q.GetCredentialRevocation(ctx, id)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return &VerifyResult{Valid: false, Reason: "unknown credential"}, nil
	case err != nil:
		return nil, err
	case revokedAt.Valid:
		return &VerifyResult{Valid: false, Reason: "credential revoked"}, nil
	}
	return res, nil
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Credential, error) {
	rows, err := s.q.ListCredentials(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]Credential, 0, len(rows))
	for _, row := range rows {
		out = append(out, Credential{
			ID:        row.ID,
			Subject:   row.Subject,
			Type:      row.Type,
			IssuedAt:  row.IssuedAt,
			ExpiresAt: tsPtr(row.ExpiresAt),
			Revoked:   row.RevokedAt.Valid,
		})
	}
	return out, nil
}

func (s *Service) Revoke(ctx context.Context, id, tenantID uuid.UUID) error {
	return s.RevokeWithActor(ctx, id, tenantID, audit.Actor{Type: "system"})
}

func (s *Service) RevokeWithActor(ctx context.Context, id, tenantID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).RevokeCredential(ctx, dbgen.RevokeCredentialParams{ID: id, TenantID: tenantID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrVCCredentialNotFound
	}
	if err := audit.Record(ctx, tx, actor.Event(tenantID, "credential.revoked", "credential", id, nil)); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: id, Topic: "credential.events", EventType: "credential.revoked", Payload: map[string]any{"credential_id": id, "tenant_id": tenantID}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type Handler struct {
	Service *Service
}

func actorOf(r *http.Request) audit.Actor {
	actor := audit.Actor{Type: "system", IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r)}
	if principal := httpx.PrincipalFromCtx(r.Context()); principal != nil {
		actor.UserID = principal.UserID
		if principal.ActorType != "" {
			actor.Type = principal.ActorType
		}
	}
	return actor
}

// Mount registers tenant-scoped admin endpoints (require a user JWT / API key).
func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/credentials", h.list)
	r.Post("/tenants/{tenantID}/credentials", h.issue)
	r.Post("/tenants/{tenantID}/credentials/{id}/revoke", h.revoke)
}

// MountPublic registers the public verify endpoint — any relying party can
// present a JWT-VC to check it (no session). CSRF-exempt (see router.go).
func (h *Handler) MountPublic(r chi.Router) {
	r.Post("/credentials/verify", h.verify)
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

func (h *Handler) issue(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		Subject    string         `json:"subject"`
		Type       string         `json:"type"`
		Claims     map[string]any `json:"claims"`
		TTLSeconds int            `json:"ttl_seconds"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	res, err := h.Service.IssueWithActor(r.Context(), tenantID, in.Subject, in.Type, in.Claims, in.TTLSeconds, actorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, res)
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
	if err := h.Service.RevokeWithActor(r.Context(), id, tenantID, actorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"revoked": true})
}

func (h *Handler) verify(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Credential string `json:"credential"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if strings.TrimSpace(in.Credential) == "" {
		httpx.WriteError(w, r, errs.ErrVCCredentialRequired)
		return
	}
	res, err := h.Service.Verify(r.Context(), in.Credential)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

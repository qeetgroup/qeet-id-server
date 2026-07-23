// Package vc issues and verifies W3C Verifiable Credentials in the JWT
// serialization (JWT-VC): ES256-signed by the platform issuer (verifiable via the
// same JWKS), tracked in auth.credentials for listing/revocation. Verification
// checks signature + issuer + expiry, then the revocation registry.
package vc

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/developer/credentials/vc/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
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
	subject = strings.TrimSpace(subject)
	credType = strings.TrimSpace(credType)
	if subject == "" || credType == "" {
		return nil, errs.ErrUnprocessable.WithDetail("subject and type are required")
	}
	if claims == nil {
		claims = map[string]any{}
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return nil, errs.ErrUnprocessable.WithDetail("claims must be a JSON object")
	}
	now := time.Now().UTC()
	var expiresAt *time.Time
	if ttlSeconds > 0 {
		e := now.Add(time.Duration(ttlSeconds) * time.Second)
		expiresAt = &e
	}

	row, err := s.q.CreateCredential(ctx, dbgen.CreateCredentialParams{
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
	return &IssueResult{CredentialID: id, JWT: signed, ExpiresAt: expiresAt}, nil
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
	if err != nil {
		return &VerifyResult{Valid: false, Reason: "signature or expiry invalid"}, nil
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
	// Revocation: jti is the credential id. If we have a record and it's
	// revoked, reject. (Absent record → can't disprove; treat as valid.)
	if jti, _ := claims["jti"].(string); jti != "" {
		if id, perr := uuid.Parse(jti); perr == nil {
			revokedAt, qerr := s.q.GetCredentialRevocation(ctx, id)
			if qerr == nil && revokedAt.Valid {
				return &VerifyResult{Valid: false, Reason: "credential revoked"}, nil
			}
		}
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
	n, err := s.q.RevokeCredential(ctx, dbgen.RevokeCredentialParams{ID: id, TenantID: tenantID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

type Handler struct {
	Service *Service
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
	res, err := h.Service.Issue(r.Context(), tenantID, in.Subject, in.Type, in.Claims, in.TTLSeconds)
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
	if err := h.Service.Revoke(r.Context(), id, tenantID); err != nil {
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
		httpx.WriteError(w, r, errs.ErrUnprocessable.WithDetail("credential (JWT) is required"))
		return
	}
	res, err := h.Service.Verify(r.Context(), in.Credential)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

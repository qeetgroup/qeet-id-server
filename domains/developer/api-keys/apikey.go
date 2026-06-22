// Package apikey issues long-lived bearer tokens for programmatic access.
// A key is `<prefix>.<secret>`; we store the prefix (for lookup) and the
// bcrypt hash of the secret. The plaintext is shown to the caller exactly
// once at creation.
package apikey

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id/platform/errs"
	"github.com/qeetgroup/qeet-id/platform/httpx"
	"github.com/qeetgroup/qeet-id/platform/password"
)

type Key struct {
	ID         uuid.UUID  `json:"id"`
	TenantID   uuid.UUID  `json:"tenant_id"`
	UserID     *uuid.UUID `json:"user_id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Scopes     []string   `json:"scopes"`
	ExpiresAt  *time.Time `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
	CreatedAt  time.Time  `json:"created_at"`
}

type Service struct {
	pool *pgxpool.Pool
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool}
}

func generateRaw() (prefix, secret, full string, err error) {
	pb := make([]byte, 6)
	sb := make([]byte, 24)
	if _, err = rand.Read(pb); err != nil {
		return
	}
	if _, err = rand.Read(sb); err != nil {
		return
	}
	prefix = "qk_" + base64.RawURLEncoding.EncodeToString(pb)
	secret = base64.RawURLEncoding.EncodeToString(sb)
	full = prefix + "." + secret
	return
}

type CreateInput struct {
	TenantID  uuid.UUID  `json:"tenant_id" validate:"required"`
	UserID    *uuid.UUID `json:"user_id"`
	Name      string     `json:"name" validate:"required,min=1,max=200"`
	Scopes    []string   `json:"scopes"`
	ExpiresAt *time.Time `json:"expires_at"`
}

func (s *Service) Create(ctx context.Context, in CreateInput) (*Key, string, error) {
	prefix, secret, full, err := generateRaw()
	if err != nil {
		return nil, "", err
	}
	secretHash, err := password.Hash(secret)
	if err != nil {
		return nil, "", err
	}
	// scopes is NOT NULL DEFAULT '{}'; a nil Go slice encodes as SQL NULL, so
	// coalesce to empty for callers that omit it.
	if in.Scopes == nil {
		in.Scopes = []string{}
	}
	var k Key
	err = s.pool.QueryRow(ctx, `
		INSERT INTO auth.api_keys (tenant_id, user_id, name, prefix, key_hash, scopes, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, tenant_id, user_id, name, prefix, scopes, expires_at, last_used_at, revoked_at, created_at
	`, in.TenantID, in.UserID, in.Name, prefix, secretHash, in.Scopes, in.ExpiresAt).
		Scan(&k.ID, &k.TenantID, &k.UserID, &k.Name, &k.Prefix, &k.Scopes, &k.ExpiresAt, &k.LastUsedAt, &k.RevokedAt, &k.CreatedAt)
	if err != nil {
		return nil, "", err
	}
	return &k, full, nil
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Key, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, tenant_id, user_id, name, prefix, scopes, expires_at, last_used_at, revoked_at, created_at
		FROM auth.api_keys
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Key
	for rows.Next() {
		var k Key
		if err := rows.Scan(&k.ID, &k.TenantID, &k.UserID, &k.Name, &k.Prefix, &k.Scopes, &k.ExpiresAt, &k.LastUsedAt, &k.RevokedAt, &k.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

func (s *Service) Revoke(ctx context.Context, id uuid.UUID) error {
	ct, err := s.pool.Exec(ctx, `UPDATE auth.api_keys SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errs.ErrNotFound
	}
	return nil
}

// Verify resolves a presented `<prefix>.<secret>` to its tenant + scopes,
// or returns an error if the key is unknown, expired, or revoked.
func (s *Service) Verify(ctx context.Context, raw string) (*Key, error) {
	parts := strings.SplitN(raw, ".", 2)
	if len(parts) != 2 {
		return nil, errs.ErrUnauthorized.WithDetail("malformed api key")
	}
	prefix, secret := parts[0], parts[1]

	var k Key
	var hash string
	err := s.pool.QueryRow(ctx, `
		SELECT id, tenant_id, user_id, name, prefix, scopes, expires_at, last_used_at, revoked_at, created_at, key_hash
		FROM auth.api_keys
		WHERE prefix = $1 AND revoked_at IS NULL
	`, prefix).Scan(&k.ID, &k.TenantID, &k.UserID, &k.Name, &k.Prefix, &k.Scopes, &k.ExpiresAt, &k.LastUsedAt, &k.RevokedAt, &k.CreatedAt, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrUnauthorized.WithDetail("unknown api key")
	}
	if err != nil {
		return nil, err
	}
	if !password.Verify(hash, secret) {
		return nil, errs.ErrUnauthorized.WithDetail("invalid api key")
	}
	if k.ExpiresAt != nil && time.Now().After(*k.ExpiresAt) {
		return nil, errs.ErrUnauthorized.WithDetail("api key expired")
	}
	// Best-effort, detached from the request but time-bounded so it can't leak.
	go func(id uuid.UUID) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := s.pool.Exec(ctx, `UPDATE auth.api_keys SET last_used_at = NOW() WHERE id = $1`, id); err != nil {
			slog.Warn("apikey last_used_at update failed", "err", err, "api_key_id", id)
		}
	}(k.ID)
	return &k, nil
}

// Middleware authenticates the request if it carries `Authorization:
// ApiKey <raw>`. On success the principal is attached and ActorType is
// "api_key"; on failure we fall through so the next middleware can try.
func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "ApiKey ") {
			raw := strings.TrimSpace(auth[len("ApiKey "):])
			k, err := s.Verify(r.Context(), raw)
			if err != nil {
				httpx.WriteError(w, r, err)
				return
			}
			p := &httpx.Principal{
				ActorType: "api_key",
				Subject:   k.ID.String(),
				Scopes:    k.Scopes,
			}
			tenant := k.TenantID
			p.TenantID = &tenant
			if k.UserID != nil {
				uid := *k.UserID
				p.UserID = &uid
			}
			next.ServeHTTP(w, r.WithContext(httpx.WithPrincipal(r.Context(), p)))
			return
		}
		next.ServeHTTP(w, r)
	})
}

type Handler struct {
	Service *Service
}

func (h *Handler) Mount(r chi.Router) {
	r.Post("/api-keys", h.create)
	r.Get("/tenants/{tenantID}/api-keys", h.list)
	r.Delete("/api-keys/{id}", h.revoke)
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	var in CreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.Name == "" || in.TenantID == uuid.Nil {
		httpx.WriteError(w, r, errs.ErrUnprocessable.WithDetail("tenant_id and name required"))
		return
	}
	k, raw, err := h.Service.Create(r.Context(), in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{
		"api_key": k,
		"secret":  raw,
		"warning": fmt.Sprintf("This secret is only shown once. Store it now."),
	})
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	out, err := h.Service.List(r.Context(), tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid id"))
		return
	}
	if err := h.Service.Revoke(r.Context(), id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

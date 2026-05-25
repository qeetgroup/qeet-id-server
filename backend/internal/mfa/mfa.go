// Package mfa implements TOTP enrollment and verification plus a small
// set of recovery codes. Recovery codes are bcrypt-hashed; the user sees
// the plaintext list exactly once at generation.
package mfa

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-identity/internal/platform/codes"
	"github.com/qeetgroup/qeet-identity/internal/platform/errs"
	"github.com/qeetgroup/qeet-identity/internal/platform/httpx"
	"github.com/qeetgroup/qeet-identity/internal/platform/password"
	"github.com/qeetgroup/qeet-identity/internal/platform/totp"
)

type Service struct {
	pool   *pgxpool.Pool
	issuer string // "qeet-identity" — shown in the authenticator app
}

func NewService(pool *pgxpool.Pool, issuer string) *Service {
	return &Service{pool: pool, issuer: issuer}
}

type Enrollment struct {
	Secret           string `json:"secret"`
	ProvisioningURL  string `json:"provisioning_url"`
}

func (s *Service) StartEnroll(ctx context.Context, userID uuid.UUID, account string) (*Enrollment, error) {
	secret, err := totp.NewSecret()
	if err != nil {
		return nil, err
	}
	if _, err := s.pool.Exec(ctx, `
		INSERT INTO auth.mfa_totp (user_id, secret) VALUES ($1, $2)
		ON CONFLICT (user_id) DO UPDATE SET secret = EXCLUDED.secret, confirmed_at = NULL
	`, userID, secret); err != nil {
		return nil, err
	}
	return &Enrollment{
		Secret:          secret,
		ProvisioningURL: totp.ProvisioningURL(secret, s.issuer, account),
	}, nil
}

func (s *Service) ConfirmEnroll(ctx context.Context, userID uuid.UUID, code string) ([]string, error) {
	var secret string
	err := s.pool.QueryRow(ctx, `SELECT secret FROM auth.mfa_totp WHERE user_id = $1`, userID).Scan(&secret)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrBadRequest.WithDetail("enrollment not started")
	}
	if err != nil {
		return nil, err
	}
	if !totp.Verify(secret, code) {
		return nil, errs.ErrBadRequest.WithDetail("invalid totp code")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE auth.mfa_totp SET confirmed_at = NOW() WHERE user_id = $1`, userID); err != nil {
		return nil, err
	}
	// Wipe old recovery codes, mint 10 new ones.
	if _, err := tx.Exec(ctx, `DELETE FROM auth.mfa_recovery_codes WHERE user_id = $1`, userID); err != nil {
		return nil, err
	}
	out := make([]string, 10)
	for i := range out {
		c, err := codes.Numeric(10)
		if err != nil {
			return nil, err
		}
		hash, err := password.Hash(c)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO auth.mfa_recovery_codes (user_id, code_hash) VALUES ($1, $2)`, userID, hash); err != nil {
			return nil, err
		}
		out[i] = c
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) Disable(ctx context.Context, userID uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM auth.mfa_totp WHERE user_id = $1`, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM auth.mfa_recovery_codes WHERE user_id = $1`, userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Verify accepts a TOTP code or a one-time recovery code. Recovery codes
// are consumed on use.
func (s *Service) Verify(ctx context.Context, userID uuid.UUID, code string) error {
	code = strings.TrimSpace(code)

	var secret string
	var confirmed bool
	err := s.pool.QueryRow(ctx, `SELECT secret, confirmed_at IS NOT NULL FROM auth.mfa_totp WHERE user_id = $1`, userID).Scan(&secret, &confirmed)
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrBadRequest.WithDetail("mfa not configured")
	}
	if err != nil {
		return err
	}
	if !confirmed {
		return errs.ErrBadRequest.WithDetail("mfa enrollment not confirmed")
	}
	if totp.Verify(secret, code) {
		return nil
	}
	// Recovery code fallback.
	rows, err := s.pool.Query(ctx, `SELECT id, code_hash FROM auth.mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL`, userID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var hash string
		if err := rows.Scan(&id, &hash); err != nil {
			return err
		}
		if password.Verify(hash, code) {
			rows.Close()
			_, _ = s.pool.Exec(ctx, `UPDATE auth.mfa_recovery_codes SET used_at = NOW() WHERE id = $1`, id)
			return nil
		}
	}
	return errs.ErrUnauthorized.WithDetail("invalid mfa code")
}

type Handler struct {
	Service *Service
}

func (h *Handler) Mount(r chi.Router) {
	r.Post("/mfa/totp/enroll/start", h.startEnroll)
	r.Post("/mfa/totp/enroll/confirm", h.confirmEnroll)
	r.Post("/mfa/totp/verify", h.verify)
	r.Delete("/mfa/totp", h.disable)
}

type startEnrollInput struct {
	Account string `json:"account"`
}

func (h *Handler) startEnroll(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in startEnrollInput
	_ = httpx.DecodeJSON(r, &in)
	if in.Account == "" {
		in.Account = p.Subject
	}
	out, err := h.Service.StartEnroll(r.Context(), *p.UserID, in.Account)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

type confirmEnrollInput struct {
	Code string `json:"code"`
}

func (h *Handler) confirmEnroll(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in confirmEnrollInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	codes, err := h.Service.ConfirmEnroll(r.Context(), *p.UserID, in.Code)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"recovery_codes": codes,
		"warning":        "store these once; they will not be shown again",
	})
}

type verifyInput struct {
	Code string `json:"code"`
}

func (h *Handler) verify(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	var in verifyInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.Verify(r.Context(), *p.UserID, in.Code); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"verified": true})
}

func (h *Handler) disable(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	if err := h.Service.Disable(r.Context(), *p.UserID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

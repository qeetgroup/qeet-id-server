// Package mfa implements TOTP enrollment and verification plus a small
// set of recovery codes. Recovery codes are bcrypt-hashed; the user sees
// the plaintext list exactly once at generation.
//
// Mutating methods take a pgx.Tx so the caller (HTTP handler) can wrap
// the mutation plus its audit row in a single transaction.
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

	"github.com/qeetgroup/qeet-identity/internal/audit"
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

// Pool exposes the connection pool so handlers can begin their own
// transactions that wrap an MFA mutation and its audit row.
func (s *Service) Pool() *pgxpool.Pool { return s.pool }

type Enrollment struct {
	Secret          string `json:"secret"`
	ProvisioningURL string `json:"provisioning_url"`
}

func (s *Service) StartEnroll(ctx context.Context, tx pgx.Tx, userID uuid.UUID, account string) (*Enrollment, error) {
	secret, err := totp.NewSecret()
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
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

func (s *Service) ConfirmEnroll(ctx context.Context, tx pgx.Tx, userID uuid.UUID, code string) ([]string, error) {
	var secret string
	err := tx.QueryRow(ctx, `SELECT secret FROM auth.mfa_totp WHERE user_id = $1`, userID).Scan(&secret)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrBadRequest.WithDetail("enrollment not started")
	}
	if err != nil {
		return nil, err
	}
	if !totp.Verify(secret, code) {
		return nil, errs.ErrBadRequest.WithDetail("invalid totp code")
	}
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
	return out, nil
}

func (s *Service) Disable(ctx context.Context, tx pgx.Tx, userID uuid.UUID) error {
	if _, err := tx.Exec(ctx, `DELETE FROM auth.mfa_totp WHERE user_id = $1`, userID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM auth.mfa_recovery_codes WHERE user_id = $1`, userID); err != nil {
		return err
	}
	return nil
}

// VerifyResult tells the caller whether the supplied code matched a TOTP
// or a recovery code. The handler audits accordingly.
type VerifyResult struct {
	UsedRecoveryCode bool
	RecoveryCodeID   *uuid.UUID
}

// Verify accepts a TOTP code or a one-time recovery code. Recovery codes
// are consumed on use. The caller passes a tx so the consumption and any
// audit row commit together.
func (s *Service) Verify(ctx context.Context, tx pgx.Tx, userID uuid.UUID, code string) (*VerifyResult, error) {
	code = strings.TrimSpace(code)

	var secret string
	var confirmed bool
	err := tx.QueryRow(ctx, `SELECT secret, confirmed_at IS NOT NULL FROM auth.mfa_totp WHERE user_id = $1`, userID).Scan(&secret, &confirmed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrBadRequest.WithDetail("mfa not configured")
	}
	if err != nil {
		return nil, err
	}
	if !confirmed {
		return nil, errs.ErrBadRequest.WithDetail("mfa enrollment not confirmed")
	}
	if totp.Verify(secret, code) {
		return &VerifyResult{}, nil
	}
	// Recovery code fallback.
	rows, err := tx.Query(ctx, `SELECT id, code_hash FROM auth.mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL`, userID)
	if err != nil {
		return nil, err
	}
	var matchedID *uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		var hash string
		if err := rows.Scan(&id, &hash); err != nil {
			rows.Close()
			return nil, err
		}
		if password.Verify(hash, code) {
			matched := id
			matchedID = &matched
		}
	}
	rows.Close()
	if matchedID == nil {
		return nil, errs.ErrUnauthorized.WithDetail("invalid mfa code")
	}
	if _, err := tx.Exec(ctx, `UPDATE auth.mfa_recovery_codes SET used_at = NOW() WHERE id = $1`, *matchedID); err != nil {
		return nil, err
	}
	return &VerifyResult{UsedRecoveryCode: true, RecoveryCodeID: matchedID}, nil
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

// auditActor builds the actor portion of an audit row from the request
// principal. Returns ("", "system") for unauthenticated calls.
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
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	out, err := h.Service.StartEnroll(ctx, tx, *p.UserID, in.Account)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	target := *p.UserID
	tenantID := p.TenantID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     tenantID,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "mfa.totp_enroll_started",
		ResourceType: "user",
		ResourceID:   &target,
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
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	codes, err := h.Service.ConfirmEnroll(ctx, tx, *p.UserID, in.Code)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	target := *p.UserID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     p.TenantID,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "mfa.totp_enrolled",
		ResourceType: "user",
		ResourceID:   &target,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     map[string]any{"recovery_codes_minted": len(codes)},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
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
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	result, err := h.Service.Verify(ctx, tx, *p.UserID, in.Code)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// Only audit when a recovery code was consumed — every successful
	// TOTP verify is high-frequency and not interesting for the chain.
	if result.UsedRecoveryCode {
		actorID, actorType := auditActor(r)
		target := *p.UserID
		meta := map[string]any{}
		if result.RecoveryCodeID != nil {
			meta["recovery_code_id"] = *result.RecoveryCodeID
		}
		if err := audit.Record(ctx, tx, audit.Event{
			TenantID:     p.TenantID,
			ActorUserID:  actorID,
			ActorType:    actorType,
			Action:       "mfa.recovery_code_used",
			ResourceType: "user",
			ResourceID:   &target,
			IP:           httpx.ClientIP(r),
			UserAgent:    r.UserAgent(),
			RequestID:    httpx.RequestID(r),
			Metadata:     meta,
		}); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}
	if err := tx.Commit(ctx); err != nil {
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
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	if err := h.Service.Disable(ctx, tx, *p.UserID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := auditActor(r)
	target := *p.UserID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     p.TenantID,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "mfa.totp_disabled",
		ResourceType: "user",
		ResourceID:   &target,
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

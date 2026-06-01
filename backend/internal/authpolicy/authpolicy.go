// Package authpolicy stores a tenant's authentication policy — password
// complexity rules and which login methods are permitted — and enforces the
// password rules on tenant-scoped password changes.
//
// Signup in this product is tenant-less, so password complexity applies to
// in-tenant password operations (admin set-password / self-service change),
// where a tenant context exists. The login-method toggles are persisted
// configuration the auth flows consult as they are hardened per tenant.
package authpolicy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-identity/internal/audit"
	"github.com/qeetgroup/qeet-identity/internal/platform/errs"
	"github.com/qeetgroup/qeet-identity/internal/platform/httpx"
)

type Policy struct {
	PasswordEnabled          bool `json:"password_enabled"`
	PasswordMinLength        int  `json:"password_min_length"`
	PasswordRequireUppercase bool `json:"password_require_uppercase"`
	PasswordRequireNumber    bool `json:"password_require_number"`
	PasswordRequireSymbol    bool `json:"password_require_symbol"`
	MagicLinkEnabled         bool `json:"magic_link_enabled"`
	MagicLinkTTLMinutes      int  `json:"magic_link_ttl_minutes"`
	PasskeyEnabled           bool `json:"passkey_enabled"`
	OTPEmailEnabled          bool `json:"otp_email_enabled"`
	OTPSMSEnabled            bool `json:"otp_sms_enabled"`
}

// DefaultPolicy mirrors the column defaults — returned when a tenant has no
// explicit row yet.
func DefaultPolicy() Policy {
	return Policy{
		PasswordEnabled:     true,
		PasswordMinLength:   8,
		MagicLinkEnabled:    true,
		MagicLinkTTLMinutes: 60,
		PasskeyEnabled:      true,
	}
}

// ValidatePassword checks a plaintext password against the policy. Pure, so it
// is unit-tested without a database.
func ValidatePassword(p Policy, pw string) error {
	if len([]rune(pw)) < p.PasswordMinLength {
		return errs.ErrUnprocessable.WithDetail(fmt.Sprintf("password must be at least %d characters", p.PasswordMinLength))
	}
	if p.PasswordRequireUppercase && !strings.ContainsFunc(pw, unicode.IsUpper) {
		return errs.ErrUnprocessable.WithDetail("password must contain an uppercase letter")
	}
	if p.PasswordRequireNumber && !strings.ContainsFunc(pw, unicode.IsDigit) {
		return errs.ErrUnprocessable.WithDetail("password must contain a number")
	}
	if p.PasswordRequireSymbol && !strings.ContainsFunc(pw, isSymbol) {
		return errs.ErrUnprocessable.WithDetail("password must contain a symbol")
	}
	return nil
}

func isSymbol(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r) }

type Service struct {
	pool *pgxpool.Pool
}

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

func (s *Service) Pool() *pgxpool.Pool { return s.pool }

const cols = `password_enabled, password_min_length, password_require_uppercase,
              password_require_number, password_require_symbol, magic_link_enabled,
              magic_link_ttl_minutes, passkey_enabled, otp_email_enabled, otp_sms_enabled`

func scan(row pgx.Row) (*Policy, error) {
	var p Policy
	if err := row.Scan(&p.PasswordEnabled, &p.PasswordMinLength, &p.PasswordRequireUppercase,
		&p.PasswordRequireNumber, &p.PasswordRequireSymbol, &p.MagicLinkEnabled,
		&p.MagicLinkTTLMinutes, &p.PasskeyEnabled, &p.OTPEmailEnabled, &p.OTPSMSEnabled); err != nil {
		return nil, err
	}
	return &p, nil
}

// Get returns the tenant's policy, or defaults when none is stored.
func (s *Service) Get(ctx context.Context, tenantID uuid.UUID) (*Policy, error) {
	p, err := scan(s.pool.QueryRow(ctx, `SELECT `+cols+` FROM tenant.auth_policy WHERE tenant_id = $1`, tenantID))
	if errors.Is(err, pgx.ErrNoRows) {
		def := DefaultPolicy()
		return &def, nil
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (s *Service) Update(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, p Policy) (*Policy, error) {
	if p.PasswordMinLength < 8 {
		p.PasswordMinLength = 8
	}
	if p.PasswordMinLength > 128 {
		p.PasswordMinLength = 128
	}
	if p.MagicLinkTTLMinutes < 5 {
		p.MagicLinkTTLMinutes = 5
	}
	if p.MagicLinkTTLMinutes > 1440 {
		p.MagicLinkTTLMinutes = 1440
	}
	return scan(tx.QueryRow(ctx, `
		INSERT INTO tenant.auth_policy
			(tenant_id, password_enabled, password_min_length, password_require_uppercase,
			 password_require_number, password_require_symbol, magic_link_enabled,
			 magic_link_ttl_minutes, passkey_enabled, otp_email_enabled, otp_sms_enabled, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW())
		ON CONFLICT (tenant_id) DO UPDATE SET
			password_enabled = EXCLUDED.password_enabled,
			password_min_length = EXCLUDED.password_min_length,
			password_require_uppercase = EXCLUDED.password_require_uppercase,
			password_require_number = EXCLUDED.password_require_number,
			password_require_symbol = EXCLUDED.password_require_symbol,
			magic_link_enabled = EXCLUDED.magic_link_enabled,
			magic_link_ttl_minutes = EXCLUDED.magic_link_ttl_minutes,
			passkey_enabled = EXCLUDED.passkey_enabled,
			otp_email_enabled = EXCLUDED.otp_email_enabled,
			otp_sms_enabled = EXCLUDED.otp_sms_enabled,
			updated_at = NOW()
		RETURNING `+cols,
		tenantID, p.PasswordEnabled, p.PasswordMinLength, p.PasswordRequireUppercase,
		p.PasswordRequireNumber, p.PasswordRequireSymbol, p.MagicLinkEnabled,
		p.MagicLinkTTLMinutes, p.PasskeyEnabled, p.OTPEmailEnabled, p.OTPSMSEnabled))
}

// ValidateForTenant loads the tenant policy and validates a password against
// it. Wired into user.Handler so the user package needn't import this one.
func (s *Service) ValidateForTenant(ctx context.Context, tenantID uuid.UUID, pw string) error {
	p, err := s.Get(ctx, tenantID)
	if err != nil {
		return err
	}
	return ValidatePassword(*p, pw)
}

type Handler struct {
	Service *Service
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/auth-policy", h.get)
	r.Put("/tenants/{tenantID}/auth-policy", h.update)
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

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	p, err := h.Service.Get(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in Policy
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
	p, err := h.Service.Update(ctx, tx, tenantID, in)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var actorID *uuid.UUID
	actorType := "system"
	if pr := httpx.PrincipalFromCtx(ctx); pr != nil {
		actorID = pr.UserID
		if pr.ActorType != "" {
			actorType = pr.ActorType
		}
	}
	tid := tenantID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "auth_policy.updated",
		ResourceType: "auth_policy",
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata: map[string]any{
			"password_min_length": p.PasswordMinLength,
			"password_enabled":    p.PasswordEnabled,
		},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

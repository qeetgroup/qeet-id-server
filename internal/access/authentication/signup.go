package auth

import (
	"context"
	"strings"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication/dbgen"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/pgxerr"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// SignupInput is what Signup takes.
type SignupInput struct {
	Email       string
	Password    string
	DisplayName string
	IP          string
	UserAgent   string
}

// TenantBrief is the small tenant projection returned alongside Signup.
type TenantBrief struct {
	ID     uuid.UUID `json:"id"`
	Slug   string    `json:"slug"`
	Name   string    `json:"name"`
	Plan   string    `json:"plan"`
	Region string    `json:"region"`
}

// Signup creates a tenant-less identity (user + password + session) and logs them in; no tenant or role is created.
func (s *Service) Signup(ctx context.Context, in SignupInput) (*TokenPair, *user.User, *TenantBrief, error) {
	// The account belongs to no organisation, so the platform baseline applies.
	if err := s.checkNewPassword(ctx, uuid.Nil, in.Email, in.Password); err != nil {
		return nil, nil, nil, err
	}
	hash, err := password.Hash(in.Password)
	if err != nil {
		return nil, nil, nil, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	defer tx.Rollback(ctx)

	// 1) User — tenant-less (tenant_id NULL).
	u := &user.User{Email: strings.TrimSpace(in.Email), Status: "active", Metadata: map[string]any{}}
	if in.DisplayName != "" {
		dn := in.DisplayName
		u.DisplayName = &dn
	}
	urow, err := s.q.WithTx(tx).InsertTenantlessUser(ctx, dbgen.InsertTenantlessUserParams{
		Email:       u.Email,
		DisplayName: u.DisplayName,
	})
	if err != nil {
		if pgxerr.IsUnique(err) {
			return nil, nil, nil, errs.ErrAuthEmailExists
		}
		return nil, nil, nil, err
	}
	u.ID, u.CreatedAt, u.UpdatedAt = urow.ID, urow.CreatedAt, urow.UpdatedAt

	// 2) Password credential.
	if err := s.q.WithTx(tx).InsertPasswordCredential(ctx, dbgen.InsertPasswordCredentialParams{
		UserID:       u.ID,
		PasswordHash: hash,
	}); err != nil {
		return nil, nil, nil, err
	}

	// 3) Tenant-less session + access + refresh token, all in the same tx so
	// signup is fully atomic.
	sessionID := uuid.New()
	maxAge, idle := s.sessionDefaults()
	bounds, err := s.q.WithTx(tx).InsertTenantlessSession(ctx, dbgen.InsertTenantlessSessionParams{
		ID:            sessionID,
		UserID:        u.ID,
		Ip:            in.IP,
		UserAgent:     &in.UserAgent,
		MaxAgeSeconds: maxAge.Seconds(),
		IdleSeconds:   idle.Seconds(),
		Country:       httpx.GeoCountry(ctx),
	})
	if err != nil {
		return nil, nil, nil, err
	}
	access, exp, err := s.tokens.IssueSessionAccess(u.ID, uuid.Nil, sessionID, nil, bounds.ExpiresAt)
	if err != nil {
		return nil, nil, nil, err
	}
	refreshRaw, refreshHash, err := tokens.NewRefreshToken()
	if err != nil {
		return nil, nil, nil, err
	}
	if _, err := s.q.WithTx(tx).InsertRefreshToken(ctx, dbgen.InsertRefreshTokenParams{
		SessionID: sessionID,
		TokenHash: refreshHash,
		ExpiresAt: s.refreshExpiry(bounds.ExpiresAt),
	}); err != nil {
		return nil, nil, nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, nil, nil, err
	}

	return &TokenPair{
		AccessToken:      access,
		TokenType:        "Bearer",
		ExpiresAt:        exp,
		RefreshToken:     refreshRaw,
		SessionExpiresAt: bounds.ExpiresAt,
		IdleExpiresAt:    bounds.IdleExpiresAt,
		SessionID:        sessionID,
		UserID:           u.ID,
	}, u, nil, nil
}

// RegisterInTenant creates a user in tenantID from the hosted sign-up flow and
// signs them in. It honours the tenant's self-registration, password sign-in and
// password rules, and returns the SSO cookie value or, when the organisation
// requires MFA, an enrolment challenge.
func (s *Service) RegisterInTenant(ctx context.Context, tenantID uuid.UUID, email, plain, displayName, ip, ua string) (*user.User, *LoginSessionResult, error) {
	if s.regPolicy == nil {
		return nil, nil, errs.ErrNotImplemented
	}
	enabled, err := s.regPolicy.SelfRegistrationEnabled(ctx, tenantID)
	if err != nil {
		return nil, nil, err
	}
	if !enabled {
		return nil, nil, errs.ErrAuthSelfRegistrationDisabled
	}
	// A password account isn't made where passwords can't sign in.
	if err := s.passwordAllowed(ctx, tenantID); err != nil {
		return nil, nil, err
	}
	// Nobody joins an organisation from an address it doesn't allow.
	if err := s.checkAddress(ctx, tenantID, uuid.Nil, ip, "hosted_signup"); err != nil {
		return nil, nil, err
	}
	if err := s.checkNewPassword(ctx, tenantID, email, plain); err != nil {
		return nil, nil, err
	}
	hash, err := password.Hash(plain)
	if err != nil {
		return nil, nil, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback(ctx)

	var dnArg any
	u := &user.User{Email: strings.TrimSpace(email), Status: "active", Metadata: map[string]any{}}
	if displayName != "" {
		dnArg = displayName
		dn := displayName
		u.DisplayName = &dn
	}
	if err := tx.QueryRow(ctx, `
		INSERT INTO "user".users (tenant_id, email, display_name)
		VALUES ($1, $2, $3)
		RETURNING id, created_at, updated_at
	`, tenantID, u.Email, dnArg).Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt); err != nil {
		if pgxerr.IsUnique(err) {
			return nil, nil, errs.ErrAuthEmailExists
		}
		return nil, nil, err
	}
	if err := s.q.WithTx(tx).InsertPasswordCredential(ctx, dbgen.InsertPasswordCredentialParams{
		UserID:       u.ID,
		PasswordHash: hash,
	}); err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}

	// A new account holds no factor: where the organisation requires one, it
	// is set up before the first session. Its sign-in is still assessed, so
	// later ones have a device and country to compare against; there is no
	// verified address yet to confirm a risky one with.
	gate, err := s.mfaGate(ctx, u.ID, tenantID)
	if err != nil {
		return nil, nil, err
	}
	step := s.nextSignInStep(ctx, u.ID, tenantID, gate, firstFactorPassword, "", ip, ua, httpx.GeoCountry(ctx))
	if step == stepChallenge {
		challenge, err := s.challengeSignIn(ctx, u.ID, tenantID, nil, gate, firstFactorPassword, ip, ua)
		if err != nil {
			return nil, nil, err
		}
		return u, &LoginSessionResult{UserID: u.ID, MFAChallenge: challenge}, nil
	}
	raw, err := s.CreateLoginSession(ctx, u.ID, ip, ua)
	if err != nil {
		return nil, nil, err
	}
	if step == stepSession {
		s.recordSignIn(ctx, u.ID, tenantID, ua, httpx.GeoCountry(ctx))
	}
	return u, &LoginSessionResult{UserID: u.ID, RawCookie: raw}, nil
}

// SelfRegistrationEnabled reports whether tenantID allows hosted self-service
// signup. Exposed so other access-domain services (e.g. the passkey-first
// signup ceremony) can gate on the same policy without duplicating it or
// requiring a password to validate. false, nil when no policy is wired.
func (s *Service) SelfRegistrationEnabled(ctx context.Context, tenantID uuid.UUID) (bool, error) {
	if s.regPolicy == nil {
		return false, nil
	}
	return s.regPolicy.SelfRegistrationEnabled(ctx, tenantID)
}

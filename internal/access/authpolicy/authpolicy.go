// Package authpolicy stores an organization's authentication policy (password rules, sign-in methods,
// lockout) and its security policy (sessions, second factor, step-up; securitypolicy.go), and owns
// the password check every path that sets a password runs (ValidateForOrganization). An account with
// no organization gets the platform baseline, DefaultPolicy.
package authpolicy

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authpolicy/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Policy is an organization's authentication policy. Self-registration (hosted
// end-user signup) and remembering devices (skipping MFA on one for
// RememberDeviceDays, 1–90; 0 on update means 30) are off by default.
// LockoutLimits is read-only: returned by Get, ignored by Update.
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
	SelfRegistrationEnabled  bool `json:"self_registration_enabled"`
	RememberDeviceEnabled    bool `json:"remember_device_enabled"`
	RememberDeviceDays       int  `json:"remember_device_days"`

	// Sign-in lockout (see Lockout); nil takes the platform default.
	LockoutThreshold       *int               `json:"lockout_threshold"`
	LockoutWindowMinutes   *int               `json:"lockout_window_minutes"`
	LockoutDurationMinutes *int               `json:"lockout_duration_minutes"`
	LockoutLimits          *LockoutLimitsView `json:"lockout_limits,omitempty"`
}

// DefaultPolicy mirrors the column defaults — returned when an organization has no
// explicit row yet. It is also the platform baseline: the password rules for
// an account that belongs to no organization (8 characters, no required
// character classes). Update never lets an organization go below it.
func DefaultPolicy() Policy {
	return Policy{
		PasswordEnabled:     true,
		PasswordMinLength:   8,
		MagicLinkEnabled:    true,
		MagicLinkTTLMinutes: 60,
		PasskeyEnabled:      true,
		RememberDeviceDays:  defaultRememberDeviceDays,
	}
}

// defaultRememberDeviceDays is how long a remembered device stays remembered
// where the organization sets nothing (the column default).
const defaultRememberDeviceDays = 30

// Service stores organizations' authentication policies. breach checks new
// passwords against known breaches; lockout holds the platform lockout
// defaults and bounds.
type Service struct {
	pool    *pgxpool.Pool
	q       *dbgen.Queries
	breach  BreachChecker
	lockout LockoutLimits
}

// BreachChecker reports whether a new password appears in known breaches,
// failing open when it can't tell. Satisfied by *hibp.Checker.
type BreachChecker interface {
	PwnedAllowOnError(ctx context.Context, password string) bool
}

// NoBreachCheck is the BreachChecker of a deployment that turns the check
// off: no password counts as breached.
type NoBreachCheck struct{}

// PwnedAllowOnError reports false.
func (NoBreachCheck) PwnedAllowOnError(context.Context, string) bool { return false }

// NewService returns the authentication policy service, checking new
// passwords with breaches.
func NewService(pool *pgxpool.Pool, breaches BreachChecker) (*Service, error) {
	if breaches == nil {
		return nil, errors.New("authpolicy: the policy service needs a breach checker (NoBreachCheck when it is off)")
	}
	return &Service{pool: pool, q: dbgen.New(pool), breach: breaches, lockout: DefaultLockoutLimits()}, nil
}

// toDomain maps a generated OrganizationAuthPolicy row to the domain Policy model.
func toDomain(row dbgen.OrganizationAuthPolicy) *Policy {
	return &Policy{
		PasswordEnabled:          row.PasswordEnabled,
		PasswordMinLength:        int(row.PasswordMinLength),
		PasswordRequireUppercase: row.PasswordRequireUppercase,
		PasswordRequireNumber:    row.PasswordRequireNumber,
		PasswordRequireSymbol:    row.PasswordRequireSymbol,
		MagicLinkEnabled:         row.MagicLinkEnabled,
		MagicLinkTTLMinutes:      int(row.MagicLinkTtlMinutes),
		PasskeyEnabled:           row.PasskeyEnabled,
		OTPEmailEnabled:          row.OtpEmailEnabled,
		OTPSMSEnabled:            row.OtpSmsEnabled,
		SelfRegistrationEnabled:  row.SelfRegistrationEnabled,
		RememberDeviceEnabled:    row.RememberDeviceEnabled,
		RememberDeviceDays:       int(row.RememberDeviceDays),
		LockoutThreshold:         intOrNil(row.LockoutThreshold),
		LockoutWindowMinutes:     intOrNil(row.LockoutWindowMinutes),
		LockoutDurationMinutes:   intOrNil(row.LockoutDurationMinutes),
	}
}

func intOrNil(v *int32) *int {
	if v == nil {
		return nil
	}
	n := int(*v)
	return &n
}

func int32OrNil(v *int) *int32 {
	if v == nil {
		return nil
	}
	n := int32(*v) // #nosec G115 -- lockout fields, range-checked by CheckLockout
	return &n
}

// Get returns the organization's policy, or defaults when none is stored, with the
// lockout limits attached.
func (s *Service) Get(ctx context.Context, organizationID uuid.UUID) (*Policy, error) {
	row, err := s.q.GetAuthPolicy(ctx, organizationID)
	if errors.Is(err, pgx.ErrNoRows) {
		def := DefaultPolicy()
		def.LockoutLimits = s.lockout.view()
		return &def, nil
	}
	if err != nil {
		return nil, err
	}
	p := toDomain(row)
	p.LockoutLimits = s.lockout.view()
	return p, nil
}

// Update stores an organization's whole policy, recorded as actor's in the same transaction. Invalid
// settings are refused, each named, before anything is written; password length (8-128) and
// magic-link lifetime (5-1440 minutes) are clamped instead. Every first-factor method may be off only
// while an active SAML or LDAP connection signs people in.
func (s *Service) Update(ctx context.Context, organizationID uuid.UUID, p Policy, actor audit.Actor) (*Policy, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	out, err := s.update(ctx, tx, organizationID, p)
	if err != nil {
		return nil, err
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "auth_policy.updated", "auth_policy", uuid.Nil, map[string]any{
		"password_min_length":      out.PasswordMinLength,
		"password_enabled":         out.PasswordEnabled,
		"lockout_threshold":        out.LockoutThreshold,
		"lockout_window_minutes":   out.LockoutWindowMinutes,
		"lockout_duration_minutes": out.LockoutDurationMinutes,
	})); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}

// update validates p and stores it on tx; see Update.
func (s *Service) update(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, p Policy) (*Policy, error) {
	if p.RememberDeviceDays == 0 {
		p.RememberDeviceDays = defaultRememberDeviceDays
	}
	sso := false
	if !p.PasswordEnabled && !p.PasskeyEnabled && !p.MagicLinkEnabled {
		var err error
		if sso, err = s.q.WithTx(tx).HasActiveSSOConnection(ctx, organizationID); err != nil {
			return nil, err
		}
	}
	fields := s.lockout.CheckLockout(p)
	fields = append(fields, checkSignInMethods(p, sso)...)
	if p.RememberDeviceDays < 1 || p.RememberDeviceDays > 90 {
		fields = append(fields, errs.FieldError{Field: "remember_device_days", Code: "out_of_range",
			Message: "Remember a device for between 1 and 90 days."})
	}
	if len(fields) > 0 {
		return nil, errs.ErrValidationFailed.WithFields(fields)
	}
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
	row, err := s.q.WithTx(tx).UpsertAuthPolicy(ctx, dbgen.UpsertAuthPolicyParams{
		OrganizationID:           organizationID,
		PasswordEnabled:          p.PasswordEnabled,
		PasswordMinLength:        int32(p.PasswordMinLength), // #nosec G115 -- clamped to 8–128 above
		PasswordRequireUppercase: p.PasswordRequireUppercase,
		PasswordRequireNumber:    p.PasswordRequireNumber,
		PasswordRequireSymbol:    p.PasswordRequireSymbol,
		MagicLinkEnabled:         p.MagicLinkEnabled,
		MagicLinkTtlMinutes:      int32(p.MagicLinkTTLMinutes), // #nosec G115 -- clamped to 5–1440 above
		PasskeyEnabled:           p.PasskeyEnabled,
		OtpEmailEnabled:          p.OTPEmailEnabled,
		OtpSmsEnabled:            p.OTPSMSEnabled,
		SelfRegistrationEnabled:  p.SelfRegistrationEnabled,
		RememberDeviceEnabled:    p.RememberDeviceEnabled,
		RememberDeviceDays:       int32(p.RememberDeviceDays), // #nosec G115 -- checked 1–90 above
		LockoutThreshold:         int32OrNil(p.LockoutThreshold),
		LockoutWindowMinutes:     int32OrNil(p.LockoutWindowMinutes),
		LockoutDurationMinutes:   int32OrNil(p.LockoutDurationMinutes),
	})
	if err != nil {
		return nil, err
	}
	out := toDomain(row)
	out.LockoutLimits = s.lockout.view()
	return out, nil
}

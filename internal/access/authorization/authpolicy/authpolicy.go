// Package authpolicy stores a tenant's authentication policy — password
// complexity rules and which login methods are permitted — and owns the one
// check every path that sets or replaces a password runs (ValidateForTenant).
//
// The rules that apply are those of the organisation the account belongs to
// (its home tenant). An account with no organisation — console sign-up is
// tenant-less — gets the platform baseline, DefaultPolicy. The login-method
// toggles are persisted configuration the auth flows consult as they are
// hardened per tenant.
//
// It also stores a tenant's sign-in lockout settings (threshold, window and
// lock duration), which the password sign-in reads through SignInLockout. The
// platform defaults and the bounds a tenant may choose within are platform
// configuration (LOGIN_LOCKOUT_*); a write outside the bounds is refused.
package authpolicy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/authpolicy/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	password "github.com/qeetgroup/qeet-id-server/internal/platform/crypto/encryption"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/hibp"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// BreachedPasswordDetail is the user-safe 422 message shown when a password is
// rejected for appearing in known breaches. It deliberately omits the sighting
// count so we don't reveal breach-corpus details to the end user.
const BreachedPasswordDetail = "This password has appeared in known data breaches — choose a different one."

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
	// SelfRegistrationEnabled gates the hosted end-user signup flow (B2C). Off by
	// default so tenants stay invite-only unless they opt in.
	SelfRegistrationEnabled bool `json:"self_registration_enabled"`
	// RememberDeviceEnabled gates adaptive MFA: when on, an enrolled user may
	// skip the second factor on a previously-trusted device. Off by default so
	// MFA stays always-on unless a tenant opts in.
	RememberDeviceEnabled bool `json:"remember_device_enabled"`
	// Sign-in lockout. After LockoutThreshold failed password sign-ins to one
	// account from one network, each within LockoutWindowMinutes of the last,
	// the account is locked for that network for LockoutDurationMinutes. nil
	// (JSON null) = the platform default. A value outside LockoutLimits is
	// refused.
	LockoutThreshold       *int `json:"lockout_threshold"`
	LockoutWindowMinutes   *int `json:"lockout_window_minutes"`
	LockoutDurationMinutes *int `json:"lockout_duration_minutes"`
	// LockoutLimits documents the platform defaults and the bounds for the
	// three settings above. Read-only: returned by Get, ignored by Update.
	LockoutLimits *LockoutLimitsView `json:"lockout_limits,omitempty"`
}

// Lockout is the sign-in lockout a tenant applies (see Policy.LockoutThreshold).
type Lockout struct {
	Threshold int
	Window    time.Duration
	Duration  time.Duration
}

// LockoutLimits are the platform defaults for the lockout settings and the
// documented bounds a tenant may choose within. Platform configuration
// (LOGIN_LOCKOUT_*), validated at start-up; windows and durations are whole
// minutes.
type LockoutLimits struct {
	Defaults Lockout
	Min      Lockout
	Max      Lockout
}

// DefaultLockoutLimits are the built-in limits: five failures within fifteen
// minutes lock for fifteen minutes; a tenant may choose a threshold of 3 to
// 20, and a window and a duration of 1 minute to 24 hours.
func DefaultLockoutLimits() LockoutLimits {
	return LockoutLimits{
		Defaults: Lockout{Threshold: 5, Window: 15 * time.Minute, Duration: 15 * time.Minute},
		Min:      Lockout{Threshold: 3, Window: time.Minute, Duration: time.Minute},
		Max:      Lockout{Threshold: 20, Window: 24 * time.Hour, Duration: 24 * time.Hour},
	}
}

// LockoutSettingsView is a lockout in API units (minutes).
type LockoutSettingsView struct {
	Threshold       int `json:"threshold"`
	WindowMinutes   int `json:"window_minutes"`
	DurationMinutes int `json:"duration_minutes"`
}

// LockoutLimitsView is LockoutLimits in API units.
type LockoutLimitsView struct {
	Defaults LockoutSettingsView `json:"defaults"`
	Min      LockoutSettingsView `json:"min"`
	Max      LockoutSettingsView `json:"max"`
}

func lockoutView(l Lockout) LockoutSettingsView {
	return LockoutSettingsView{
		Threshold:       l.Threshold,
		WindowMinutes:   int(l.Window / time.Minute),
		DurationMinutes: int(l.Duration / time.Minute),
	}
}

func (l LockoutLimits) view() *LockoutLimitsView {
	return &LockoutLimitsView{Defaults: lockoutView(l.Defaults), Min: lockoutView(l.Min), Max: lockoutView(l.Max)}
}

// CheckLockout reports each lockout setting in p that lies outside the
// bounds. Unset (nil) settings take the platform default and are not checked.
// Pure, so it is unit-tested without a database.
func (l LockoutLimits) CheckLockout(p Policy) []errs.FieldError {
	lo, hi := lockoutView(l.Min), lockoutView(l.Max)
	var out []errs.FieldError
	for _, f := range []struct {
		field  string
		value  *int
		lo, hi int
		unit   string
	}{
		{"lockout_threshold", p.LockoutThreshold, lo.Threshold, hi.Threshold, "failed attempts"},
		{"lockout_window_minutes", p.LockoutWindowMinutes, lo.WindowMinutes, hi.WindowMinutes, "minutes"},
		{"lockout_duration_minutes", p.LockoutDurationMinutes, lo.DurationMinutes, hi.DurationMinutes, "minutes"},
	} {
		if f.value != nil && (*f.value < f.lo || *f.value > f.hi) {
			out = append(out, errs.FieldError{
				Field:   f.field,
				Code:    "out_of_range",
				Message: fmt.Sprintf("Must be between %d and %d %s.", f.lo, f.hi, f.unit),
			})
		}
	}
	return out
}

// DefaultPolicy mirrors the column defaults — returned when a tenant has no
// explicit row yet. It is also the platform baseline: the password rules for
// an account that belongs to no organisation (8 characters, no required
// character classes). Update never lets a tenant go below it.
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
// is unit-tested without a database. Each refusal names the rule that failed
// (the length one names the minimum) and never echoes the password.
func ValidatePassword(p Policy, pw string) error {
	if len([]rune(pw)) < p.PasswordMinLength {
		return errs.ErrAuthPolicyPasswordTooShort.
			WithMessage(fmt.Sprintf("Your password must be at least %d characters.", p.PasswordMinLength)).
			WithMetadata(map[string]any{"min_length": p.PasswordMinLength})
	}
	if p.PasswordRequireUppercase && !strings.ContainsFunc(pw, unicode.IsUpper) {
		return errs.ErrAuthPolicyPasswordNoUppercase
	}
	if p.PasswordRequireNumber && !strings.ContainsFunc(pw, unicode.IsDigit) {
		return errs.ErrAuthPolicyPasswordNoNumber
	}
	if p.PasswordRequireSymbol && !strings.ContainsFunc(pw, isSymbol) {
		return errs.ErrAuthPolicyPasswordNoSymbol
	}
	return nil
}

func isSymbol(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r) }

type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
	// breach is the optional breached-password checker. Nil disables the check
	// (a no-op), so dev/CI/offline deploys are unaffected; when set it is
	// consulted by ValidateForTenant — so on every path that sets a password —
	// and is itself fail-open (a HIBP outage allows the password). Set via
	// SetBreachChecker.
	breach *hibp.Checker
	// lockout holds the platform lockout defaults and the bounds a tenant's
	// settings must stay within. Set via SetLockoutLimits.
	lockout LockoutLimits
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), lockout: DefaultLockoutLimits()}
}

// SetLockoutLimits sets the platform lockout defaults and bounds (from
// LOGIN_LOCKOUT_*). Called from internal/bootstrap/dependencies.go.
func (s *Service) SetLockoutLimits(l LockoutLimits) { s.lockout = l }

// SetBreachChecker wires (or clears, with nil) the breached-password checker.
// Called from internal/bootstrap/dependencies.go only when BREACHED_PASSWORD_CHECK is enabled.
func (s *Service) SetBreachChecker(c *hibp.Checker) { s.breach = c }

func (s *Service) Pool() *pgxpool.Pool { return s.pool }

// toDomain maps a generated TenantAuthPolicy row to the domain Policy model.
func toDomain(row dbgen.TenantAuthPolicy) *Policy {
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
	n := int32(*v)
	return &n
}

// Get returns the tenant's policy, or defaults when none is stored, with the
// lockout limits attached.
func (s *Service) Get(ctx context.Context, tenantID uuid.UUID) (*Policy, error) {
	row, err := s.q.GetAuthPolicy(ctx, tenantID)
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

// SignInLockout returns the lockout a password sign-in for tenantID is held
// to: each setting the tenant chose, the platform default for the rest.
// uuid.Nil (a sign-in with no tenant) gets the platform defaults without a
// read. Which tenant a sign-in belongs to is the caller's decision.
func (s *Service) SignInLockout(ctx context.Context, tenantID uuid.UUID) (Lockout, error) {
	l := s.lockout.Defaults
	if tenantID == uuid.Nil {
		return l, nil
	}
	p, err := s.Get(ctx, tenantID)
	if err != nil {
		return Lockout{}, err
	}
	if p.LockoutThreshold != nil {
		l.Threshold = *p.LockoutThreshold
	}
	if p.LockoutWindowMinutes != nil {
		l.Window = time.Duration(*p.LockoutWindowMinutes) * time.Minute
	}
	if p.LockoutDurationMinutes != nil {
		l.Duration = time.Duration(*p.LockoutDurationMinutes) * time.Minute
	}
	return l, nil
}

// Update stores a tenant's whole policy. Lockout settings outside the bounds
// are refused with a validation error naming each field, before anything is
// written; the password length and magic-link lifetime are clamped as before.
func (s *Service) Update(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, p Policy) (*Policy, error) {
	fields := s.lockout.CheckLockout(p)
	fields = append(fields, checkSignInMethods(p)...)
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
		TenantID:                 tenantID,
		PasswordEnabled:          p.PasswordEnabled,
		PasswordMinLength:        int32(p.PasswordMinLength),
		PasswordRequireUppercase: p.PasswordRequireUppercase,
		PasswordRequireNumber:    p.PasswordRequireNumber,
		PasswordRequireSymbol:    p.PasswordRequireSymbol,
		MagicLinkEnabled:         p.MagicLinkEnabled,
		MagicLinkTtlMinutes:      int32(p.MagicLinkTTLMinutes),
		PasskeyEnabled:           p.PasskeyEnabled,
		OtpEmailEnabled:          p.OTPEmailEnabled,
		OtpSmsEnabled:            p.OTPSMSEnabled,
		SelfRegistrationEnabled:  p.SelfRegistrationEnabled,
		RememberDeviceEnabled:    p.RememberDeviceEnabled,
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

// checkSignInMethods refuses a policy that leaves no first-factor sign-in
// method (password, passkey or magic link) on, and one that switches on an
// email or SMS one-time-code sign-in — no such sign-in exists, so saving it
// would claim a method the organisation does not have.
func checkSignInMethods(p Policy) []errs.FieldError {
	var out []errs.FieldError
	if !p.PasswordEnabled && !p.PasskeyEnabled && !p.MagicLinkEnabled {
		out = append(out, errs.FieldError{Field: "password_enabled", Code: "no_sign_in_method",
			Message: "Keep at least one of password, passkey or magic-link sign-in on."})
	}
	if p.OTPEmailEnabled {
		out = append(out, errs.FieldError{Field: "otp_email_enabled", Code: "not_available",
			Message: "Email one-time-code sign-in isn't available."})
	}
	if p.OTPSMSEnabled {
		out = append(out, errs.FieldError{Field: "otp_sms_enabled", Code: "not_available",
			Message: "SMS one-time-code sign-in isn't available."})
	}
	return out
}

// ValidateForTenant is the one check every path that sets or replaces a
// password runs — sign-up (in a tenant and tenant-less), self-service change,
// reset, invitation acceptance, admin set-password, admin create and bulk
// import — so a password is judged the same way whichever path it takes:
//
//  1. the rules of the organisation the account belongs to (tenantID), or the
//     platform baseline DefaultPolicy when it belongs to none (uuid.Nil);
//  2. the always-on offline strength baseline (common passwords, the account's
//     email, trivial sequences); email may be empty;
//  3. the breached-password check, when enabled — fail-open: an unreachable
//     provider allows the password (counted in a metric, see hibp).
//
// The first failure is returned. Each names the requirement that was not met
// (authpolicy.password_* or auth.password_weak), and none echoes the password
// or says anything about the account's current credential. Callers take it
// through a consumer-declared interface so they needn't import this package.
func (s *Service) ValidateForTenant(ctx context.Context, tenantID uuid.UUID, email, pw string) error {
	p := DefaultPolicy()
	if tenantID != uuid.Nil {
		tp, err := s.Get(ctx, tenantID)
		if err != nil {
			return err
		}
		p = *tp
	}
	if err := ValidatePassword(p, pw); err != nil {
		return err
	}
	if reason := password.WeakReason(pw, email); reason != "" {
		return errs.ErrAuthPasswordWeak.WithMessage(reason)
	}
	// Breached-password gate. No-op when the checker is nil (feature off) and
	// fail-open inside PwnedAllowOnError (a HIBP outage allows the password).
	if s.breach.PwnedAllowOnError(ctx, pw) {
		return errs.ErrAuthPolicyPasswordBreached
	}
	return nil
}

// SelfRegistrationEnabled reports whether the tenant permits hosted end-user
// self-registration. Gates POST /v1/auth/register and the hosted /signup page.
func (s *Service) SelfRegistrationEnabled(ctx context.Context, tenantID uuid.UUID) (bool, error) {
	p, err := s.Get(ctx, tenantID)
	if err != nil {
		return false, err
	}
	return p.SelfRegistrationEnabled, nil
}

// SignInMethods are the first-factor sign-in methods an organisation allows.
type SignInMethods struct {
	Password  bool `json:"password"`
	Passkey   bool `json:"passkey"`
	MagicLink bool `json:"magic_link"`
}

// SignInMethodsFor returns the sign-in methods tenantID allows; uuid.Nil (no
// organisation) allows all. Read on every call — a change applies to the next
// sign-in.
func (s *Service) SignInMethodsFor(ctx context.Context, tenantID uuid.UUID) (SignInMethods, error) {
	if tenantID == uuid.Nil {
		return SignInMethods{Password: true, Passkey: true, MagicLink: true}, nil
	}
	p, err := s.Get(ctx, tenantID)
	if err != nil {
		return SignInMethods{}, err
	}
	return SignInMethods{Password: p.PasswordEnabled, Passkey: p.PasskeyEnabled, MagicLink: p.MagicLinkEnabled}, nil
}

// AllowedSignInMethods is SignInMethodsFor as plain values, for consumers in
// other contexts (the hosted login's login-context) that take it through an
// interface of their own.
func (s *Service) AllowedSignInMethods(ctx context.Context, tenantID uuid.UUID) (password, passkey, magicLink bool, err error) {
	m, err := s.SignInMethodsFor(ctx, tenantID)
	return m.Password, m.Passkey, m.MagicLink, err
}

// PasswordEnabled reports whether the tenant permits password sign-in
// (password_enabled); uuid.Nil is not restricted.
func (s *Service) PasswordEnabled(ctx context.Context, tenantID uuid.UUID) (bool, error) {
	m, err := s.SignInMethodsFor(ctx, tenantID)
	return m.Password, err
}

// MagicLinkPolicy reports whether the tenant permits magic-link sign-in and how
// long a link it issues lives (magic_link_ttl_minutes).
func (s *Service) MagicLinkPolicy(ctx context.Context, tenantID uuid.UUID) (bool, time.Duration, error) {
	p, err := s.Get(ctx, tenantID)
	if err != nil {
		return false, 0, err
	}
	return p.MagicLinkEnabled, time.Duration(p.MagicLinkTTLMinutes) * time.Minute, nil
}

// PasskeyEnabled reports whether the tenant permits passkeys (passkey_enabled).
// Gates adding a passkey: the passkey service consults it when offering
// enrolment and when beginning and finishing the ceremony.
func (s *Service) PasskeyEnabled(ctx context.Context, tenantID uuid.UUID) (bool, error) {
	p, err := s.Get(ctx, tenantID)
	if err != nil {
		return false, err
	}
	return p.PasskeyEnabled, nil
}

// RememberDeviceEnabled reports whether the tenant allows adaptive MFA (skipping
// the second factor on a previously-trusted device). Gates the trusted-device
// skip and the "remember this device" option on the hosted MFA step.
func (s *Service) RememberDeviceEnabled(ctx context.Context, tenantID uuid.UUID) (bool, error) {
	p, err := s.Get(ctx, tenantID)
	if err != nil {
		return false, err
	}
	return p.RememberDeviceEnabled, nil
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
			"password_min_length":      p.PasswordMinLength,
			"password_enabled":         p.PasswordEnabled,
			"lockout_threshold":        p.LockoutThreshold,
			"lockout_window_minutes":   p.LockoutWindowMinutes,
			"lockout_duration_minutes": p.LockoutDurationMinutes,
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

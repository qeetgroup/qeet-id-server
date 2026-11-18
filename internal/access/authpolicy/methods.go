package authpolicy

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// checkSignInMethods refuses a policy that leaves no first-factor method (password, passkey or magic
// link) on unless the organization signs in through single sign-on (sso), and one that switches on an
// email or SMS one-time-code sign-in, which doesn't exist.
func checkSignInMethods(p Policy, sso bool) []errs.FieldError {
	var out []errs.FieldError
	if !p.PasswordEnabled && !p.PasskeyEnabled && !p.MagicLinkEnabled && !sso {
		out = append(out, errs.FieldError{Field: "password_enabled", Code: "no_sign_in_method",
			Message: "Keep at least one of password, passkey or magic-link sign-in on, or activate a SAML or LDAP connection first."})
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

// SelfRegistrationEnabled reports whether the organization permits hosted end-user
// self-registration.
func (s *Service) SelfRegistrationEnabled(ctx context.Context, organizationID uuid.UUID) (bool, error) {
	p, err := s.Get(ctx, organizationID)
	if err != nil {
		return false, err
	}
	return p.SelfRegistrationEnabled, nil
}

// SignInMethods are the first-factor sign-in methods an organization allows.
type SignInMethods struct {
	Password  bool `json:"password"`
	Passkey   bool `json:"passkey"`
	MagicLink bool `json:"magic_link"`
}

// SignInMethodsFor returns the sign-in methods organizationID allows; uuid.Nil (no
// organization) allows all. Read on every call — a change applies to the next
// sign-in.
func (s *Service) SignInMethodsFor(ctx context.Context, organizationID uuid.UUID) (SignInMethods, error) {
	if organizationID == uuid.Nil {
		return SignInMethods{Password: true, Passkey: true, MagicLink: true}, nil
	}
	p, err := s.Get(ctx, organizationID)
	if err != nil {
		return SignInMethods{}, err
	}
	return SignInMethods{Password: p.PasswordEnabled, Passkey: p.PasskeyEnabled, MagicLink: p.MagicLinkEnabled}, nil
}

// SignInMethodsChecker reports which ways of signing in an organization allows.
// Satisfied by *Service.
type SignInMethodsChecker interface {
	AllowedSignInMethods(ctx context.Context, organizationID uuid.UUID) (password, passkey, magicLink bool, err error)
}

// AllowedSignInMethods is SignInMethodsFor as plain values.
func (s *Service) AllowedSignInMethods(ctx context.Context, organizationID uuid.UUID) (password, passkey, magicLink bool, err error) {
	m, err := s.SignInMethodsFor(ctx, organizationID)
	return m.Password, m.Passkey, m.MagicLink, err
}

// HostedSignInPolicy is what organizationID's hosted sign-in pages say before anyone signs in: the
// rules a new password must meet (so the page can tick them off as they are met; the server still
// checks on submit), how long a sign-in link works and how long a device is remembered. None of it
// is secret: every rule is told to anyone who tries a password that breaks it.
func (s *Service) HostedSignInPolicy(ctx context.Context, organizationID uuid.UUID) (minLength int, upper, number, symbol bool, magicLinkMinutes, rememberDeviceDays int, err error) {
	p := DefaultPolicy()
	if organizationID != uuid.Nil {
		tp, gerr := s.Get(ctx, organizationID)
		if gerr != nil {
			return 0, false, false, false, 0, 0, gerr
		}
		p = *tp
	}
	return p.PasswordMinLength, p.PasswordRequireUppercase, p.PasswordRequireNumber, p.PasswordRequireSymbol,
		p.MagicLinkTTLMinutes, p.RememberDeviceDays, nil
}

// PasswordEnabled reports whether the organization permits password sign-in
// (password_enabled); uuid.Nil is not restricted.
func (s *Service) PasswordEnabled(ctx context.Context, organizationID uuid.UUID) (bool, error) {
	m, err := s.SignInMethodsFor(ctx, organizationID)
	return m.Password, err
}

// MagicLinkPolicy reports whether the organization permits magic-link sign-in and how
// long a link it issues lives (magic_link_ttl_minutes).
func (s *Service) MagicLinkPolicy(ctx context.Context, organizationID uuid.UUID) (bool, time.Duration, error) {
	p, err := s.Get(ctx, organizationID)
	if err != nil {
		return false, 0, err
	}
	return p.MagicLinkEnabled, time.Duration(p.MagicLinkTTLMinutes) * time.Minute, nil
}

// PasskeyEnabled reports whether the organization permits passkeys (passkey_enabled)
// for enrolment and sign-in.
func (s *Service) PasskeyEnabled(ctx context.Context, organizationID uuid.UUID) (bool, error) {
	p, err := s.Get(ctx, organizationID)
	if err != nil {
		return false, err
	}
	return p.PasskeyEnabled, nil
}

// RememberDeviceEnabled reports whether the organization lets an enrolled user skip
// the second factor on a remembered device.
func (s *Service) RememberDeviceEnabled(ctx context.Context, organizationID uuid.UUID) (bool, error) {
	p, err := s.Get(ctx, organizationID)
	if err != nil {
		return false, err
	}
	return p.RememberDeviceEnabled, nil
}

// RememberDevicePolicy reports whether the organization allows remembering a device
// and for how long one stays remembered.
func (s *Service) RememberDevicePolicy(ctx context.Context, organizationID uuid.UUID) (bool, time.Duration, error) {
	p, err := s.Get(ctx, organizationID)
	if err != nil {
		return false, 0, err
	}
	days := p.RememberDeviceDays
	if days == 0 {
		days = defaultRememberDeviceDays
	}
	return p.RememberDeviceEnabled, time.Duration(days) * 24 * time.Hour, nil
}

// MethodUsage is how many of the organization's people use each way of
// signing in, and how many would have no other way in without it. Magic links
// and email codes aren't counted as a way in; MagicLinkEnabled says whether
// they are one too.
type MethodUsage struct {
	People           int           `json:"people"`
	Password         MethodCount   `json:"password"`
	Passkey          MethodCount   `json:"passkey"`
	Social           []SocialCount `json:"social"`
	MagicLinkEnabled bool          `json:"magic_link_enabled"`
}

// MethodCount is the people with a way of signing in, and those with no other.
type MethodCount struct {
	People int `json:"people"`
	Only   int `json:"only"`
}

// SocialCount is a social provider's linked accounts and those it alone lets in.
type SocialCount struct {
	Provider string `json:"provider"`
	Linked   int    `json:"linked"`
	Only     int    `json:"only"`
}

// Usage counts how the organization's live accounts sign in.
func (s *Service) Usage(ctx context.Context, organizationID uuid.UUID) (*MethodUsage, error) {
	row, err := s.q.SignInMethodUsage(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	social, err := s.q.SocialProviderUsage(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	policy, err := s.Get(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := &MethodUsage{
		People:           int(row.People),
		Password:         MethodCount{People: int(row.WithPassword), Only: int(row.OnlyPassword)},
		Passkey:          MethodCount{People: int(row.WithPasskey), Only: int(row.OnlyPasskey)},
		Social:           make([]SocialCount, len(social)),
		MagicLinkEnabled: policy.MagicLinkEnabled,
	}
	for i, p := range social {
		out.Social[i] = SocialCount{Provider: p.Provider, Linked: int(p.Linked), Only: int(p.Only)}
	}
	return out, nil
}

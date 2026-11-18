package authpolicy

import (
	"context"
	"fmt"
	"strings"
	"unicode"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// BreachedPasswordDetail is the user-safe 422 message shown when a password is
// rejected for appearing in known breaches. It deliberately omits the sighting
// count so we don't reveal breach-corpus details to the end user.
const BreachedPasswordDetail = "This password has appeared in known data breaches — choose a different one."

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

// PasswordRules checks a new password: ValidateForOrganization's rules, strength
// and breach checks. Satisfied by *Service.
type PasswordRules interface {
	ValidateForOrganization(ctx context.Context, organizationID uuid.UUID, email, pw string) error
}

// ValidateForOrganization is the check every path that sets a password runs, so a
// password is judged the same everywhere: organizationID's rules (DefaultPolicy for
// uuid.Nil), the offline strength baseline (email may be empty), then the
// breach check, which fails open. It returns the first failure, never echoing pw.
func (s *Service) ValidateForOrganization(ctx context.Context, organizationID uuid.UUID, email, pw string) error {
	p := DefaultPolicy()
	if organizationID != uuid.Nil {
		tp, err := s.Get(ctx, organizationID)
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

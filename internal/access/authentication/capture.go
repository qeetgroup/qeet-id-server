package auth

import "context"

// DomainCapture decides whether an address must sign in through its
// organisation's identity provider. RefuseCaptured returns
// errs.ErrAuthSSORequired for an address on a captured domain that isn't one of
// the organisation's break-glass members, deciding without asking whether the
// address has an account. Satisfied by *domainverify.Service.
type DomainCapture interface {
	RefuseCaptured(ctx context.Context, email string) error
}

// SetDomainCapture wires domain capture into password sign-in and sign-up
// (nil: no address is captured).
func (s *Service) SetDomainCapture(c DomainCapture) { s.capture = c }

// refuseCaptured refuses the address's own sign-in methods when its domain
// is captured.
func (s *Service) refuseCaptured(ctx context.Context, email string) error {
	if s.capture == nil {
		return nil
	}
	return s.capture.RefuseCaptured(ctx, email)
}

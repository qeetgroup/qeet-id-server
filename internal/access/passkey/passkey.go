// Package passkey implements WebAuthn passkey registration and login on top of
// go-webauthn. The credential store (auth.passkey_credentials) backs
// list/rename/delete and the ceremony; in-flight challenges live in
// auth.webauthn_sessions.
package passkey

import (
	"context"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/access/passkey/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// Service runs passkey ceremonies and manages stored passkeys. policy says
// whether an organization permits passkeys (nil: no restriction); invitations
// lets an invited person found an account on a passkey (nil: that path is off);
// sender emails the account holder when one is added or removed (nil: no one);
// capture refuses passkey sign-in and sign-up to an address whose organization
// requires single sign-on (nil: none is refused).
type Service struct {
	pool        *pgxpool.Pool
	q           *dbgen.Queries
	wa          *webauthn.WebAuthn
	auth        *auth.Service
	policy      MethodPolicy
	invitations InvitationAcceptor
	sender      notifier.Sender
	capture     auth.DomainCapture
}

// NewService returns the passkey service.
func NewService(pool *pgxpool.Pool, wa *webauthn.WebAuthn, authSvc *auth.Service) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), wa: wa, auth: authSvc}
}

// SetSender sets how the account holder is emailed when a passkey is added to
// or removed from their account.
func (s *Service) SetSender(sender notifier.Sender) { s.sender = sender }

// MethodPolicy says whether an organization permits passkeys. It is satisfied
// by *authpolicy.Service without this package importing it.
type MethodPolicy interface {
	PasskeyEnabled(ctx context.Context, organizationID uuid.UUID) (bool, error)
}

// SetMethodPolicy wires the organization's passkey on/off setting.
func (s *Service) SetMethodPolicy(p MethodPolicy) { s.policy = p }

// SetDomainCapture wires domain capture into passkey sign-in and sign-up.
func (s *Service) SetDomainCapture(c auth.DomainCapture) { s.capture = c }

// refuseCaptured returns errs.ErrAuthSSORequired when email's domain is
// captured.
func (s *Service) refuseCaptured(ctx context.Context, email string) error {
	if s.capture == nil {
		return nil
	}
	return s.capture.RefuseCaptured(ctx, email)
}

// passkeysAllowed returns ErrPasskeyDisabled if organizationID's policy switches
// passkeys off. uuid.Nil (a user without an organization) is not restricted.
func (s *Service) passkeysAllowed(ctx context.Context, organizationID uuid.UUID) error {
	if organizationID == uuid.Nil || s.policy == nil {
		return nil
	}
	enabled, err := s.policy.PasskeyEnabled(ctx, organizationID)
	if err != nil {
		return err
	}
	if !enabled {
		return ErrDisabled
	}
	return nil
}

// Requester is who changes a passkey, for its audit record: the account
// holder's request, and the organization their session is in (nil: none).
type Requester struct {
	audit.Actor
	OrganizationID *uuid.UUID
}

// event returns the audit event of action on userID's account.
func (r Requester) event(action string, userID uuid.UUID, metadata map[string]any) audit.Event {
	return r.EventIn(r.OrganizationID, action, "user", userID, metadata)
}

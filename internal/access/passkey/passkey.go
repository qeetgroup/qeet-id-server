// Package passkey implements WebAuthn passkey registration and login on top of
// go-webauthn. The credential store (auth.passkey_credentials) backs
// list/rename/delete and the ceremony; in-flight challenges live in
// auth.webauthn_sessions.
package passkey

import (
	"context"
	"errors"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/access/passkey/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
)

// RelyingParty is the WebAuthn relying party and its store of in-flight
// ceremonies: all a passkey second factor needs (see mfa.go), so the
// second-factor service is built before the sign-in service it serves.
type RelyingParty struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
	wa   *webauthn.WebAuthn
}

// NewRelyingParty returns the relying party wa over pool.
func NewRelyingParty(pool *pgxpool.Pool, wa *webauthn.WebAuthn) (*RelyingParty, error) {
	if wa == nil {
		return nil, errors.New("passkey: the relying party needs a WebAuthn configuration")
	}
	return &RelyingParty{pool: pool, q: dbgen.New(pool), wa: wa}, nil
}

// Service runs passkey ceremonies and manages stored passkeys. policy says whether an organization
// permits passkeys; invitations let an invited person found an account on one; sender emails the
// holder when one is added or removed; capture refuses passkeys for addresses that require SSO.
type Service struct {
	*RelyingParty
	auth        *authentication.Service
	policy      MethodPolicy
	invitations InvitationAcceptor
	sender      notifier.Sender
	capture     authentication.DomainCapture
}

// Deps are what the passkey service is built from, all required.
type Deps struct {
	RelyingParty *RelyingParty
	Auth         *authentication.Service      // signs a person in once a passkey proves them
	Policy       MethodPolicy                 // the organization's passkey on/off setting
	Invitations  InvitationAcceptor           // accepts an invitation with a passkey
	Sender       notifier.Sender              // tells the account holder of a passkey added or removed
	Capture      authentication.DomainCapture // refuses passkey sign-in and sign-up on a captured domain
}

// NewService returns the passkey service built from d.
func NewService(d Deps) (*Service, error) {
	switch {
	case d.RelyingParty == nil:
		return nil, errors.New("passkey: the passkey service needs a relying party")
	case d.Auth == nil:
		return nil, errors.New("passkey: the passkey service needs the sign-in service")
	case d.Policy == nil:
		return nil, errors.New("passkey: the passkey service needs a method policy")
	case d.Invitations == nil:
		return nil, errors.New("passkey: the passkey service needs invitations")
	case d.Sender == nil:
		return nil, errors.New("passkey: the passkey service needs a sender")
	case d.Capture == nil:
		return nil, errors.New("passkey: the passkey service needs domain capture")
	}
	return &Service{RelyingParty: d.RelyingParty, auth: d.Auth, policy: d.Policy, invitations: d.Invitations,
		sender: d.Sender, capture: d.Capture}, nil
}

// MethodPolicy says whether an organization permits passkeys. It is satisfied
// by *authpolicy.Service without this package importing it.
type MethodPolicy interface {
	PasskeyEnabled(ctx context.Context, organizationID uuid.UUID) (bool, error)
}

// refuseCaptured returns errs.ErrAuthSSORequired when email's domain is
// captured.
func (s *Service) refuseCaptured(ctx context.Context, email string) error {
	return s.capture.RefuseCaptured(ctx, email)
}

// passkeysAllowed returns ErrPasskeyDisabled if organizationID's policy switches
// passkeys off. uuid.Nil (a user without an organization) is not restricted.
func (s *Service) passkeysAllowed(ctx context.Context, organizationID uuid.UUID) error {
	if organizationID == uuid.Nil {
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

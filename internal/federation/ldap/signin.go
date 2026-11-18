package ldap

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/federation/provision"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
)

// findOrCreateUser returns the account the connection signs in for the
// directory user u, found, adopted or created by identitylink's rules, which
// also keep its profile and groups in step with the directory, recorded as
// actor's, and store its mapped profile.
func (s *Service) findOrCreateUser(ctx context.Context, organizationID, connID uuid.UUID, u *ldapUser, actor audit.Actor) (uuid.UUID, error) {
	return s.link.Resolve(ctx, provision.Source{OrganizationID: organizationID, Provider: provider, ConnectionID: connID},
		provision.Person{Subject: u.DN, Email: u.Email, Name: u.Name, Groups: u.Groups, Profile: u.Profile}, actor)
}

// Login checks the password with the directory and signs the person in as a
// password sign-in to the connection's organization is (auth.SignInExternal):
// under its address, lockout, hook, risk and second-factor rules. The result
// is a token pair, or a challenge to complete at /v1/auth/mfa.
func (s *Service) Login(ctx context.Context, connID uuid.UUID, username, password, ip, ua string) (*auth.LoginResult, error) {
	return directorySignIn(ctx, s, connID, username, password, ip, ua, s.auth.SignInExternal)
}

// LoginSession is Login for the hosted login: the same checks, ending in the hosted login
// session, or the challenge to complete first.
func (s *Service) LoginSession(ctx context.Context, connID uuid.UUID, username, password, ip, ua string) (*auth.LoginSessionResult, error) {
	return directorySignIn(ctx, s, connID, username, password, ip, ua, s.auth.SignInExternalSession)
}

// directorySignIn signs username in through connection connID with password,
// recording the operation: the connection must be active and the plan include
// LDAP, then finish runs the sign-in's checks around the directory bind and
// says how it ends.
func directorySignIn[R any](ctx context.Context, s *Service, connID uuid.UUID, username, password, ip, ua string,
	finish func(context.Context, auth.ExternalSignIn, auth.ExternalCheck) (R, error)) (res R, resultError error) {
	c, err := s.getFull(ctx, connID, uuid.Nil)
	if err != nil {
		return res, err
	}
	started := time.Now()
	var signedIn *uuid.UUID
	defer func() { s.recordOperation(ctx, c, "sign-in", "user", started, resultError, username, signedIn) }()
	// A draft connection is still being set up: it signs nobody in until an
	// administrator turns it on.
	switch c.Status {
	case "active":
	case "draft":
		return res, ErrConnectionDraft
	default:
		return res, ErrConnectionDisabled
	}
	// The plan is checked at every sign-in, not only when the connection was
	// set up, so one set up on a plan that has since lapsed signs no one in.
	if err := s.requireLDAP(ctx, c.OrganizationID); err != nil {
		return res, err
	}
	if username == "" || password == "" {
		return res, ErrCredentialsRequired
	}
	res, err = finish(ctx, auth.ExternalSignIn{
		OrganizationID: c.OrganizationID,
		Account:        provider + ":" + connID.String() + ":" + lockoutName(username),
		Method:         provider,
		IP:             ip,
		UserAgent:      ua,
	}, func(ctx context.Context) (uuid.UUID, bool, error) {
		du, err := s.authenticate(ctx, c, username, password)
		if err != nil {
			return uuid.Nil, errors.Is(err, ErrInvalidCredentials), err
		}
		userID, err := s.findOrCreateUser(ctx, c.OrganizationID, connID, du,
			audit.Actor{Type: provider, IP: ip, UserAgent: ua, RequestID: middleware.GetReqID(ctx)})
		if err == nil {
			signedIn = &userID
		}
		return userID, false, err
	})
	if err != nil {
		var none R
		return none, err
	}
	_ = s.q.TouchLdapLastLogin(ctx, connID)
	return res, nil
}

// lockoutName is username as the lockout counts it: lower-cased, with runs of
// spaces made one and none at either end, as directories compare names, so
// one account's spellings share a counter.
func lockoutName(username string) string {
	return strings.ToLower(strings.Join(strings.Fields(username), " "))
}

// ProfileMapper maps directory attributes to a profile.
type ProfileMapper interface {
	SourceAttributes(context.Context, uuid.UUID, string) ([]string, error)
	MapProfile(context.Context, uuid.UUID, string, map[string]any, bool) (map[string]any, error)
	StoreProfile(context.Context, pgx.Tx, uuid.UUID, uuid.UUID, string, map[string]any) error
}

// SetProfileMapper sets the mapper applied to signed-in directory accounts.
func (service *Service) SetProfileMapper(mapper ProfileMapper) { service.mapper = mapper }

// storeMappedProfile stores the profile the connection's mapping made of the
// directory user's attributes, in the sign-in's transaction (identitylink's
// Flow.Store).
func (service *Service) storeMappedProfile(ctx context.Context, tx pgx.Tx, src provision.Source, userID uuid.UUID, p provision.Person) error {
	if service.mapper == nil || len(p.Profile) == 0 {
		return nil
	}
	return service.mapper.StoreProfile(ctx, tx, src.OrganizationID, userID, src.ConnectionID.String(), p.Profile)
}

package authentication

import (
	"context"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// An external sign-in proves its first factor outside this service, as a
// directory bind does, then gets the address, lockout, hook, risk and
// second-factor decisions of a password sign-in: a token pair, or a challenge
// completed at /v1/auth/mfa as for a password sign-in.

// ExternalSignIn is a sign-in whose first factor another system checks.
type ExternalSignIn struct {
	OrganizationID uuid.UUID // the organization signed in to, whose policies apply
	// Account keys the lockout counters; it should be unique to the source,
	// such as "ldap:<connection id>:<username>".
	Account string
	// Method is the first factor, recorded on the session and any challenge;
	// "ldap" is the one sign-in challenges accept.
	Method string
	// Actor is the client's address and user agent.
	audit.Actor
}

// ExternalCheck checks the first factor and returns the account it proved.
// rejected reports a refused credential, which the lockout counts as it does
// a wrong password.
type ExternalCheck func(ctx context.Context) (userID uuid.UUID, rejected bool, err error)

// SignInExternal checks the organization's address rules, then runs check
// under the sign-in lockout and, once it proves an account, applies the account
// status, login hook, risk assessment and second-factor requirement. It returns
// a token pair or the challenge to meet first.
func (s *Service) SignInExternal(ctx context.Context, in ExternalSignIn, check ExternalCheck) (*LoginResult, error) {
	userID, claims, challenge, err := s.externalFirstFactor(ctx, in, check)
	if err != nil {
		return nil, err
	}
	if challenge != nil {
		return &LoginResult{MFAChallenge: *challenge}, nil
	}
	pair, err := s.IssuePairWithClaims(ctx, userID, in.OrganizationID, in.IP, in.UserAgent, in.Method, claims)
	if err != nil {
		return nil, err
	}
	s.recordSignIn(ctx, userID, in.OrganizationID, in.UserAgent, httpx.GeoCountry(ctx))
	return &LoginResult{Pair: pair}, nil
}

// SignInExternalSession is SignInExternal for the hosted login: the same checks, ending in the
// hosted login session (its cookie value) instead of a token pair, or the challenge to complete
// first at POST /v1/auth/session/mfa.
func (s *Service) SignInExternalSession(ctx context.Context, in ExternalSignIn, check ExternalCheck) (*LoginSessionResult, error) {
	userID, _, challenge, err := s.externalFirstFactor(ctx, in, check)
	if err != nil {
		return nil, err
	}
	if challenge != nil {
		return &LoginSessionResult{UserID: userID, MFAChallenge: *challenge}, nil
	}
	raw, err := s.createLoginSession(ctx, userID, in.OrganizationID, in.IP, in.UserAgent, in.Method, "")
	if err != nil {
		return nil, err
	}
	s.recordSignIn(ctx, userID, in.OrganizationID, in.UserAgent, httpx.GeoCountry(ctx))
	return &LoginSessionResult{UserID: userID, RawCookie: raw}, nil
}

// externalFirstFactor runs an external sign-in up to its last step: the account it proved, the
// hook's claims, and the challenge to meet when a second factor is due (nil when none is).
func (s *Service) externalFirstFactor(ctx context.Context, in ExternalSignIn, check ExternalCheck) (uuid.UUID, map[string]any, *MFAChallenge, error) {
	// Before the first factor, so the answer from a refused network is the same
	// whether or not the credential is right.
	if err := s.checkAddress(ctx, in.OrganizationID, uuid.Nil, in.IP, in.Method); err != nil {
		return uuid.Nil, nil, nil, err
	}
	attempt, err := s.signInAttemptIn(ctx, in.OrganizationID, in.Account, in.IP)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	failure := SignInFailure{OrganizationID: in.OrganizationID, Method: in.Method, Actor: in.Actor}
	if err := s.refuseLocked(ctx, attempt, failure, nil); err != nil {
		return uuid.Nil, nil, nil, err
	}
	userID, rejected, err := check(ctx)
	if err != nil {
		if rejected {
			failure.Reason = FailureWrongPassword
			if rerr := s.recordFailedSignIn(ctx, attempt, failure); rerr != nil {
				return uuid.Nil, nil, nil, rerr
			}
		}
		return uuid.Nil, nil, nil, err
	}
	if err := s.clearFailedSignIns(ctx, attempt); err != nil {
		return uuid.Nil, nil, nil, err
	}
	if err := s.refuseInactiveAccount(ctx, userID, in.OrganizationID, in.Method, in.IP, in.UserAgent); err != nil {
		return uuid.Nil, nil, nil, err
	}
	u, err := s.users.Get(ctx, userID)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	claims, err := s.hookClaims(ctx, in.OrganizationID, u)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	gate, err := s.mfaGateFor(ctx, userID, u.OrganizationID, in.OrganizationID)
	if err != nil {
		return uuid.Nil, nil, nil, err
	}
	switch s.nextSignInStep(ctx, userID, in.OrganizationID, gate, in.Method, "", in.IP, in.UserAgent, httpx.GeoCountry(ctx)) {
	case stepChallenge:
		challenge, err := s.challengeSignIn(ctx, userID, in.OrganizationID, claims, gate, in.Method, in.IP, in.UserAgent)
		if err != nil {
			return uuid.Nil, nil, nil, err
		}
		return userID, claims, &challenge, nil
	case stepRiskEmail:
		challenge, err := s.riskEmailChallenge(ctx, userID, in.OrganizationID, claims, in.Method, in.IP, in.UserAgent)
		if err != nil {
			return uuid.Nil, nil, nil, err
		}
		return userID, claims, &challenge, nil
	}
	return userID, claims, nil, nil
}

// BeginSSOLoginSession signs a person an organization's identity provider authenticated (SAML or
// OpenID Connect single sign-on) in to the hosted login: the organization's address rules, then
// the hosted login session. As the console's SSO sign-in, it asks for no second factor: the
// identity provider decides how its people prove who they are.
func (s *Service) BeginSSOLoginSession(ctx context.Context, userID, organizationID uuid.UUID, method, ip, ua string) (string, error) {
	if err := s.checkAddress(ctx, organizationID, userID, ip, "hosted_"+method); err != nil {
		return "", err
	}
	raw, err := s.createLoginSession(ctx, userID, organizationID, ip, ua, method, "")
	if err != nil {
		return "", err
	}
	s.recordSignIn(ctx, userID, organizationID, ua, httpx.GeoCountry(ctx))
	return raw, nil
}

package auth

import (
	"context"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// An external sign-in proves its first factor outside this service, as a
// directory bind does, then gets the address, lockout, hook, risk and
// second-factor decisions of a password sign-in: a token pair, or a challenge
// completed at /v1/auth/mfa as for a password sign-in.

// ExternalSignIn is a sign-in whose first factor another system checks.
type ExternalSignIn struct {
	TenantID uuid.UUID // the organisation signed in to, whose policies apply
	// Account keys the lockout counters; it should be unique to the source,
	// such as "ldap:<connection id>:<username>".
	Account string
	// Method is the first factor, recorded on the session and any challenge;
	// "ldap" is the one sign-in challenges accept.
	Method    string
	IP        string // the client address
	UserAgent string // the client's User-Agent
}

// ExternalCheck checks the first factor and returns the account it proved.
// rejected reports a refused credential, which the lockout counts as it does
// a wrong password.
type ExternalCheck func(ctx context.Context) (userID uuid.UUID, rejected bool, err error)

// SignInExternal checks the organisation's address rules, then runs check
// under the sign-in lockout and, once it proves an account, applies the account
// status, login hook, risk assessment and second-factor requirement. It returns
// a token pair or the challenge to meet first.
func (s *Service) SignInExternal(ctx context.Context, in ExternalSignIn, check ExternalCheck) (*LoginResult, error) {
	// Before the first factor, so the answer from a refused network is the same
	// whether or not the credential is right.
	if err := s.checkAddress(ctx, in.TenantID, uuid.Nil, in.IP, in.Method); err != nil {
		return nil, err
	}
	attempt, err := s.signInAttemptIn(ctx, in.TenantID, in.Account, in.IP)
	if err != nil {
		return nil, err
	}
	failure := SignInFailure{TenantID: in.TenantID, Method: in.Method, IP: in.IP, UserAgent: in.UserAgent}
	if err := s.refuseLocked(ctx, attempt, failure, nil); err != nil {
		return nil, err
	}
	userID, rejected, err := check(ctx)
	if err != nil {
		if rejected {
			failure.Reason = FailureWrongPassword
			if rerr := s.recordFailedSignIn(ctx, attempt, failure); rerr != nil {
				return nil, rerr
			}
		}
		return nil, err
	}
	if err := s.clearFailedSignIns(ctx, attempt); err != nil {
		return nil, err
	}
	if err := s.refuseInactiveAccount(ctx, userID, in.TenantID, in.Method, in.IP, in.UserAgent); err != nil {
		return nil, err
	}
	u, err := s.users.Get(ctx, userID)
	if err != nil {
		return nil, err
	}
	claims, err := s.hookClaims(ctx, in.TenantID, u)
	if err != nil {
		return nil, err
	}
	gate, err := s.mfaGateFor(ctx, userID, u.TenantID, in.TenantID)
	if err != nil {
		return nil, err
	}
	switch s.nextSignInStep(ctx, userID, in.TenantID, gate, in.Method, "", in.IP, in.UserAgent, httpx.GeoCountry(ctx)) {
	case stepChallenge:
		challenge, err := s.challengeSignIn(ctx, userID, in.TenantID, claims, gate, in.Method, in.IP, in.UserAgent)
		if err != nil {
			return nil, err
		}
		return &LoginResult{MFAChallenge: challenge}, nil
	case stepRiskEmail:
		challenge, err := s.riskEmailChallenge(ctx, userID, in.TenantID, claims, in.Method, in.IP, in.UserAgent)
		if err != nil {
			return nil, err
		}
		return &LoginResult{MFAChallenge: challenge}, nil
	}
	pair, err := s.IssuePairWithClaims(ctx, userID, in.TenantID, in.IP, in.UserAgent, in.Method, claims)
	if err != nil {
		return nil, err
	}
	s.recordSignIn(ctx, userID, in.TenantID, in.UserAgent, httpx.GeoCountry(ctx))
	return &LoginResult{Pair: pair}, nil
}

package auth

import (
	"context"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// A social sign-in — Google, Microsoft, GitHub, Apple, or an organisation's
// own provider — proves the first factor through the provider, and then takes
// the same second-factor, enrolment and risk decision as a password or
// magic-link sign-in (QTID-801): an account holding a factor is challenged
// for it, one an organisation requires a factor of and holding none sets one
// up first, and a risky sign-in is confirmed. Before, the provider's word
// alone issued the session, so anyone who could sign in to the person's
// provider account got past the factor they had set up. The challenge records
// the provider as its first factor, so the session it completes is a
// "social_mfa" sign-in.

// BeginSocialSignIn signs in the account a social sign-in to tenantID
// (uuid.Nil: the console's own, tenant-less) completed for: a token pair, or a
// challenge to complete first (at /v1/auth/mfa, as for a password sign-in).
func (s *Service) BeginSocialSignIn(ctx context.Context, userID, tenantID uuid.UUID, ip, ua string) (*LoginResult, error) {
	gate, err := s.mfaGate(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	switch s.nextSignInStep(ctx, userID, tenantID, gate, firstFactorSocial, "", ip, ua, httpx.GeoCountry(ctx)) {
	case stepChallenge:
		challenge, err := s.challengeSignIn(ctx, userID, tenantID, nil, gate, firstFactorSocial, ip, ua)
		if err != nil {
			return nil, err
		}
		return &LoginResult{MFAChallenge: challenge}, nil
	case stepRiskEmail:
		challenge, err := s.riskEmailChallenge(ctx, userID, tenantID, nil, firstFactorSocial, ip, ua)
		if err != nil {
			return nil, err
		}
		return &LoginResult{MFAChallenge: challenge}, nil
	}
	pair, err := s.IssuePair(ctx, userID, tenantID, ip, ua, firstFactorSocial)
	if err != nil {
		return nil, err
	}
	return &LoginResult{Pair: pair}, nil
}

// BeginSocialLoginSession is BeginLoginSession for a hosted social sign-in to
// tenantID, the organisation whose provider it used: the hosted sign-in cookie
// value, or a challenge to complete first (at /v1/auth/session/mfa). The
// account's own organisation's requirement applies as well as tenantID's. A
// remembered device may skip the factor on the same terms as the hosted
// password sign-in, and never the setting up of one the account must have.
func (s *Service) BeginSocialLoginSession(ctx context.Context, userID, tenantID uuid.UUID, ip, ua, trustedToken, country string) (*LoginSessionResult, error) {
	u, err := s.users.Get(ctx, userID)
	if err != nil {
		return nil, err
	}
	gate, err := s.mfaGateFor(ctx, userID, u.TenantID, tenantID)
	if err != nil {
		return nil, err
	}
	switch s.nextSignInStep(ctx, userID, tenantID, gate, firstFactorSocial, trustedToken, ip, ua, country) {
	case stepChallenge:
		challenge, err := s.challengeSignIn(ctx, userID, tenantID, nil, gate, firstFactorSocial, ip, ua)
		if err != nil {
			return nil, err
		}
		return &LoginSessionResult{UserID: userID, MFAChallenge: challenge}, nil
	case stepRiskEmail:
		challenge, err := s.riskEmailChallenge(ctx, userID, tenantID, nil, firstFactorSocial, ip, ua)
		if err != nil {
			return nil, err
		}
		return &LoginSessionResult{UserID: userID, MFAChallenge: challenge}, nil
	}
	raw, err := s.createLoginSession(ctx, userID, ip, ua, gate.skippedFactor())
	if err != nil {
		return nil, err
	}
	return &LoginSessionResult{UserID: userID, RawCookie: raw}, nil
}

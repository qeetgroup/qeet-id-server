package auth

import (
	"context"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// A social sign-in proves the first factor through the provider and then gets
// the same second-factor, enrolment and risk decision as a password sign-in.
// The completed session is recorded as a "social_mfa" sign-in.

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
// tenantID. It returns the SSO cookie value or a challenge to complete first.
// Both tenantID's and the account's own organisation's MFA requirements apply.
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

package auth

import (
	"context"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// A magic link proves only that the person can read the account's email, so it
// gets the same second-factor decision as a password sign-in. The link is spent
// before any challenge, and the completed session is recorded as a
// "magic_link_mfa" sign-in.

// BeginMagicLinkSignIn signs in the account a console magic link was consumed
// for: a token pair, or a challenge to complete first.
func (s *Service) BeginMagicLinkSignIn(ctx context.Context, userID, tenantID uuid.UUID, ip, ua string) (*LoginResult, error) {
	claims, err := s.signInHook(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	gate, err := s.mfaGate(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	if s.nextSignInStep(ctx, userID, tenantID, gate, firstFactorMagicLink, "", ip, ua, httpx.GeoCountry(ctx)) == stepChallenge {
		challenge, err := s.challengeSignIn(ctx, userID, tenantID, claims, gate, firstFactorMagicLink, ip, ua)
		if err != nil {
			return nil, err
		}
		return &LoginResult{MFAChallenge: challenge}, nil
	}
	pair, err := s.IssuePairWithClaims(ctx, userID, tenantID, ip, ua, firstFactorMagicLink, claims)
	if err != nil {
		return nil, err
	}
	s.recordSignIn(ctx, userID, tenantID, ua, httpx.GeoCountry(ctx))
	return &LoginResult{Pair: pair}, nil
}

// BeginMagicLinkSession is BeginLoginSession for a consumed hosted-login magic
// link. It returns the SSO cookie value or a challenge to complete first; a
// trusted device can skip the challenge as for a hosted password sign-in.
func (s *Service) BeginMagicLinkSession(ctx context.Context, userID, tenantID uuid.UUID, ip, ua, trustedToken, country string) (*LoginSessionResult, error) {
	// The link was sent for tenantID: its address rules decide, here.
	if err := s.checkAddress(ctx, tenantID, userID, ip, "hosted_magic_link"); err != nil {
		return nil, err
	}
	claims, err := s.signInHook(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	gate, err := s.mfaGate(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	if s.nextSignInStep(ctx, userID, tenantID, gate, firstFactorMagicLink, trustedToken, ip, ua, country) == stepChallenge {
		challenge, err := s.challengeSignIn(ctx, userID, tenantID, claims, gate, firstFactorMagicLink, ip, ua)
		if err != nil {
			return nil, err
		}
		return &LoginSessionResult{UserID: userID, MFAChallenge: challenge}, nil
	}
	raw, err := s.createLoginSession(ctx, userID, ip, ua, gate.skippedFactor())
	if err != nil {
		return nil, err
	}
	s.recordSignIn(ctx, userID, tenantID, ua, country)
	return &LoginSessionResult{UserID: userID, RawCookie: raw}, nil
}

package auth

import (
	"context"

	"github.com/google/uuid"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// A magic link proves only that the person can read the account's email: a
// first factor, as a password is. Completing one therefore meets the same
// second-factor decision as password sign-in (mfaGate, see mfapolicy.go): an
// account holding a factor, or required to have one, gets a challenge instead
// of a session, completed at the same endpoints (POST /v1/auth/mfa for the
// console link, /v1/auth/session/mfa for the hosted-login one) and drawing on
// the same attempt budget. The link is spent before the challenge is raised,
// so an abandoned or failed challenge leaves neither a session nor a link to
// use again. The challenge records the link as its first factor, so the
// session it completes is a "magic_link_mfa" sign-in.

// BeginMagicLinkSignIn signs in the account a console magic link was consumed
// for: a token pair, or a challenge to complete first.
func (s *Service) BeginMagicLinkSignIn(ctx context.Context, userID, tenantID uuid.UUID, ip, ua string) (*LoginResult, error) {
	gate, err := s.mfaGate(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	if s.nextSignInStep(ctx, userID, tenantID, gate, firstFactorMagicLink, "", ip, ua, httpx.GeoCountry(ctx)) == stepChallenge {
		challenge, err := s.challengeSignIn(ctx, userID, tenantID, nil, gate, firstFactorMagicLink, ip, ua)
		if err != nil {
			return nil, err
		}
		return &LoginResult{MFAChallenge: challenge}, nil
	}
	pair, err := s.IssuePair(ctx, userID, tenantID, ip, ua, firstFactorMagicLink)
	if err != nil {
		return nil, err
	}
	return &LoginResult{Pair: pair}, nil
}

// BeginMagicLinkSession is BeginLoginSession for a consumed hosted-login magic
// link: the SSO session cookie value, or a challenge to complete first. A
// trusted device may skip the challenge on the same terms as the hosted
// password sign-in — the organisation allows it, the request carries a live
// trusted-device token of the account's, and the request's risk does not
// override it — and never the setting up of a factor the account must have.
func (s *Service) BeginMagicLinkSession(ctx context.Context, userID, tenantID uuid.UUID, ip, ua, trustedToken, country string) (*LoginSessionResult, error) {
	// The link was sent for tenantID: its address rules decide, here.
	if err := s.checkAddress(ctx, tenantID, userID, ip, "hosted_magic_link"); err != nil {
		return nil, err
	}
	gate, err := s.mfaGate(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	if s.nextSignInStep(ctx, userID, tenantID, gate, firstFactorMagicLink, trustedToken, ip, ua, country) == stepChallenge {
		challenge, err := s.challengeSignIn(ctx, userID, tenantID, nil, gate, firstFactorMagicLink, ip, ua)
		if err != nil {
			return nil, err
		}
		return &LoginSessionResult{UserID: userID, MFAChallenge: challenge}, nil
	}
	raw, err := s.CreateLoginSession(ctx, userID, ip, ua)
	if err != nil {
		return nil, err
	}
	return &LoginSessionResult{UserID: userID, RawCookie: raw}, nil
}

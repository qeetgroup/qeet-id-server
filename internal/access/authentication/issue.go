package authentication

import (
	"context"
	"encoding/json"
	"maps"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// signInHook runs the login hook for userID signing in to organizationID, or to
// their own organization for uuid.Nil. Every sign-in runs it once its first
// factor is proven, so a refusal applies whatever the method.
func (s *Service) signInHook(ctx context.Context, userID, organizationID uuid.UUID) (map[string]any, error) {
	u, err := s.users.Get(ctx, userID)
	if err != nil {
		return nil, err
	}
	if organizationID == uuid.Nil {
		organizationID = u.OrganizationID
	}
	return s.hookClaims(ctx, organizationID, u)
}

// hookClaims runs the login hook for a sign-in of u to organizationID: the organization's
// policy endpoint may deny it, or supply claims to carry into the token.
func (s *Service) hookClaims(ctx context.Context, organizationID uuid.UUID, u *user.User) (map[string]any, error) {
	return s.loginHook.Run(ctx, organizationID, u.ID, u.Email)
}

// IssuePair runs the login hook, then creates a session, issues an access and
// refresh token pair carrying the hook's claims, and records the sign-in
// method in an audit row in the same transaction. The hook may refuse the
// sign-in.
func (s *Service) IssuePair(ctx context.Context, userID, organizationID uuid.UUID, ip, ua, method string) (*TokenPair, error) {
	claims, err := s.signInHook(ctx, userID, organizationID)
	if err != nil {
		return nil, err
	}
	return s.issuePair(ctx, userID, organizationID, ip, ua, method, claims)
}

// IssuePairWithClaims is IssuePair for a sign-in whose login hook has already
// run: claims are its answer, injected into the access token.
func (s *Service) IssuePairWithClaims(ctx context.Context, userID, organizationID uuid.UUID, ip, ua, method string, claims map[string]any) (*TokenPair, error) {
	return s.issuePair(ctx, userID, organizationID, ip, ua, method, claims)
}

func (s *Service) issuePair(ctx context.Context, userID, organizationID uuid.UUID, ip, ua, method string, claims map[string]any) (*TokenPair, error) {
	if err := s.refuseSignIn(ctx, userID, organizationID, method, ip, ua); err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	pair, err := s.issuePairTx(ctx, tx, userID, organizationID, ip, ua, method, claims, nil, time.Time{})
	if err != nil {
		return nil, s.signInFailed(ctx, tx, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	countSignIn(method)
	return pair, nil
}

// issuePairTx is issuePair inside the caller's transaction, begun once
// refuseSignIn has passed and committed by the caller. Hook claims are stored
// with the session so renewals issue them again; auditMeta (may be nil) joins
// the audit record; the session ends no later than notAfter (zero: no bound).
func (s *Service) issuePairTx(ctx context.Context, tx pgx.Tx, userID, organizationID uuid.UUID, ip, ua, method string, claims, auditMeta map[string]any, notAfter time.Time) (*TokenPair, error) {
	sessionID := uuid.New()
	// uuid.Nil = organization-less: store NULL (the zero UUID would violate the FK).
	organizationPtr := orNil(organizationID)
	var hookClaims []byte
	if len(claims) > 0 {
		raw, err := json.Marshal(claims)
		if err != nil {
			return nil, err
		}
		hookClaims = raw
	}
	// The organization's limit on one person's simultaneous sessions.
	if organizationID != uuid.Nil {
		if err := s.enforceSessionLimit(ctx, tx, userID, organizationID, ip, ua); err != nil {
			return nil, err
		}
	}
	// The organization's own session bounds, else the platform's; taken now,
	// so a later change to the policy applies to new sessions only.
	maxAge, idle := s.sessionDefaults()
	bounds, err := s.q.WithTx(tx).InsertSession(ctx, dbgen.InsertSessionParams{
		ID: sessionID, UserID: userID, OrganizationID: organizationPtr, Ip: ip, UserAgent: &ua, HookClaims: hookClaims,
		MaxAgeS: maxAge.Seconds(), IdleS: idle.Seconds(), NotAfter: postgres.NullIfZero(notAfter),
		Country: httpx.GeoCountry(ctx), SecondFactor: secondFactorOfMethod(method), City: httpx.GeoCity(ctx),
	})
	if err != nil {
		return nil, err
	}
	sessionExp, idleExp := bounds.ExpiresAt, bounds.IdleExpiresAt
	access, exp, err := s.tokens.IssueSessionAccess(userID, organizationID, sessionID, claims, sessionExp)
	if err != nil {
		return nil, err
	}
	refreshRaw, refreshHash, err := tokens.NewRefreshToken()
	if err != nil {
		return nil, err
	}
	if _, err := s.q.WithTx(tx).InsertRefreshToken(ctx, dbgen.InsertRefreshTokenParams{
		SessionID: sessionID,
		TokenHash: refreshHash,
		ExpiresAt: s.refreshExpiry(sessionExp),
	}); err != nil {
		return nil, err
	}
	if factor := secondFactorOfMethod(method); factor != "" && auditMeta["second_factor"] == nil {
		auditMeta = maps.Clone(auditMeta)
		if auditMeta == nil {
			auditMeta = map[string]any{}
		}
		auditMeta["second_factor"] = factor
	}
	if err := audit.Record(ctx, tx, signInEvent(userID, organizationID, "session", sessionID, ip, ua, method, auditMeta)); err != nil {
		return nil, err
	}
	if err := user.RecordActive(ctx, tx, organizationID, userID); err != nil {
		return nil, err
	}
	return &TokenPair{
		AccessToken:      access,
		TokenType:        "Bearer",
		ExpiresAt:        exp,
		RefreshToken:     refreshRaw,
		SessionExpiresAt: sessionExp,
		IdleExpiresAt:    idleExp,
		SessionID:        sessionID,
		UserID:           userID,
		OrganizationID:   organizationPtr,
	}, nil
}

// signInEvent is the auth.login_succeeded record of a sign-in by method to
// organizationID (uuid.Nil: none) that opened the session resourceType/sessionID.
// Every sign-in writes one, and the dashboard counts them; extra joins its
// metadata.
func signInEvent(userID, organizationID uuid.UUID, resourceType string, sessionID uuid.UUID, ip, ua, method string, extra map[string]any) audit.Event {
	if method == "" {
		method = "unknown"
	}
	meta := map[string]any{"method": method}
	for k, v := range extra {
		meta[k] = v
	}
	return asUser(userID, ip, ua).EventIn(orNil(organizationID), "auth.login_succeeded", resourceType, sessionID, meta)
}

// refreshExpiry is when a refresh token issued now expires: its usual
// lifetime, but never after the session it renews has ended.
func (s *Service) refreshExpiry(sessionExp time.Time) time.Time {
	exp := time.Now().UTC().Add(s.tokens.RefreshTTL())
	if sessionExp.Before(exp) {
		return sessionExp
	}
	return exp
}

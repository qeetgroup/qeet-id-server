package auth

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication/dbgen"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// signInHook runs the login hook for userID signing in to tenantID, or to
// their own organisation for uuid.Nil. Every sign-in runs it once its first
// factor is proven, so a refusal applies whatever the method.
func (s *Service) signInHook(ctx context.Context, userID, tenantID uuid.UUID) (map[string]any, error) {
	if s.loginHook == nil {
		return nil, nil
	}
	u, err := s.users.Get(ctx, userID)
	if err != nil {
		return nil, err
	}
	if tenantID == uuid.Nil {
		tenantID = u.TenantID
	}
	return s.hookClaims(ctx, tenantID, u)
}

// hookClaims runs the login hook for a sign-in of u to tenantID: the tenant's
// policy endpoint may deny it, or supply claims to carry into the token. No
// hook wired: no claims.
func (s *Service) hookClaims(ctx context.Context, tenantID uuid.UUID, u *user.User) (map[string]any, error) {
	if s.loginHook == nil {
		return nil, nil
	}
	return s.loginHook.Run(ctx, tenantID, u.ID, u.Email)
}

// IssuePair runs the login hook, then creates a session, issues an access and
// refresh token pair carrying the hook's claims, and records the sign-in
// method in an audit row in the same transaction. The hook may refuse the
// sign-in.
func (s *Service) IssuePair(ctx context.Context, userID, tenantID uuid.UUID, ip, ua, method string) (*TokenPair, error) {
	claims, err := s.signInHook(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	return s.issuePair(ctx, userID, tenantID, ip, ua, method, claims)
}

// IssuePairWithClaims is IssuePair for a sign-in whose login hook has already
// run: claims are its answer, injected into the access token.
func (s *Service) IssuePairWithClaims(ctx context.Context, userID, tenantID uuid.UUID, ip, ua, method string, claims map[string]any) (*TokenPair, error) {
	return s.issuePair(ctx, userID, tenantID, ip, ua, method, claims)
}

func (s *Service) issuePair(ctx context.Context, userID, tenantID uuid.UUID, ip, ua, method string, claims map[string]any) (*TokenPair, error) {
	if err := s.refuseSignIn(ctx, userID, tenantID, method, ip, ua); err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	pair, err := s.issuePairTx(ctx, tx, userID, tenantID, ip, ua, method, claims, nil, time.Time{})
	if err != nil {
		return nil, s.signInFailed(ctx, tx, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return pair, nil
}

// issuePairTx is issuePair inside the caller's transaction, begun once
// refuseSignIn has passed and committed by the caller. Hook claims are stored
// with the session so renewals issue them again; auditMeta (may be nil) joins
// the audit record; the session ends no later than notAfter (zero: no bound).
func (s *Service) issuePairTx(ctx context.Context, tx pgx.Tx, userID, tenantID uuid.UUID, ip, ua, method string, claims, auditMeta map[string]any, notAfter time.Time) (*TokenPair, error) {
	sessionID := uuid.New()
	var ipArg any
	if ip != "" {
		ipArg = ip
	}
	// uuid.Nil = tenant-less: store NULL (the zero UUID would violate the FK).
	var tenantArg any
	var tenantPtr *uuid.UUID
	if tenantID != uuid.Nil {
		t := tenantID
		tenantArg = t
		tenantPtr = &t
	}
	var hookClaims []byte
	if len(claims) > 0 {
		raw, err := json.Marshal(claims)
		if err != nil {
			return nil, err
		}
		hookClaims = raw
	}
	// The organisation's limit on one person's simultaneous sessions.
	if tenantID != uuid.Nil {
		if err := s.enforceSessionLimit(ctx, tx, userID, tenantID, ip, ua); err != nil {
			return nil, err
		}
	}
	// The organisation's own session bounds, else the platform's; taken now,
	// so a later change to the policy applies to new sessions only.
	maxAge, idle := s.sessionDefaults()
	var sessionExp, idleExp time.Time
	if err := tx.QueryRow(ctx, `
		INSERT INTO auth.sessions (id, user_id, tenant_id, ip, user_agent, hook_claims, expires_at, idle_timeout, country,
		                           second_factor)
		SELECT $1, $2, $3, NULLIF($4,'')::inet, $5, $6,
		       LEAST(NOW() + COALESCE(sp.session_max_age, make_interval(secs => $7::float8)),
		             COALESCE($9::timestamptz, 'infinity'::timestamptz)),
		       COALESCE(sp.session_idle_timeout, make_interval(secs => $8::float8)),
		       NULLIF($10, ''), NULLIF($11, '')
		FROM (VALUES (1)) AS one
		LEFT JOIN tenant.security_policies sp ON sp.tenant_id = $3
		RETURNING expires_at, LEAST(last_seen_at + idle_timeout, expires_at)
	`, sessionID, userID, tenantArg, ipArg, ua, hookClaims, maxAge.Seconds(), idle.Seconds(), notAfterArg(notAfter),
		httpx.GeoCountry(ctx), secondFactorOfMethod(method)).Scan(&sessionExp, &idleExp); err != nil {
		return nil, err
	}
	access, exp, err := s.tokens.IssueSessionAccess(userID, tenantID, sessionID, claims, sessionExp)
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
	if method == "" {
		method = "unknown"
	}
	meta := map[string]any{"method": method}
	for k, v := range auditMeta {
		meta[k] = v
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     tenantPtr,
		ActorUserID:  &userID,
		ActorType:    "user",
		Action:       "auth.login_succeeded",
		ResourceType: "session",
		ResourceID:   &sessionID,
		IP:           ip,
		UserAgent:    ua,
		Metadata:     meta,
	}); err != nil {
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
		TenantID:         tenantPtr,
	}, nil
}

// notAfterArg is a session's latest end for the insert: NULL for none.
func notAfterArg(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
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

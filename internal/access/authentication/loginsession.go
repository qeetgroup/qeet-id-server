package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// LoginSessionCookie is the browser SSO cookie for the hosted login/consent
// flow. It proves the browser is signed in to the Qeet ID identity provider and
// is HttpOnly (never readable by JS) — distinct from API access/refresh tokens.
const LoginSessionCookie = "qe_ls"

// loginSessionTTL is the lifetime of a hosted SSO session — shorter when the
// account's organisation (or, with none, the platform) bounds sessions more
// tightly; see loginSessionLifetime.
const loginSessionTTL = 30 * time.Minute

// loginSessionLifetime is how long a hosted SSO session opened now for userID
// lasts: loginSessionTTL, or the idle timeout or maximum age of the sessions
// of the user's organisation (the platform's for a user with none) when
// either is shorter, so signing in through the hosted page never outlasts
// what the organisation allows any session.
func (s *Service) loginSessionLifetime(ctx context.Context, userID uuid.UUID) (time.Duration, error) {
	maxAge, idle := s.sessionDefaults()
	var orgMax, orgIdle *int64
	err := s.pool.QueryRow(ctx, `
		SELECT EXTRACT(EPOCH FROM sp.session_max_age)::bigint, EXTRACT(EPOCH FROM sp.session_idle_timeout)::bigint
		FROM "user".users u
		JOIN tenant.security_policies sp ON sp.tenant_id = u.tenant_id
		WHERE u.id = $1`, userID).Scan(&orgMax, &orgIdle)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, err
	}
	if orgMax != nil {
		maxAge = time.Duration(*orgMax) * time.Second
	}
	if orgIdle != nil {
		idle = time.Duration(*orgIdle) * time.Second
	}
	return min(loginSessionTTL, maxAge, idle), nil
}

// CreateLoginSession mints a hosted SSO session for a user whose sign-in met
// no second factor and returns the raw cookie value. Only the hash is
// persisted (like refresh tokens).
func (s *Service) CreateLoginSession(ctx context.Context, userID uuid.UUID, ip, ua string) (string, error) {
	return s.createLoginSession(ctx, userID, ip, ua, "")
}

// CreatePasskeyLoginSession is CreateLoginSession for a passkey sign-in: the
// passkey is its second factor, so an organisation that requires one is
// satisfied (see tenantFactorShortfall).
func (s *Service) CreatePasskeyLoginSession(ctx context.Context, userID uuid.UUID, ip, ua string) (string, error) {
	return s.createLoginSession(ctx, userID, ip, ua, secondFactorPasskey)
}

// createLoginSession mints the session, recording how its sign-in met a
// second factor ("": it didn't).
func (s *Service) createLoginSession(ctx context.Context, userID uuid.UUID, ip, ua, secondFactor string) (string, error) {
	raw, hash, err := tokens.NewRefreshToken()
	if err != nil {
		return "", err
	}
	ttl, err := s.loginSessionLifetime(ctx, userID)
	if err != nil {
		return "", err
	}
	if err := s.q.InsertLoginSession(ctx, dbgen.InsertLoginSessionParams{
		TokenHash:    hash,
		UserID:       userID,
		ExpiresAt:    time.Now().Add(ttl),
		Ip:           ip,
		UserAgent:    &ua,
		SecondFactor: secondFactor,
	}); err != nil {
		return "", err
	}
	return raw, nil
}

// LoginSessionFactorShortfall is what stops a code or token being issued for
// tenantID through the user's hosted-login session: nil when nothing does, or
// ErrStepUpRequired / ErrMFAEnrollmentRequired while the organisation requires
// a second factor the session's sign-in didn't meet (see
// tenantFactorShortfall). An unknown or expired session is ErrUnauthorized.
func (s *Service) LoginSessionFactorShortfall(ctx context.Context, loginSessionID, userID, tenantID uuid.UUID) error {
	factor, err := s.q.LoginSessionSecondFactor(ctx, dbgen.LoginSessionSecondFactorParams{ID: loginSessionID, UserID: userID})
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrUnauthorized
	}
	if err != nil {
		return err
	}
	return s.tenantFactorShortfall(ctx, userID, tenantID, factor)
}

// ResolveLoginSession returns the user id behind a valid, unexpired SSO session
// cookie value, or ErrUnauthorized.
func (s *Service) ResolveLoginSession(ctx context.Context, raw string) (uuid.UUID, error) {
	_, userID, err := s.ResolveLoginSessionWithID(ctx, raw)
	return userID, err
}

// ResolveLoginSessionWithID is ResolveLoginSession that also returns the
// session's own id, which the authorization codes minted through it record so
// that signing out of it can end what it started.
func (s *Service) ResolveLoginSessionWithID(ctx context.Context, raw string) (sessionID, userID uuid.UUID, err error) {
	sessionID, userID, _, err = s.ResolveLoginSessionAt(ctx, raw)
	return sessionID, userID, err
}

// ResolveLoginSessionAt is ResolveLoginSessionWithID plus when the person
// signed in to the hosted login: the authentication time (auth_time) an
// authorization request's max_age and prompt=login are judged by.
func (s *Service) ResolveLoginSessionAt(ctx context.Context, raw string) (sessionID, userID uuid.UUID, signedInAt time.Time, err error) {
	if raw == "" {
		return uuid.Nil, uuid.Nil, time.Time{}, errs.ErrUnauthorized
	}
	row, err := s.q.GetLoginSession(ctx, tokens.HashRefresh(raw))
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, uuid.Nil, time.Time{}, errs.ErrUnauthorized
	}
	if err != nil {
		return uuid.Nil, uuid.Nil, time.Time{}, err
	}
	if time.Now().After(row.ExpiresAt) {
		return uuid.Nil, uuid.Nil, time.Time{}, errs.ErrUnauthorized
	}
	return row.ID, row.UserID, row.CreatedAt, nil
}

// ResolveLoginSessionUser returns the user behind a live SSO session cookie
// value and their own organization (uuid.Nil when they have none), or
// ErrUnauthorized when the session is unknown, expired or ended, or the user or
// their organization is no longer active.
func (s *Service) ResolveLoginSessionUser(ctx context.Context, raw string) (userID, tenantID uuid.UUID, err error) {
	userID, tenantID, _, err = s.resolveLoginSession(ctx, raw)
	return userID, tenantID, err
}

// resolveLoginSession is ResolveLoginSessionUser plus when the sign-in that
// opened the session happened, if that sign-in proved a second factor (zero
// otherwise): what a hosted-login principal's step-up is judged by.
func (s *Service) resolveLoginSession(ctx context.Context, raw string) (userID, tenantID uuid.UUID, signedInAt time.Time, err error) {
	if raw == "" {
		return uuid.Nil, uuid.Nil, time.Time{}, errs.ErrUnauthorized
	}
	row, err := s.q.GetLoginSessionUser(ctx, tokens.HashRefresh(raw))
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, uuid.Nil, time.Time{}, errs.ErrUnauthorized
	}
	if err != nil {
		return uuid.Nil, uuid.Nil, time.Time{}, err
	}
	if row.TenantID.Valid {
		tenantID = uuid.UUID(row.TenantID.Bytes)
	}
	// A fresh hosted sign-in counts as a step-up only when it proved a second
	// factor itself — a met challenge or a passkey — not when a remembered
	// device stood in for one or none was asked for, as for a social sign-in
	// (QTID-801).
	if row.SecondFactor != secondFactorMFA && row.SecondFactor != secondFactorPasskey {
		return row.UserID, tenantID, time.Time{}, nil
	}
	return row.UserID, tenantID, row.CreatedAt, nil
}

// LoginSessionAuth lets the hosted login's own pages call a short list of
// signed-in routes with the browser's SSO session (the qe_ls cookie) instead of
// a bearer token, which the hosted login never holds. Mount it on the
// authenticated route group, ahead of httpx.RequireAuth.
//
// routes are "METHOD /path" entries in chi pattern syntax ("{id}" matches one
// path segment). The cookie is read only for a listed route, and only when the
// request carries no Authorization header and nothing earlier authenticated it;
// every other request passes through untouched for RequireAuth to decide. So
// the session reaches no other route, and a request presenting a token is
// judged on that token alone.
//
// Cross-site requests: the router's CSRF middleware runs first and skips only
// requests carrying "Authorization: Bearer", so a cookie-authenticated mutation
// here has already passed its Origin and qe_csrf double-submit checks.
//
// The principal is the session's user in their own organization, both read
// from the database, never from the request. An unknown, expired or ended
// session, or a user or organization that is no longer active, is refused
// with 401.
func (s *Service) LoginSessionAuth(routes []string) func(http.Handler) http.Handler {
	listed := chi.NewRouter()
	for _, route := range routes {
		method, pattern, ok := strings.Cut(route, " ")
		if !ok {
			panic("auth: hosted-login session route without a method: " + route)
		}
		listed.MethodFunc(method, pattern, func(http.ResponseWriter, *http.Request) {})
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if httpx.PrincipalFromCtx(r.Context()) != nil || r.Header.Get("Authorization") != "" ||
				!listed.Match(chi.NewRouteContext(), r.Method, r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			c, err := r.Cookie(LoginSessionCookie)
			if err != nil || c.Value == "" {
				next.ServeHTTP(w, r)
				return
			}
			userID, tenantID, factorAt, err := s.resolveLoginSession(r.Context(), c.Value)
			if err != nil {
				httpx.WriteError(w, r, err)
				return
			}
			p := &httpx.Principal{ActorType: "user", Subject: userID.String(), UserID: &userID}
			if !factorAt.IsZero() {
				p.SignedInAt = &factorAt
			}
			if tenantID != uuid.Nil {
				p.TenantID = &tenantID
			}
			next.ServeHTTP(w, r.WithContext(httpx.WithPrincipal(r.Context(), p)))
		})
	}
}

// RevokeLoginSession signs a browser out of the hosted login: EndLoginSession
// as the hosted login's own sign-out.
func (s *Service) RevokeLoginSession(ctx context.Context, raw string) error {
	_, err := s.EndLoginSession(ctx, EndLoginSessionInput{Cookie: raw, InitiatedBy: SignOutByHostedLogin})
	return err
}

// Who asked for a sign-out, as recorded.
const (
	// SignOutByHostedLogin: the hosted login signed itself out.
	SignOutByHostedLogin = "hosted_login"
	// SignOutByApplication: an application's sign-out request (OIDC
	// RP-initiated logout).
	SignOutByApplication = "application"
)

// EndLoginSessionInput describes a sign-out. Cookie is the browser's
// hosted-login cookie value — the only thing that says which session to end.
// InitiatedBy is SignOutByHostedLogin or SignOutByApplication. ClientID names
// the application that asked, and only when it is a registered one.
type EndLoginSessionInput struct {
	Cookie      string
	InitiatedBy string
	ClientID    string
	IP          string
	UserAgent   string
	RequestID   string
}

// LoginSessionEnded reports what a sign-out ended. Ended is false when the
// cookie named no session (nothing was ended or recorded).
type LoginSessionEnded struct {
	Ended                     bool
	SessionID                 uuid.UUID
	AppGrants                 int64
	ExpiredAuthorizationCodes int64
	// FrontChannelLogoutURIs are the pages of the applications in the session
	// that the hosted signed-out page loads to sign the browser out of them
	// (with iss and sid), as the SignOutNotifier returned them.
	FrontChannelLogoutURIs []string
}

// SignOutNotifier tells the applications in an ended hosted-login session
// (back-channel notices) and returns their front-channel sign-out pages.
// Satisfied by *oidc.Service; an interface so auth doesn't import it. Wired
// via SetSignOutNotifier.
type SignOutNotifier interface {
	NotifySignOut(ctx context.Context, sessionID, userID uuid.UUID, initiatedBy string) ([]string, error)
}

// SetSignOutNotifier wires the sign-out notices. Called from
// internal/bootstrap/dependencies.go.
func (s *Service) SetSignOutNotifier(n SignOutNotifier) { s.signOutNotifier = n }

// EndLoginSession signs a browser out of the hosted login. In one transaction
// it deletes the session behind the cookie, spends the authorization codes
// minted through it that no application has redeemed, revokes the application
// grants it started (renewals included), and records the sign-out. Other
// browsers, API sessions and grants started elsewhere are untouched — signing
// out everywhere is a separate action.
//
// Only the cookie identifies the session: with no cookie, or one that names no
// session, nothing is ended and nothing is recorded. A session that has
// expired is still ended, with what it started, because its grants outlive it.
func (s *Service) EndLoginSession(ctx context.Context, in EndLoginSessionInput) (LoginSessionEnded, error) {
	if in.Cookie == "" {
		return LoginSessionEnded{}, nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return LoginSessionEnded{}, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	row, err := q.EndLoginSession(ctx, tokens.HashRefresh(in.Cookie))
	if errors.Is(err, pgx.ErrNoRows) {
		return LoginSessionEnded{}, nil
	}
	if err != nil {
		return LoginSessionEnded{}, err
	}
	ended := LoginSessionEnded{Ended: true, SessionID: row.ID}
	// Codes first: a redemption under way holds its code until its grant is
	// written, so waiting here means the grant pass below sees that grant.
	if ended.ExpiredAuthorizationCodes, err = q.ExpireAuthorizationCodesForLoginSession(ctx, pgtype.UUID{Bytes: row.ID, Valid: true}); err != nil {
		return LoginSessionEnded{}, err
	}
	// An application renewing a grant at this moment writes the next token
	// after a pass may have taken its snapshot; pass again until one finds
	// nothing left, as EndAllSignIns does.
	for pass := 0; pass < maxGrantPasses; pass++ {
		grants, err := q.RevokeAppGrantsForLoginSession(ctx, pgtype.UUID{Bytes: row.ID, Valid: true})
		if err != nil {
			return LoginSessionEnded{}, err
		}
		ended.AppGrants += grants.Live
		if grants.Touched == 0 {
			break
		}
	}
	metadata := map[string]any{
		"initiated_by":                in.InitiatedBy,
		"revoked_app_grants":          ended.AppGrants,
		"expired_authorization_codes": ended.ExpiredAuthorizationCodes,
	}
	if in.ClientID != "" {
		metadata["client_id"] = in.ClientID
	}
	var tenantID *uuid.UUID
	if row.TenantID.Valid {
		t := uuid.UUID(row.TenantID.Bytes)
		tenantID = &t
	}
	userID, sessionID := row.UserID, row.ID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: tenantID, ActorUserID: &userID, ActorType: "user",
		Action: "auth.signed_out", ResourceType: "login_session", ResourceID: &sessionID,
		IP: in.IP, UserAgent: in.UserAgent, RequestID: in.RequestID,
		Metadata: metadata,
	}); err != nil {
		return LoginSessionEnded{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LoginSessionEnded{}, err
	}
	// The session has ended whatever happens next; telling the applications
	// is best effort (a failure is logged, and back-channel notices retry).
	if s.signOutNotifier != nil {
		uris, err := s.signOutNotifier.NotifySignOut(ctx, row.ID, row.UserID, in.ClientID)
		if err != nil {
			slog.Warn("auth: tell applications of a sign-out", "session_id", row.ID, "err", err)
		}
		ended.FrontChannelLogoutURIs = uris
	}
	return ended, nil
}

// SetLoginSessionCookie writes the HttpOnly SSO cookie. secure should be true
// outside dev so it is only sent over HTTPS. SameSite=Lax so it survives the
// top-level GET redirects of the OAuth authorize flow.
func SetLoginSessionCookie(w http.ResponseWriter, raw string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     LoginSessionCookie,
		Value:    raw,
		Path:     "/",
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(loginSessionTTL.Seconds()),
	})
}

// ClearLoginSessionCookie expires the SSO cookie.
func ClearLoginSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     LoginSessionCookie,
		Value:    "",
		Path:     "/",
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

package authentication

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

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// LoginSessionCookie is the browser SSO cookie for the hosted login/consent
// flow. It proves the browser is signed in to the Qeet ID identity provider and
// is HttpOnly (never readable by JS) — distinct from API access/refresh tokens.
const LoginSessionCookie = "qe_ls"

// loginSessionTTL is the lifetime of a hosted SSO session — shorter when the
// account's organization (or, with none, the platform) bounds sessions more
// tightly; see loginSessionLifetime.
const loginSessionTTL = 30 * time.Minute

// loginSessionLifetime returns how long a hosted SSO session for userID lasts:
// loginSessionTTL, capped by the organization's session idle timeout and
// maximum age.
func (s *Service) loginSessionLifetime(ctx context.Context, userID uuid.UUID) (time.Duration, error) {
	maxAge, idle := s.sessionDefaults()
	bounds, err := s.q.LoginSessionBounds(ctx, userID)
	switch {
	case err == nil:
		maxAge, idle = time.Duration(bounds.MaxAgeS)*time.Second, time.Duration(bounds.IdleS)*time.Second
	case !errors.Is(err, pgx.ErrNoRows):
		return 0, err
	}
	return min(loginSessionTTL, maxAge, idle), nil
}

// CreateLoginSession mints a hosted SSO session, once the login hook of the
// user's own organization allows it, for a password sign-in that met no second
// factor, and returns the raw cookie value. Only the hash is persisted (like
// refresh tokens).
func (s *Service) CreateLoginSession(ctx context.Context, userID uuid.UUID, ip, ua string) (string, error) {
	if _, err := s.signInHook(ctx, userID, uuid.Nil); err != nil {
		return "", err
	}
	return s.createLoginSession(ctx, userID, uuid.Nil, ip, ua, firstFactorPassword, "")
}

// CreatePasskeyLoginSession is CreateLoginSession for a passkey sign-in: the
// passkey is its second factor, so an organization that requires one is
// satisfied (see organizationFactorShortfall).
func (s *Service) CreatePasskeyLoginSession(ctx context.Context, userID uuid.UUID, ip, ua string) (string, error) {
	if _, err := s.signInHook(ctx, userID, uuid.Nil); err != nil {
		return "", err
	}
	return s.createLoginSession(ctx, userID, uuid.Nil, ip, ua, "passkey", secondFactorPasskey)
}

// createLoginSession mints the session and records the sign-in by method to organizationID
// (uuid.Nil: the account's own), with how it met a second factor ("": it didn't). The session reaches
// the account's self-service routes, so its own organization's address rules apply whichever
// organization's application asked.
func (s *Service) createLoginSession(ctx context.Context, userID, organizationID uuid.UUID, ip, ua, method, secondFactor string) (string, error) {
	// Every hosted sign-in ends here, whatever its method.
	if err := s.refuseInactiveAccount(ctx, userID, uuid.Nil, "hosted", ip, ua); err != nil {
		return "", err
	}
	u, err := s.users.Get(ctx, userID)
	if err != nil {
		return "", err
	}
	if err := s.checkAddress(ctx, u.OrganizationID, userID, ip, "hosted_"+method); err != nil {
		return "", err
	}
	raw, hash, err := tokens.NewRefreshToken()
	if err != nil {
		return "", err
	}
	ttl, err := s.loginSessionLifetime(ctx, userID)
	if err != nil {
		return "", err
	}
	if organizationID == uuid.Nil {
		organizationID = u.OrganizationID
	}
	meta := s.signInClientMeta(ctx)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	sessionID, err := s.q.WithTx(tx).InsertLoginSession(ctx, dbgen.InsertLoginSessionParams{
		TokenHash:    hash,
		UserID:       userID,
		ExpiresAt:    time.Now().Add(ttl),
		Ip:           ip,
		UserAgent:    &ua,
		SecondFactor: secondFactor,
	})
	if err != nil {
		return "", err
	}
	if secondFactor != "" {
		if meta == nil {
			meta = map[string]any{}
		}
		meta["second_factor"] = secondFactor
	}
	if err := audit.Record(ctx, tx, signInEvent(userID, organizationID, "login_session", sessionID, ip, ua, method, meta)); err != nil {
		return "", err
	}
	return raw, tx.Commit(ctx)
}

// LoginSessionFactorShortfall reports what stops a code or token being issued
// for organizationID through the user's hosted-login session: nil, ErrStepUpRequired
// or ErrMFAEnrollmentRequired. An unknown or expired session is ErrUnauthorized.
func (s *Service) LoginSessionFactorShortfall(ctx context.Context, loginSessionID, userID, organizationID uuid.UUID) error {
	factor, err := s.q.LoginSessionSecondFactor(ctx, dbgen.LoginSessionSecondFactorParams{ID: loginSessionID, UserID: userID})
	if errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrUnauthorized
	}
	if err != nil {
		return err
	}
	return s.organizationFactorShortfall(ctx, userID, organizationID, factor)
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
func (s *Service) ResolveLoginSessionUser(ctx context.Context, raw string) (userID, organizationID uuid.UUID, err error) {
	userID, organizationID, _, err = s.resolveLoginSession(ctx, raw)
	return userID, organizationID, err
}

// resolveLoginSession is ResolveLoginSessionUser plus when the sign-in that
// opened the session happened, if that sign-in proved a second factor (zero
// otherwise): what a hosted-login principal's step-up is judged by.
func (s *Service) resolveLoginSession(ctx context.Context, raw string) (userID, organizationID uuid.UUID, signedInAt time.Time, err error) {
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
	if row.OrganizationID != nil {
		organizationID = *row.OrganizationID
	}
	// A fresh hosted sign-in counts as a step-up only when it proved a second
	// factor itself — a met challenge or a passkey — not when a remembered
	// device stood in for one or none was asked for, as for a social sign-in.
	if row.SecondFactor != secondFactorMFA && row.SecondFactor != secondFactorPasskey {
		return row.UserID, organizationID, time.Time{}, nil
	}
	return row.UserID, organizationID, row.CreatedAt, nil
}

// LoginSessionAuth lets the hosted login's pages call the listed routes
// ("METHOD /path", chi syntax) with the SSO session cookie instead of a bearer
// token; mount it ahead of httpx.RequireAuth. Other requests pass through
// untouched, and an inactive session, user or organization gets 401.
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
			userID, organizationID, factorAt, err := s.resolveLoginSession(r.Context(), c.Value)
			if err != nil {
				httpx.WriteError(w, r, err)
				return
			}
			p := &httpx.Principal{ActorType: "user", Subject: userID.String(), UserID: &userID}
			if !factorAt.IsZero() {
				p.SignedInAt = &factorAt
			}
			if organizationID != uuid.Nil {
				p.OrganizationID = &organizationID
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
	SignOutByHostedLogin = "hosted_login" // the hosted login signed itself out
	SignOutByApplication = "application"  // OIDC RP-initiated logout
)

// EndLoginSessionInput describes a sign-out. Cookie is the browser's
// hosted-login cookie value — the only thing that says which session to end.
// InitiatedBy is SignOutByHostedLogin or SignOutByApplication. ClientID names
// the application that asked, and only when it is a registered one.
type EndLoginSessionInput struct {
	Cookie      string
	InitiatedBy string
	ClientID    string
	// Actor is the request's client address, user agent and request ID, for
	// its audit record.
	audit.Actor
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
// Satisfied by *oidc.Service; an interface so auth doesn't import it.
type SignOutNotifier interface {
	NotifySignOut(ctx context.Context, sessionID, userID uuid.UUID, initiatedBy string) ([]string, error)
}

// EndLoginSession signs a browser out of the hosted login. In one transaction it
// deletes the session named by the cookie, spends its unredeemed authorization
// codes, revokes the application grants it started and records the sign-out.
// Without a matching cookie nothing happens; an expired session is still ended.
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
	if ended.ExpiredAuthorizationCodes, err = q.ExpireAuthorizationCodesForLoginSession(ctx, &row.ID); err != nil {
		return LoginSessionEnded{}, err
	}
	// An application renewing a grant at this moment writes the next token
	// after a pass may have taken its snapshot; pass again until one finds
	// nothing left, as EndAllSignIns does.
	for pass := 0; pass < maxGrantPasses; pass++ {
		grants, err := q.RevokeAppGrantsForLoginSession(ctx, &row.ID)
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
	if err := audit.Record(ctx, tx, as(in.Actor, "user", &row.UserID).EventIn(row.OrganizationID, "auth.signed_out", "login_session", row.ID, metadata)); err != nil {
		return LoginSessionEnded{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return LoginSessionEnded{}, err
	}
	// The session has ended whatever happens next; telling the applications
	// is best effort (a failure is logged, and back-channel notices retry).
	uris, err := s.signOutNotifier.NotifySignOut(ctx, row.ID, row.UserID, in.ClientID)
	if err != nil {
		slog.Warn("auth: tell applications of a sign-out", "session_id", row.ID, "err", err)
	}
	ended.FrontChannelLogoutURIs = uris
	return ended, nil
}

// SetLoginSessionCookie writes the HttpOnly SSO cookie. secure should be true
// outside dev so it is only sent over HTTPS. SameSite=Lax so it survives the
// top-level GET redirects of the OAuth authorize flow.
func SetLoginSessionCookie(w http.ResponseWriter, raw string, secure bool) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure is off only in dev
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
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure is off only in dev
		Name:     LoginSessionCookie,
		Value:    "",
		Path:     "/",
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

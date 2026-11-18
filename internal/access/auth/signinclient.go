package auth

import (
	"context"
	"net/http"
	"regexp"
	"time"
)

// SignInClientCookie names the application a hosted sign-in is for. The
// authorization endpoint sets it when it sends the browser to sign in, and
// clears it once it has given that application a code.
const SignInClientCookie = "qe_sc"

// signInClientTTL is how long the cookie names the application: long enough
// for a sign-in with a second factor and an email link.
const signInClientTTL = time.Hour

// clientIDShape is what a client_id can look like; anything else in the cookie
// is ignored.
var clientIDShape = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,255}$`)

type signInClientKey struct{}

// WithSignInClient names clientID as the application the sign-in in ctx is
// for.
func WithSignInClient(ctx context.Context, clientID string) context.Context {
	if !clientIDShape.MatchString(clientID) {
		return ctx
	}
	return context.WithValue(ctx, signInClientKey{}, clientID)
}

// signInClient is the application ctx's sign-in is for, or "".
func signInClient(ctx context.Context) string {
	id, _ := ctx.Value(signInClientKey{}).(string)
	return id
}

// SignInClientContext puts the application the cookie names in the request's
// context, so whichever hosted sign-in follows can record it.
func SignInClientContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(SignInClientCookie); err == nil && c.Value != "" {
			r = r.WithContext(WithSignInClient(r.Context(), c.Value))
		}
		next.ServeHTTP(w, r)
	})
}

// SetSignInClientCookie names clientID as the application the browser is
// about to sign in for. secure should be true outside dev.
func SetSignInClientCookie(w http.ResponseWriter, clientID string, secure bool) {
	if !clientIDShape.MatchString(clientID) {
		return
	}
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure is off only in dev
		Name:     SignInClientCookie,
		Value:    clientID,
		Path:     "/",
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(signInClientTTL.Seconds()),
	})
}

// ClearSignInClientCookie expires the cookie, when r carries it.
func ClearSignInClientCookie(w http.ResponseWriter, r *http.Request, secure bool) {
	if _, err := r.Cookie(SignInClientCookie); err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure is off only in dev
		Name:     SignInClientCookie,
		Value:    "",
		Path:     "/",
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// signInClientMeta is the audit metadata naming the registered application
// ctx's sign-in is for, or nil when it names none, or one that isn't
// registered.
func (s *Service) signInClientMeta(ctx context.Context) map[string]any {
	id := signInClient(ctx)
	if id == "" {
		return nil
	}
	name, err := s.q.SignInClientName(ctx, id)
	if err != nil {
		return nil
	}
	return map[string]any{"client_id": id, "client_name": name}
}

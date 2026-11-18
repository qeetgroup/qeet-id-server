package social

// Platform sign-in is the console's own organization-less social sign-in. It uses
// env-configured providers and its own kind of state and code, matches people
// by their globally unique email, and issues an organization-less session.

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/auth"
	"github.com/qeetgroup/qeet-id-server/internal/federation/logincode"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oauthstate"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidcrp"
	"github.com/qeetgroup/qeet-id-server/internal/federation/social/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/strutil"
)

// PlatformProvider is one of the console's organization-less social
// sign-ins, configured from the environment.
type PlatformProvider struct {
	name   string
	config providerConfig
}

// PlatformOIDC is a discovery-based OpenID Connect provider (Google,
// Microsoft, …) named name.
func PlatformOIDC(name, clientID, clientSecret, discoveryURL string) PlatformProvider {
	return PlatformProvider{name, providerConfig{clientID: clientID, clientSecret: clientSecret, discoveryURL: discoveryURL, kind: kindOIDC}}
}

// PlatformGitHub is GitHub, which isn't OIDC (no discovery doc), so it uses
// the dedicated adapter in github.go instead of the generic OIDC ceremony.
func PlatformGitHub(clientID, clientSecret string) PlatformProvider {
	return PlatformProvider{kindGitHub, providerConfig{clientID: clientID, clientSecret: clientSecret, kind: kindGitHub}}
}

// PlatformApple is Sign in with Apple. servicesID is the Services ID; the
// client secret is signed per request from teamID, keyID and privateKey (a
// .p8 key). See apple.go.
func PlatformApple(servicesID, teamID, keyID, privateKey string) PlatformProvider {
	return PlatformProvider{kindApple, providerConfig{
		clientID: servicesID, kind: kindApple, teamID: teamID, keyID: keyID, privateKey: privateKey,
	}}
}

// PlatformProviderEnabled reports whether a platform provider is configured.
func (s *Service) PlatformProviderEnabled(name string) bool {
	_, ok := s.platform[name]
	return ok
}

// PlatformProviderNames lists the configured platform provider names (for the
// frontend to know which buttons to enable).
func (s *Service) PlatformProviderNames() []string {
	out := make([]string, 0, len(s.platform))
	for k := range s.platform {
		out = append(out, k)
	}
	return out
}

// BeginPlatformLogin persists PKCE state and returns the provider authorization
// URL for an organization-less console sign-in / sign-up. allowCreate=true (sign-up)
// lets the callback provision a new account just-in-time; false (sign-in) makes
// it require an existing account instead of silently creating one.
func (s *Service) BeginPlatformLogin(ctx context.Context, provider, redirectURI string, allowCreate bool) (string, error) {
	return s.beginPlatform(ctx, provider, redirectURI, uuid.Nil, allowCreate)
}

// BeginPlatformLink starts an authenticated "connect this provider to my
// account" ceremony. The callback attaches the resulting identity to userID
// instead of logging in / creating an account — the account-page link flow.
func (s *Service) BeginPlatformLink(ctx context.Context, provider, redirectURI string, userID uuid.UUID) (string, error) {
	return s.beginPlatform(ctx, provider, redirectURI, userID, false)
}

// beginPlatform persists the state of a console sign-in, sign-up or link
// with a platform provider and returns its authorization URL.
func (s *Service) beginPlatform(ctx context.Context, provider, redirectURI string, linkUserID uuid.UUID, allowCreate bool) (string, error) {
	pc, ok := s.platform[provider]
	if !ok {
		return "", errs.ErrSocialProviderNotConfigured
	}
	var doc oidcrp.Discovery
	if pc.kind == kindOIDC {
		var err error
		if doc, err = s.oidc.Discover(ctx, pc.discoveryURL); err != nil {
			return "", ErrDiscoveryFailed.Wrap(err)
		}
	}
	verifier, challenge, nonce, nonceHash, err := ceremonySecrets(pc.kind)
	if err != nil {
		return "", err
	}
	state, err := oauthstate.Save(ctx, s.pool, oauthstate.State{
		Kind:         oauthstate.KindPlatformSocial,
		Provider:     provider,
		CodeVerifier: verifier,
		NonceHash:    nonceHash,
		RedirectURI:  redirectURI,
		LinkUserID:   linkUserID,
		AllowCreate:  allowCreate,
	}, socialStateTTL)
	if err != nil {
		return "", err
	}
	return s.authorizeURL(pc, doc, redirectURI, state, challenge, nonce), nil
}

// PlatformCallbackResult is the outcome of a platform OAuth callback: a login
// ceremony yields a one-time LoginCode the SPA trades for a session; an
// authenticated link ceremony yields a one-time LinkCode the account that began
// it completes the link with (CompletePlatformLink). Neither issues a session.
type PlatformCallbackResult struct {
	LoginCode string
	LinkCode  string
	Provider  string
}

// CompletePlatformCallback consumes the state and exchanges the code. A sign-in
// yields a one-time LoginCode and needs startedHere (else ErrSocialBrowserMismatch);
// a link yields a LinkCode for CompletePlatformLink. ErrSocialStateInvalid means
// the state isn't a platform one, so the caller can try the organization flow.
func (s *Service) CompletePlatformCallback(ctx context.Context, provider, state, code string, startedHere bool) (*PlatformCallbackResult, error) {
	if state == "" || code == "" {
		return nil, ErrCallbackParamsMissing
	}
	pc, ok := s.platform[provider]
	if !ok {
		return nil, errs.ErrSocialProviderNotConfigured
	}
	st, err := oauthstate.Take(ctx, s.pool, oauthstate.KindPlatformSocial, state, uuid.Nil, stateRefusals)
	if err != nil {
		return nil, err
	}
	if st.Provider != provider {
		return nil, ErrProviderMismatch
	}
	// A sign-in completes only in the browser that began it. A link is begun
	// through the console's server, which sets no cookie in the browser; it is
	// bound to its account instead, when the account completes it.
	if st.LinkUserID == uuid.Nil && !startedHere {
		return nil, ErrBrowserMismatch
	}
	ui, err := s.signedIn(ctx, pc, code, st.RedirectURI, st.CodeVerifier, st.NonceHash)
	if err != nil {
		return nil, err
	}
	// A link ceremony doesn't attach here: whoever arrived may not be the
	// account that began it. What the provider returned waits under a one-time
	// code that only that account can complete.
	if st.LinkUserID != uuid.Nil {
		verifiedEmail := ""
		if ui.EmailVerified {
			verifiedEmail = ui.Email
		}
		rawCode, codeHash, err := codes.URLToken()
		if err != nil {
			return nil, err
		}
		if err := s.q.InsertPlatformSocialLinkCode(ctx, dbgen.InsertPlatformSocialLinkCodeParams{
			CodeHash: codeHash, UserID: st.LinkUserID, Provider: provider, Subject: ui.Subject,
			Email: strutil.NilIfEmpty(verifiedEmail), ExpiresAt: time.Now().UTC().Add(socialCodeTTL),
		}); err != nil {
			return nil, err
		}
		return &PlatformCallbackResult{LinkCode: rawCode, Provider: provider}, nil
	}

	owner, ownerErr := s.q.GetPlatformSocialIdentityOwner(ctx, dbgen.GetPlatformSocialIdentityOwnerParams{
		Provider: provider,
		Subject:  ui.Subject,
	})
	if ownerErr != nil && !errors.Is(ownerErr, pgx.ErrNoRows) {
		return nil, ownerErr
	}

	var userID uuid.UUID
	if ownerErr == nil {
		// Existing provider-subject binding is the identity proof; an upstream
		// provider omitting email on later logins does not break the account.
		userID = owner
	} else {
		if ui.Email == "" {
			return nil, ErrEmailMissing
		}
		if !ui.EmailVerified {
			return nil, ErrEmailUnverified
		}
		// New login/signup binding: verified email may resolve an existing local
		// account or provision a new one when this is a signup ceremony.
		userID, err = s.findOrCreatePlatformUser(ctx, ui, st.AllowCreate)
		if err != nil {
			return nil, err
		}
		if err := s.refuseCapturedAccount(ctx, userID); err != nil {
			return nil, err
		}
		if err := s.q.UpsertPlatformSocialIdentity(ctx, dbgen.UpsertPlatformSocialIdentityParams{
			UserID: userID, Provider: provider, Subject: ui.Subject, Email: strutil.NilIfEmpty(ui.Email),
		}); err != nil {
			return nil, err
		}
	}

	// Nor does one whose organization requires single sign-on on its domain.
	if err := s.refuseCapturedAccount(ctx, userID); err != nil {
		return nil, err
	}
	// A suspended or deleted account gets no code to sign in with.
	if err := s.auth.CheckSignInAccount(ctx, userID, uuid.Nil, "social", "", ""); err != nil {
		return nil, err
	}
	rawCode, err := logincode.Issue(ctx, s.pool, logincode.Code{Kind: logincode.KindPlatformSocial, UserID: userID}, socialCodeTTL)
	if err != nil {
		return nil, err
	}
	return &PlatformCallbackResult{LoginCode: rawCode, Provider: provider}, nil
}

// CompletePlatformLink attaches the identity held under rawCode to userID and
// returns the provider. Only the account that began the link may complete it,
// but the code is spent either way. Email isn't checked, since the signed-in
// account is the proof; an identity linked to someone else is refused.
func (s *Service) CompletePlatformLink(ctx context.Context, rawCode string, userID uuid.UUID) (string, error) {
	if rawCode == "" {
		return "", ErrCodeRequired
	}
	held, err := s.q.TakePlatformSocialLinkCode(ctx, codes.Hash(rawCode))
	linkUserID, provider, subject, email, expiresAt := held.UserID, held.Provider, held.Subject, held.Email, held.ExpiresAt
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrLinkCodeInvalid
	}
	if err != nil {
		return "", err
	}
	if time.Now().After(expiresAt) {
		return "", ErrLinkCodeInvalid
	}
	if linkUserID != userID {
		return "", ErrLinkAccountMismatch
	}
	// An account whose organization requires single sign-on signs in only
	// through it, so a provider linked now would never sign it in.
	if err := s.refuseCapturedAccount(ctx, userID); err != nil {
		return "", err
	}
	owner, err := s.q.GetPlatformSocialIdentityOwner(ctx, dbgen.GetPlatformSocialIdentityOwnerParams{
		Provider: provider,
		Subject:  subject,
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	if err == nil && owner != userID {
		return "", ErrAlreadyLinked
	}
	if err := s.q.UpsertPlatformSocialIdentity(ctx, dbgen.UpsertPlatformSocialIdentityParams{
		UserID:   userID,
		Provider: provider,
		Subject:  subject,
		Email:    email,
	}); err != nil {
		return "", err
	}
	return provider, nil
}

// findOrCreatePlatformUser returns the user with ui.Email. With none, it creates
// a password-less organization-less user when allowCreate (sign-up) and otherwise
// fails with ErrSocialNoAccount.
func (s *Service) findOrCreatePlatformUser(ctx context.Context, ui userInfo, allowCreate bool) (uuid.UUID, error) {
	userID, err := s.q.AccountByEmail(ctx, ui.Email)
	if err == nil {
		// Adopt the account only if it has proved owning the address, or a squatter
		// who registered it unverified keeps a working password on it.
		if err := requireVerifiedAddress(ctx, s.q, userID); err != nil {
			return uuid.Nil, err
		}
		// Existing account: adopt the provider's avatar only if none is set yet,
		// so we never clobber a picture the user chose themselves.
		if ui.Picture != "" {
			_ = s.q.AdoptAccountAvatar(ctx, dbgen.AdoptAccountAvatarParams{ID: userID, AvatarUrl: &ui.Picture})
		}
		return userID, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, err
	}
	// No account for this email. Only a sign-up ceremony may provision one — a
	// sign-in must not silently create an account.
	if !allowCreate {
		return uuid.Nil, ErrNoAccount
	}
	// Nor on a domain an organization manages: it creates its people's accounts.
	if err := domainverify.CheckNewAccount(ctx, s.pool, uuid.Nil, ui.Email); err != nil {
		return uuid.Nil, err
	}
	var displayName, avatar *string
	if ui.Name != "" {
		displayName = &ui.Name
	}
	if ui.Picture != "" {
		avatar = &ui.Picture
	}
	// The platform provider verified the address: the callback takes no other.
	return s.q.InsertPlatformAccount(ctx, dbgen.InsertPlatformAccountParams{Email: ui.Email, DisplayName: displayName, AvatarUrl: avatar})
}

// platformCodeRefusals are the errors a platform login code is refused with.
// A used or expired one reads as invalid, as any code that isn't a platform
// one does, so the caller tries the organization exchange.
var platformCodeRefusals = logincode.Refusals{
	Required: ErrCodeRequired,
	Invalid:  ErrLoginCodeInvalid,
	Used:     ErrLoginCodeInvalid,
	Expired:  ErrLoginCodeInvalid,
}

// ExchangePlatformLogin trades a one-time platform login code for an
// organization-less token pair, or the second-factor challenge to meet first.
// A code that isn't a platform one fails with ErrSocialLoginCodeInvalid, so
// the caller can try the organization exchange.
func (s *Service) ExchangePlatformLogin(ctx context.Context, rawCode, ip, ua string) (*auth.LoginResult, error) {
	code, err := logincode.Consume(ctx, s.pool, logincode.KindPlatformSocial, rawCode, platformCodeRefusals)
	if err != nil {
		return nil, err
	}
	// Organization-less, exactly like signup.
	return s.auth.BeginSocialSignIn(ctx, code.UserID, uuid.Nil, ip, ua)
}

// platformProviders reports the configured platform-level social providers.
func (h *Handler) platformProviders(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"providers": h.Service.PlatformProviderNames()})
}

// requireVerifiedAddress refuses, with ErrSocialAccountUnverified, adopting an
// account whose address nobody has proved owning.
func requireVerifiedAddress(ctx context.Context, q *dbgen.Queries, userID uuid.UUID) error {
	verified, err := q.AccountAddressVerified(ctx, userID)
	if err != nil {
		return err
	}
	if !verified {
		return ErrAccountUnverified
	}
	return nil
}

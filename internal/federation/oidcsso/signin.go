package oidcsso

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/logincode"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oauthstate"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidcrp"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidcsso/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/federation/provision"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

const (
	stateTTL     = 10 * time.Minute // how long a begun sign-in can be completed
	loginCodeTTL = 5 * time.Minute  // how long the console has to trade its code
)

// providerFor reads c's discovery document and returns it with the ID token
// rules it implies.
func (s *Service) providerFor(ctx context.Context, c *signInConnection) (oidcrp.Discovery, oidcrp.Rules, error) {
	doc, err := s.providers.Discover(ctx, c.discoveryURL())
	if errors.Is(err, oidcrp.ErrDiscoveryInvalid) {
		return oidcrp.Discovery{}, oidcrp.Rules{}, ErrMisconfigured.Wrap(err)
	}
	if err != nil {
		return oidcrp.Discovery{}, oidcrp.Rules{}, ErrProviderUnreachable.Wrap(err)
	}
	rules, err := rulesFor(&c.Connection, doc)
	if err != nil {
		return oidcrp.Discovery{}, oidcrp.Rules{}, ErrMisconfigured.Wrap(err)
	}
	return doc, rules, nil
}

// BeginSignIn starts a sign-in through connection id, returning the provider
// URL to send the browser to and the state to bind to that browser. The state,
// PKCE verifier and nonce are kept, hashed where the provider echoes them, for
// the callback; redirectURI is where the provider sends the browser back.
func (s *Service) BeginSignIn(ctx context.Context, id uuid.UUID, redirectURI, returnTo string) (authURL, state string, err error) {
	// A sign-in started on the hosted login names where the browser goes back to.
	if returnTo != "" && (s.loginBaseURL == "" || !s.returnTo.Valid(returnTo)) {
		return "", "", ErrReturnToInvalid
	}
	c, err := s.loadForSignIn(ctx, id)
	if err != nil {
		return "", "", err
	}
	// Every sign-in needs a plan with SSO, not only setting the connection up.
	if err := s.RequireSSO(ctx, c.OrganizationID); err != nil {
		return "", "", err
	}
	doc, _, err := s.providerFor(ctx, c)
	if err != nil {
		return "", "", err
	}
	// PKCE S256: the verifier is the raw token, the challenge its SHA-256.
	verifier, challenge, err := codes.URLToken()
	if err != nil {
		return "", "", err
	}
	nonce, nonceHash, err := codes.URLToken()
	if err != nil {
		return "", "", err
	}
	state, err = oauthstate.Save(ctx, s.pool, oauthstate.State{
		Kind:           oauthstate.KindOIDCConnection,
		OrganizationID: c.OrganizationID,
		ConnectionID:   c.ID,
		CodeVerifier:   verifier,
		NonceHash:      nonceHash,
		RedirectURI:    redirectURI,
		ReturnTo:       returnTo,
	}, stateTTL)
	if err != nil {
		return "", "", err
	}
	return oidcrp.AuthorizeURL(doc.AuthorizationEndpoint, url.Values{
		"response_type":         {"code"},
		"client_id":             {c.ClientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {strings.Join(c.Scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}), state, nil
}

// Callback is a provider's answer to a sign-in, as the browser brings it back.
// Its Actor is the provider, with the browser's address, user agent and
// request ID.
type Callback struct {
	audit.Actor
	ConnectionID  uuid.UUID
	State, Code   string
	ProviderError string // the error parameter, when the provider refused
	StartedHere   bool   // the browser holds the sign-in's binding
}

// CompleteSignIn spends the sign-in's state and, when this browser began it, trades the code for an
// ID token, validates it, finds or provisions its person and returns a one-time code (for the
// console's ExchangeLogin or the hosted login's session route) with the stored return_to. Refusals
// after the browser check still return that return_to; each is recorded as a failed sign-in.
func (s *Service) CompleteSignIn(ctx context.Context, cb Callback) (loginCode, returnTo string, err error) {
	c, err := s.loadForSignIn(ctx, cb.ConnectionID)
	if c == nil {
		return "", "", err
	}
	// A refusal of the account is recorded where it is made (identitylink).
	recorded := false
	defer func() {
		if err != nil && !recorded {
			s.recordFailure(ctx, c, cb, err)
		}
	}()
	if err != nil {
		return "", "", err
	}
	if cb.State == "" {
		return "", "", ErrCallbackInvalid
	}
	st, err := oauthstate.Take(ctx, s.pool, oauthstate.KindOIDCConnection, cb.State, c.ID,
		oauthstate.Refusals{Invalid: ErrStateInvalid, Expired: ErrStateInvalid})
	if err != nil {
		return "", "", err
	}
	// A sign-in completes only in the browser that began it, or whoever began
	// one could have someone else's browser finish it as themselves.
	if !cb.StartedHere {
		return "", "", ErrOtherBrowser
	}
	// From here the sign-in is this browser's own: a failure still says where the hosted login's
	// sign-in goes back to.
	back := st.ReturnTo
	if cb.ProviderError != "" {
		return "", back, ErrProviderRefused
	}
	if cb.Code == "" {
		return "", back, ErrCallbackInvalid
	}
	// Checked again as the answer arrives, so a plan that has since lapsed
	// signs no one in.
	if err := s.RequireSSO(ctx, c.OrganizationID); err != nil {
		return "", back, err
	}
	doc, rules, err := s.providerFor(ctx, c)
	if err != nil {
		return "", back, err
	}
	tokens, err := s.providers.Exchange(ctx, doc, oidcrp.Credentials{ClientID: c.ClientID, ClientSecret: c.clientSecret}, cb.Code, st.RedirectURI, st.CodeVerifier)
	if err == nil && tokens.IDToken == "" {
		err = errors.New("token endpoint: no id_token")
	}
	if err != nil {
		return "", back, ErrTokenExchangeFailed.Wrap(err)
	}
	rules.NonceHash = st.NonceHash
	claims, err := s.providers.VerifyIDToken(ctx, tokens.IDToken, doc.JWKSURI, rules)
	if err != nil {
		return "", back, ErrIDTokenInvalid.Wrap(err)
	}
	userID, err := s.findOrCreateUser(ctx, c, c.profileOf(claims), cb)
	if err != nil {
		recorded = true
		return "", back, err
	}
	// A suspended or deleted account gets no code to sign in with.
	if err := s.auth.CheckSignInAccount(ctx, userID, c.OrganizationID, provider, cb.IP, cb.UserAgent); err != nil {
		return "", back, err
	}
	rawCode, err := logincode.Issue(ctx, s.pool, logincode.Code{
		Kind: logincode.KindOIDCConnection, UserID: userID, OrganizationID: c.OrganizationID, ConnectionID: c.ID,
	}, loginCodeTTL)
	if err != nil {
		return "", back, err
	}
	s.touchLastLogin(ctx, c)
	return rawCode, back, nil
}

// recordFailure records a refused sign-in through c in the organization's
// audit trail, with the error code as its reason.
func (s *Service) recordFailure(ctx context.Context, c *signInConnection, cb Callback, err error) {
	reason := errs.CodeInternal
	if e := errs.As(err); e != nil {
		reason = e.Code
	}
	meta := map[string]any{"connection_id": c.ID.String()}
	if code := oidcrp.SafeErrorCode(cb.ProviderError); code != "" {
		meta["provider_error"] = code
	}
	s.auth.RecordSignInFailure(ctx, authentication.SignInFailure{
		OrganizationID: c.OrganizationID,
		Method:         provider,
		Reason:         reason,
		IP:             cb.IP,
		UserAgent:      cb.UserAgent,
		Metadata:       meta,
	})
}

// linkMetadata is the profile a link keeps from the provider's last sign-in.
func linkMetadata(p profile) ([]byte, error) {
	meta := map[string]any{"issuer": p.issuer}
	for k, v := range map[string]string{"name": p.name, "given_name": p.givenName, "family_name": p.familyName} {
		if v != "" {
			meta[k] = v
		}
	}
	if p.groups != nil {
		meta["groups"] = p.groups
	}
	return json.Marshal(meta)
}

// findOrCreateUser returns the account c signs in for the ID token's
// profile p, found, adopted or created by identitylink's rules, which also
// keep its profile and groups in step with the token. A provider that says
// itself it hasn't verified the address doesn't vouch for it.
func (s *Service) findOrCreateUser(ctx context.Context, c *signInConnection, p profile, cb Callback) (uuid.UUID, error) {
	meta, err := linkMetadata(p)
	if err != nil {
		return uuid.Nil, err
	}
	return s.link.Resolve(ctx, provision.Source{OrganizationID: c.OrganizationID, Provider: provider, ConnectionID: c.ID},
		provision.Person{
			Subject: p.subject, Email: p.email, EmailVerified: p.verified, Name: p.name,
			Groups: p.groups, GroupsWithheld: p.groupsWithheld, LinkMetadata: meta,
		},
		cb.Actor)
}

// ExchangeLogin trades a one-time login code for a token pair, while the
// connection that issued it is still active.
func (s *Service) ExchangeLogin(ctx context.Context, rawCode, ip, ua string) (*authentication.TokenPair, error) {
	code, err := s.consumeLoginCode(ctx, rawCode)
	if err != nil {
		return nil, err
	}
	return s.auth.IssuePair(ctx, code.UserID, code.OrganizationID, ip, ua, provider)
}

// loginCodeRefusals are the errors a connection's login code is refused with.
var loginCodeRefusals = logincode.Refusals{
	Required: ErrLoginCodeRequired,
	Invalid:  ErrLoginCodeInvalid,
	Used:     ErrLoginCodeUsed,
	Expired:  ErrLoginCodeExpired,
	Draft:    ErrConnectionDraft,
	Disabled: ErrConnectionDisabled,
}

// consumeLoginCode spends a one-time code the callback issued, once, and
// returns whom it signs in. A code of a connection since disabled, put back to
// draft or deleted is refused.
func (s *Service) consumeLoginCode(ctx context.Context, rawCode string) (logincode.Code, error) {
	return logincode.Consume(ctx, s.pool, logincode.KindOIDCConnection, rawCode, loginCodeRefusals)
}

// signInConnection is a connection being signed in through, with its client
// secret opened.
type signInConnection struct {
	Connection
	clientSecret string
}

// loadForSignIn loads a connection by ID alone, for the public sign-in
// endpoints, and refuses one that isn't active: a draft one is still being
// set up, so it signs nobody in until an administrator turns it on.
func (s *Service) loadForSignIn(ctx context.Context, id uuid.UUID) (*signInConnection, error) {
	r, err := s.q.GetOidcConnectionForSignIn(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c := &signInConnection{Connection: *toConnection(dbgen.GetOidcConnectionRow{
		ID: r.ID, OrganizationID: r.OrganizationID, Name: r.Name, Issuer: r.Issuer, DiscoveryUrl: r.DiscoveryUrl,
		ClientID: r.ClientID, Scopes: r.Scopes, AllowedIdpTenantIds: r.AllowedIdpTenantIds,
		EmailClaim: r.EmailClaim, NameClaim: r.NameClaim, GivenNameClaim: r.GivenNameClaim,
		FamilyNameClaim: r.FamilyNameClaim, GroupsClaim: r.GroupsClaim, Status: r.Status,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, LastLoginAt: r.LastLoginAt,
	})}
	if err := signInStatus(c.Status); err != nil {
		return c, err
	}
	plain, err := s.box.Open(c.OrganizationID, secretPurpose, c.ID.String(), r.ClientSecretCt, r.ClientSecretNonce)
	if err != nil {
		return c, ErrMisconfigured.Wrap(err)
	}
	c.clientSecret = string(plain)
	return c, nil
}

// signInStatus refuses a sign-in through a connection that isn't active.
func signInStatus(status string) error {
	switch status {
	case "active":
		return nil
	case "draft":
		return ErrConnectionDraft
	}
	return ErrConnectionDisabled
}

// touchLastLogin stamps the connection's last sign-in. Best effort.
func (s *Service) touchLastLogin(ctx context.Context, c *signInConnection) {
	_ = s.q.TouchOidcConnectionLastLogin(ctx, dbgen.TouchOidcConnectionLastLoginParams{ID: c.ID, OrganizationID: c.OrganizationID})
}

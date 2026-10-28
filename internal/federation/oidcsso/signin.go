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

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/identitylink"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidcsso/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

const (
	stateTTL      = 10 * time.Minute // how long a begun sign-in can be completed
	loginCodeTTL  = 5 * time.Minute  // how long the console has to trade its code
	sweepInterval = 5 * time.Minute  // how often a replica deletes expired states and codes
)

// providerFor reads c's discovery document and returns it with the ID token
// rules it implies.
func (s *Service) providerFor(ctx context.Context, c *signInConnection) (discovery, idTokenRules, error) {
	doc, err := s.providers.discover(ctx, c.discoveryURL())
	if errors.Is(err, errDiscoveryInvalid) {
		return discovery{}, idTokenRules{}, errs.ErrOIDCSSOMisconfigured.Wrap(err)
	}
	if err != nil {
		return discovery{}, idTokenRules{}, errs.ErrOIDCSSOProviderUnreachable.Wrap(err)
	}
	rules, err := rulesFor(&c.Connection, doc)
	if err != nil {
		return discovery{}, idTokenRules{}, errs.ErrOIDCSSOMisconfigured.Wrap(err)
	}
	return doc, rules, nil
}

// sweep deletes expired sign-in states and stale login codes, at most once
// per sweepInterval on this replica. Best effort: the deletes are idempotent
// and touch only rows past their use.
func (s *Service) sweep(ctx context.Context) {
	now := time.Now().Unix()
	due := s.nextSweep.Load()
	if now < due || !s.nextSweep.CompareAndSwap(due, now+int64(sweepInterval.Seconds())) {
		return
	}
	_ = s.q.DeleteExpiredOidcConnectionStates(ctx)
	_ = s.q.DeleteStaleOidcConnectionLoginCodes(ctx)
}

// BeginSignIn starts a sign-in through connection id, returning the provider
// URL to send the browser to and the state to bind to that browser. The state,
// PKCE verifier and nonce are kept, hashed where the provider echoes them, for
// the callback; redirectURI is where the provider sends the browser back.
func (s *Service) BeginSignIn(ctx context.Context, id uuid.UUID, redirectURI string) (authURL, state string, err error) {
	c, err := s.loadForSignIn(ctx, id)
	if err != nil {
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
	state, stateHash, err := codes.URLToken()
	if err != nil {
		return "", "", err
	}
	nonce, nonceHash, err := codes.URLToken()
	if err != nil {
		return "", "", err
	}
	s.sweep(ctx)
	if err := s.q.InsertOidcConnectionState(ctx, dbgen.InsertOidcConnectionStateParams{
		StateHash:    stateHash,
		ConnectionID: c.ID,
		CodeVerifier: verifier,
		NonceHash:    nonceHash,
		RedirectUri:  redirectURI,
		ExpiresAt:    time.Now().UTC().Add(stateTTL),
	}); err != nil {
		return "", "", err
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.ClientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {strings.Join(c.Scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	sep := "?"
	if strings.Contains(doc.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return doc.AuthorizationEndpoint + sep + q.Encode(), state, nil
}

// Callback is a provider's answer to a sign-in, as the browser brings it back.
type Callback struct {
	ConnectionID  uuid.UUID
	State, Code   string
	ProviderError string // the error parameter, when the provider refused
	StartedHere   bool   // the browser holds the sign-in's binding
	IP, UserAgent string
}

// CompleteSignIn spends the sign-in's state, then, when this browser began it,
// trades the code for an ID token, validates it, finds or provisions the
// person it names and returns a one-time code the console trades for a
// session at ExchangeLogin. Each refusal is recorded as a failed sign-in.
func (s *Service) CompleteSignIn(ctx context.Context, cb Callback) (loginCode string, err error) {
	c, err := s.loadForSignIn(ctx, cb.ConnectionID)
	if c == nil {
		return "", err
	}
	var userID uuid.UUID
	defer func() {
		if err != nil {
			s.recordFailure(ctx, c, userID, cb, err)
		}
	}()
	if err != nil {
		return "", err
	}
	if cb.State == "" {
		return "", errs.ErrOIDCSSOCallbackInvalid
	}
	st, err := s.q.ConsumeOidcConnectionState(ctx, codes.Hash(cb.State))
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errs.ErrOIDCSSOStateInvalid
	}
	if err != nil {
		return "", err
	}
	if st.ConnectionID != c.ID || !time.Now().Before(st.ExpiresAt) {
		return "", errs.ErrOIDCSSOStateInvalid
	}
	// A sign-in completes only in the browser that began it, or whoever began
	// one could have someone else's browser finish it as themselves.
	if !cb.StartedHere {
		return "", errs.ErrOIDCSSOOtherBrowser
	}
	if cb.ProviderError != "" {
		return "", errs.ErrOIDCSSOProviderRefused
	}
	if cb.Code == "" {
		return "", errs.ErrOIDCSSOCallbackInvalid
	}
	doc, rules, err := s.providerFor(ctx, c)
	if err != nil {
		return "", err
	}
	rawIDToken, err := s.providers.exchangeCode(ctx, doc, c.ClientID, c.clientSecret, cb.Code, st.RedirectUri, st.CodeVerifier)
	if err != nil {
		return "", errs.ErrOIDCSSOTokenExchangeFailed.Wrap(err)
	}
	rules.nonceHash = st.NonceHash
	claims, err := s.providers.verifyIDToken(ctx, rawIDToken, doc.JWKSURI, rules)
	if err != nil {
		return "", errs.ErrOIDCSSOIDTokenInvalid.Wrap(err)
	}
	if userID, err = s.findOrCreateUser(ctx, c, c.profileOf(claims)); err != nil {
		return "", err
	}
	if s.auth != nil {
		// A suspended or deleted account gets no code to sign in with.
		if err := s.auth.CheckSignInAccount(ctx, userID, c.TenantID, provider, cb.IP, cb.UserAgent); err != nil {
			return "", err
		}
	}
	rawCode, codeHash, err := codes.URLToken()
	if err != nil {
		return "", err
	}
	if err := s.q.InsertOidcConnectionLoginCode(ctx, dbgen.InsertOidcConnectionLoginCodeParams{
		CodeHash:     codeHash,
		ConnectionID: c.ID,
		UserID:       userID,
		ExpiresAt:    time.Now().UTC().Add(loginCodeTTL),
	}); err != nil {
		return "", err
	}
	s.touchLastLogin(ctx, c)
	return rawCode, nil
}

// recordFailure records a refused sign-in through c in the organisation's
// audit trail, with the error code as its reason.
func (s *Service) recordFailure(ctx context.Context, c *signInConnection, userID uuid.UUID, cb Callback, err error) {
	if s.auth == nil {
		return
	}
	reason := errs.CodeInternal
	if e := errs.As(err); e != nil {
		reason = e.Code
	}
	meta := map[string]any{"connection_id": c.ID.String()}
	if code := safeCode(cb.ProviderError); code != "" {
		meta["provider_error"] = code
	}
	s.auth.RecordSignInFailure(ctx, auth.SignInFailure{
		TenantID:  c.TenantID,
		UserID:    userID,
		Method:    provider,
		Reason:    reason,
		IP:        cb.IP,
		UserAgent: cb.UserAgent,
		Metadata:  meta,
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

// findOrCreateUser returns the person c linked to the token's subject, else
// the one with its email address, else a new one, and links the subject to c.
// An address is adopted or given an account only on a domain the organisation
// manages, and only while the provider hasn't said it is unverified; a new
// account only where that domain has just-in-time provisioning on; an adopted
// account must have the organisation as its home, a verified address, and not
// administer the organisation. One transaction, so concurrent sign-ins can't
// duplicate rows.
func (s *Service) findOrCreateUser(ctx context.Context, c *signInConnection, p profile) (uuid.UUID, error) {
	tenantID := c.TenantID
	// Read before the transaction: it reads every organisation's domains.
	domain, managed, err := domainverify.ManagingDomain(postgres.AcrossTenants(ctx), s.pool, p.email)
	if err != nil {
		return uuid.Nil, err
	}
	meta, err := linkMetadata(p)
	if err != nil {
		return uuid.Nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	var email *string
	if p.email != "" {
		email = &p.email
	}
	link := dbgen.LinkExternalIdentityParams{
		TenantID:     tenantID,
		Provider:     provider,
		ConnectionID: c.ID,
		Subject:      p.subject,
		Email:        email,
		Metadata:     meta,
	}

	userID, err := q.GetExternalIdentityUser(ctx, dbgen.GetExternalIdentityUserParams{
		TenantID:     tenantID,
		Provider:     provider,
		ConnectionID: c.ID,
		Subject:      p.subject,
	})
	if err == nil {
		// A linked subject signs in only while this organisation is still the
		// account's home.
		home, herr := identitylink.HomeIn(ctx, tx, userID, tenantID)
		if herr != nil {
			return uuid.Nil, herr
		}
		if !home {
			return uuid.Nil, errs.ErrOIDCSSOUserTenantMismatch
		}
		link.UserID = userID
		if err := q.LinkExternalIdentity(ctx, link); err != nil {
			return uuid.Nil, err
		}
		return userID, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, err
	}
	if p.email == "" {
		return uuid.Nil, errs.ErrOIDCSSONoEmail
	}
	// The token proves only that this connection's provider vouched for the
	// address. Anyone who can configure a connection runs one, so it speaks
	// only for the organisation's own domains; and an address the provider
	// itself calls unverified isn't vouched for at all. A provider that doesn't
	// say (Microsoft Entra ID) is trusted for those domains, as SAML is.
	if !managed || domain.TenantID != tenantID {
		return uuid.Nil, errs.ErrOIDCSSOEmailDomainUnverified
	}
	if p.verified != nil && !*p.verified {
		return uuid.Nil, errs.ErrOIDCSSOEmailUnverified
	}

	userID, err = q.GetUserByEmail(ctx, p.email)
	if errors.Is(err, pgx.ErrNoRows) {
		if !domain.JIT {
			return uuid.Nil, errs.ErrOIDCSSOJITNotAllowed
		}
		var displayName *string
		if p.name != "" {
			displayName = &p.name
		}
		userID, err = q.InsertUserWithEmail(ctx, dbgen.InsertUserWithEmailParams{
			TenantID:    pgUUID(tenantID),
			Email:       p.email,
			DisplayName: displayName,
		})
		if err != nil {
			return uuid.Nil, err
		}
	} else if err != nil {
		return uuid.Nil, err
	} else {
		// Emails are unique across organisations, so the address may be another
		// organisation's account; and an administrator keeps the credentials
		// they have, or the connection's provider could take over an owner.
		home, herr := identitylink.HomeIn(ctx, tx, userID, tenantID)
		if herr != nil {
			return uuid.Nil, herr
		}
		if !home {
			return uuid.Nil, errs.ErrOIDCSSOUserTenantMismatch
		}
		verified, verr := identitylink.AddressVerified(ctx, tx, userID)
		if verr != nil {
			return uuid.Nil, verr
		}
		if !verified {
			return uuid.Nil, errs.ErrOIDCSSOAccountUnverified
		}
		admin, aerr := identitylink.Administers(ctx, tx, userID, tenantID)
		if aerr != nil {
			return uuid.Nil, aerr
		}
		if admin {
			return uuid.Nil, errs.ErrOIDCSSOAccountAdministers
		}
		if err := identitylink.MarkAddressVerified(ctx, tx, userID); err != nil {
			return uuid.Nil, err
		}
	}
	link.UserID = userID
	if err := q.LinkExternalIdentity(ctx, link); err != nil {
		return uuid.Nil, err
	}
	return userID, tx.Commit(ctx)
}

// ExchangeLogin trades a one-time login code for a token pair, while the
// connection that issued it is still active.
func (s *Service) ExchangeLogin(ctx context.Context, rawCode, ip, ua string) (*auth.TokenPair, error) {
	if rawCode == "" {
		return nil, errs.ErrOIDCSSOLoginCodeRequired
	}
	codeHash := codes.Hash(rawCode)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	row, err := q.ConsumeOidcConnectionLoginCode(ctx, codeHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrOIDCSSOLoginCodeInvalid
	}
	if err != nil {
		return nil, err
	}
	if row.UsedAt.Valid {
		return nil, errs.ErrOIDCSSOLoginCodeUsed
	}
	if !time.Now().Before(row.ExpiresAt) {
		return nil, errs.ErrOIDCSSOLoginCodeExpired
	}
	if err := signInStatus(row.Status); err != nil {
		return nil, err
	}
	if err := q.MarkOidcConnectionLoginCodeUsed(ctx, codeHash); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.auth.IssuePair(ctx, row.UserID, row.TenantID, ip, ua, provider)
}

package oidc

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc/dbgen"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/password"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TokenResponse is a token endpoint answer (RFC 6749 §5.1).
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	// IssuedTokenType is set for RFC 8693 token-exchange responses.
	IssuedTokenType string `json:"issued_token_type,omitempty"`
}

// RFC 8693 token-exchange identifiers.
const (
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange" // #nosec G101 -- RFC 8693 URN, not a credential
	tokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"   // #nosec G101 -- RFC 8693 URN, not a credential
)

// authedClient is the client a request identified itself as. For a public
// client that identity is only claimed: its client_id is in every sign-in link
// and it has no secret, so an endpoint that needs proof calls
// requireConfidential.
type authedClient struct {
	ID         uuid.UUID
	TenantID   uuid.UUID
	ClientID   string
	Type       string
	GrantTypes []string
	Scopes     []string // the scopes it is registered for
}

// authenticateClient identifies the calling client: a confidential client must
// present its secret, a public one presents none. A wrong secret is audited
// against the client's tenant. Unknown client ids are refused without an audit
// row, so an unauthenticated caller can't fill the audit trail.
func (s *Service) authenticateClient(ctx context.Context, clientID, clientSecret string) (authedClient, error) {
	row, err := s.q.GetClientForAuth(ctx, clientID)
	if errors.Is(err, pgx.ErrNoRows) {
		return authedClient{}, errs.ErrOIDCClientAuthFailed
	}
	if err != nil {
		return authedClient{}, err
	}
	c := authedClient{ID: row.ID, TenantID: row.TenantID, ClientID: clientID, Type: row.Type, GrantTypes: row.GrantTypes, Scopes: row.Scopes}
	if row.Type == "confidential" {
		// A locked-out application is refused before its secret is compared,
		// with the same answer as a wrong one.
		locked, err := s.clientLocked(ctx, row.ID)
		if err != nil {
			return authedClient{}, err
		}
		if locked {
			return authedClient{}, errs.ErrOIDCClientAuthFailed
		}
		var ok, rehash bool
		if row.ClientSecretHash != nil {
			if ok, rehash, err = password.VerifySecret(ctx, *row.ClientSecretHash, clientSecret); err != nil {
				return authedClient{}, err
			}
		}
		if !ok {
			s.clientAuthFailed(ctx, c)
			return authedClient{}, errs.ErrOIDCClientAuthFailed
		}
		if rehash {
			upgraded := password.HashSecret(clientSecret)
			if err := s.q.UpgradeOIDCClientSecretHash(ctx, dbgen.UpgradeOIDCClientSecretHashParams{
				NewHash: &upgraded, ID: row.ID, TenantID: row.TenantID, OldHash: row.ClientSecretHash,
			}); err != nil {
				slog.Warn("oidc client hash upgrade failed", "err", err, "client_id", clientID)
			}
		}
		if err := s.q.ClearClientAuthFailures(ctx, dbgen.ClearClientAuthFailuresParams{ClientRowID: row.ID, SourceNetwork: callerNetwork(ctx)}); err != nil {
			return authedClient{}, err
		}
	}
	return c, nil
}

// requireConfidential refuses a public client at an endpoint that relies on
// client authentication (introspection, token exchange, backchannel sign-in):
// for a public client, presenting its client_id proves nothing.
func (s *Service) requireConfidential(ctx context.Context, c authedClient) error {
	if c.Type == "confidential" {
		return nil
	}
	s.auditClientAuthFailure(ctx, c, "public_client")
	return errs.ErrOIDCClientAuthFailed
}

// auditClientAuthFailure records a refused client authentication. Best-effort:
// the refusal stands whether or not the row is written.
func (s *Service) auditClientAuthFailure(ctx context.Context, c authedClient, reason string) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)
	tenantID, id := c.TenantID, c.ID
	if audit.Record(ctx, tx, audit.Event{
		TenantID: &tenantID, ActorType: "client", Action: "oidc.client_auth_failed",
		ResourceType: "oidc_client", ResourceID: &id, IP: httpx.ClientIPFromContext(ctx),
		Metadata: map[string]any{"client_id": c.ClientID, "reason": reason},
	}) == nil {
		_ = tx.Commit(ctx)
	}
}

// TokenExchange implements RFC 8693 downscoping: a confidential client with the
// token_exchange grant swaps a valid access token for a new one with a subset of
// its scopes. It never adds scopes or changes the subject or tenant.
func (s *Service) TokenExchange(ctx context.Context, clientID, clientSecret, subjectToken, subjectTokenType, requestedTokenType, scope, actorToken, actorTokenType, resource string) (*TokenResponse, error) {
	client, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	if err := s.requireConfidential(ctx, client); err != nil {
		return nil, err
	}
	if err := checkResource(ctx, s.q, client.TenantID, resource); err != nil {
		return nil, err
	}
	if !containsAny(client.GrantTypes, "token_exchange", grantTypeTokenExchange) {
		return nil, errs.ErrOIDCGrantTypeNotAllowed
	}
	if subjectToken == "" {
		return nil, errs.ErrOIDCSubjectTokenRequired
	}
	if subjectTokenType != "" && subjectTokenType != tokenTypeAccessToken {
		return nil, errs.ErrOIDCSubjectTokenTypeUnsupported
	}
	if requestedTokenType != "" && requestedTokenType != tokenTypeAccessToken {
		return nil, errs.ErrOIDCRequestedTokenTypeUnsupported
	}
	// Whatever its audience; who may exchange it is decided below.
	claims, err := s.issuer.VerifyAccessAnyAudience(subjectToken)
	if err != nil {
		return nil, errs.ErrOIDCSubjectTokenInvalid
	}
	// The subject token must belong to the calling client's tenant; otherwise any
	// client could keep renewing an access token stolen from another tenant.
	caller, err := s.q.GetClientName(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if claims.TenantID != caller.TenantID {
		return nil, errs.ErrOIDCSubjectTokenInvalid
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, errs.ErrOIDCSubjectTokenNoSubject
	}
	// Only a person's access token names them in user_id: an ID token, signed by
	// the same key, carries none and is no credential.
	if claims.UserID != userID {
		return nil, errs.ErrOIDCSubjectTokenInvalid
	}
	// The caller must be entitled to the subject's token: issued to it, issued
	// for a resource it serves, or the person delegated to it (consented).
	// Otherwise an application allowed to exchange could mint tokens in the
	// name of anyone whose token passes through it, an administrator's too.
	entitled, consented, err := s.mayExchange(ctx, caller.TenantID, clientID, userID, claims)
	if err != nil {
		return nil, err
	}
	if !entitled {
		return nil, errs.ErrOIDCSubjectTokenInvalid
	}
	// A suspended or deleted person, or a closed organisation, gets nothing.
	live, err := s.activeTenantPrincipal(ctx, s.q, userID, claims.TenantID)
	if err != nil {
		return nil, err
	}
	if !live {
		return nil, errs.ErrAuthAccountSuspended
	}
	// Nor does the token of a session that has ended.
	sessionLive, err := s.tokenSessionLive(ctx, claims)
	if err != nil {
		return nil, err
	}
	if !sessionLive {
		return nil, errs.ErrOIDCSubjectTokenInvalid
	}
	// A chain of exchanges is bounded.
	if claims.ExchangeDepth >= s.exchangeMaxDepth {
		return nil, errs.ErrOIDCExchangeDepthExceeded
	}
	// Downscope: the result is at most the subject's scopes (never escalate),
	// and at most what the caller may hold: the scopes it is registered for
	// and, when it holds the token by the person's consent, those consented
	// to. Otherwise exchanging another application's token would hand the
	// caller that application's access.
	held := intersect(strings.Fields(claims.Scope), client.Scopes)
	if consented != nil {
		held = intersect(held, consented)
	}
	granted, ok := downscope(held, scope)
	if !ok {
		return nil, errs.ErrOIDCScopeExceedsSubject
	}
	// Delegation (RFC 8693): an actor_token names the party acting on the
	// subject's behalf (e.g. an AI agent exercising a user's authority). The
	// issued token records it in an `act` claim for downstream authz + audit.
	var actorSubject string
	if actorToken != "" {
		if actorTokenType != "" && actorTokenType != tokenTypeAccessToken {
			return nil, errs.ErrOIDCActorTokenTypeUnsupported
		}
		actorClaims, aerr := s.issuer.VerifyAccess(actorToken)
		if aerr != nil {
			return nil, errs.ErrOIDCActorTokenInvalid
		}
		// The delegating actor must also be inside the caller's tenant, or the
		// `act` claim could name a principal from another organisation.
		if actorClaims.TenantID != caller.TenantID {
			return nil, errs.ErrOIDCActorTokenInvalid
		}
		actorSubject = actorClaims.Subject
	}
	// A session of its own, linked to the one it came from in the audit
	// record, so the chain doesn't read as one sign-in.
	sid := uuid.New()
	scopeStr := strings.Join(granted, " ")
	// Never outlive the subject token: exchange can't extend a credential.
	var notAfter time.Time
	if claims.ExpiresAt != nil {
		notAfter = claims.ExpiresAt.Time
	}
	var (
		access string
		exp    time.Time
	)
	// Issued to the requesting client, which it names: an exchange cannot turn
	// an application token into one the management API accepts.
	access, exp, err = s.issuer.IssueClientAccess(tokens.ClientAccess{
		UserID: userID, TenantID: claims.TenantID, SessionID: sid, Scopes: scopeStr,
		ActorSubject: actorSubject, Resource: resource, ClientID: clientID,
		NotAfter: notAfter, ExchangeDepth: claims.ExchangeDepth + 1,
	})
	if err != nil {
		return nil, err
	}
	if err := s.auditExchange(ctx, claims, clientID, userID, sid, actorSubject, scopeStr, resource, exp); err != nil {
		return nil, err
	}
	return &TokenResponse{
		AccessToken:     access,
		TokenType:       "Bearer",
		ExpiresIn:       int(time.Until(exp).Seconds()),
		Scope:           scopeStr,
		IssuedTokenType: tokenTypeAccessToken,
	}, nil
}

// downscope returns the scopes to grant for a token-exchange: the requested
// scopes if every one is held by the subject (never escalate), or the subject's
// own scopes when no scope is requested. ok=false means the request asked for a
// scope the subject token doesn't carry.
func downscope(subjectScopes []string, requestedScope string) (granted []string, ok bool) {
	if strings.TrimSpace(requestedScope) == "" {
		return subjectScopes, true
	}
	requested := strings.Fields(requestedScope)
	for _, r := range requested {
		if !contains(subjectScopes, r) {
			return nil, false
		}
	}
	return requested, true
}

func containsAny(set []string, vs ...string) bool {
	for _, v := range vs {
		if contains(set, v) {
			return true
		}
	}
	return false
}

// ExchangeCode swaps an authorization_code for tokens.
func (s *Service) ExchangeCode(ctx context.Context, clientID, clientSecret, code, redirectURI, codeVerifier, resource string) (*TokenResponse, error) {
	client, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	// A client no longer registered for codes redeems none it was issued.
	if !contains(client.GrantTypes, "authorization_code") {
		return nil, errs.ErrOIDCGrantTypeNotAllowed
	}
	clientInfo, err := s.q.GetClientForAuth(ctx, clientID)
	if err != nil {
		return nil, err
	}
	hash := codes.Hash(code)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	q := s.q.WithTx(tx)
	ac, err := q.ConsumeAuthorizationCode(ctx, dbgen.ConsumeAuthorizationCodeParams{CodeHash: hash, ClientID: clientID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrOIDCAuthCodeInvalid
	}
	if err != nil {
		return nil, err
	}
	userID := ac.UserID
	tenantID := ac.TenantID
	scopes := ac.Scopes
	nonce := ac.Nonce
	challenge := ac.CodeChallenge
	method := ac.CodeChallengeMethod
	if ac.UsedAt.Valid {
		// A code presented twice was seen by someone else: end what its first
		// redemption issued (RFC 6749 §4.1.2), then refuse.
		if err := s.revokeGrantFromCode(ctx, tx, clientID, hash, userID, tenantID); err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, errs.ErrOIDCAuthCodeUsed
	}
	if time.Now().After(ac.ExpiresAt) {
		return nil, errs.ErrOIDCAuthCodeExpired
	}
	if ac.RedirectUri != redirectURI {
		return nil, errs.ErrOIDCRedirectURIMismatch
	}
	// The token is for the resource the authorization named; a token request
	// may repeat it but not name another.
	if ac.Resource != nil && *ac.Resource != "" {
		if resource != "" && resource != *ac.Resource {
			return nil, oauthErr("invalid_target", "resource differs from the one the authorization was for")
		}
		resource = *ac.Resource
	}
	if err := checkResource(ctx, q, tenantID, resource); err != nil {
		return nil, err
	}
	// A code issued with no challenge redeems only while its confidential
	// application's exemption is still in force.
	if (challenge == nil || *challenge == "") && (clientInfo.Type != "confidential" || !clientInfo.PkceExempt) {
		return nil, errs.ErrOIDCCodeChallengeRequired
	}
	if challenge != nil && *challenge != "" {
		if codeVerifier == "" {
			return nil, errs.ErrOIDCCodeVerifierRequired
		}
		if !validPKCEValue(codeVerifier, 43, 128) {
			return nil, errs.ErrOIDCCodeVerifierInvalid
		}
		// We support S256 only (the recommended PKCE method).
		if method == nil || *method != "S256" {
			return nil, errs.ErrOIDCCodeChallengeMethodUnsupported
		}
		computed := codes.Hash(codeVerifier)
		if subtle.ConstantTimeCompare([]byte(computed), []byte(*challenge)) != 1 {
			return nil, errs.ErrOIDCCodeVerifierInvalid
		}
	}
	// A code issued before the account was suspended or deleted, or before its
	// person left the application's organisation, is spent, not redeemed.
	active, err := accountActive(ctx, q, userID)
	if err != nil {
		return nil, err
	}
	member, err := s.activeTenantPrincipal(ctx, q, userID, tenantID)
	if err != nil {
		return nil, err
	}
	if err := q.MarkAuthorizationCodeUsed(ctx, hash); err != nil {
		return nil, err
	}
	if !active || !member {
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		if !active {
			return nil, errs.ErrAuthAccountSuspended
		}
		return nil, errs.ErrOIDCUserTenantMismatch
	}
	// The grant is written while the code is still locked, so a sign-out of
	// the hosted-login session the code came from either spends the code first
	// (and this redemption fails) or waits and then ends the grant.
	refresh := ""
	if issuesRefreshToken(clientInfo.Scopes, client.GrantTypes, scopes) {
		refresh, err = s.issueRefreshToken(ctx, q, clientID, userID, tenantID, scopes, resource, ac.LoginSessionID, hash, ac.AuthTime)
		if err != nil {
			return nil, err
		}
	}
	if err := user.RecordActive(ctx, tx, tenantID, userID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	// RFC 8707: bind the token's audience to the requested resource (if any).
	// Its sid is the hosted-login session, as the ID token's is.
	access, _, err := s.issuer.IssueClientAccess(tokens.ClientAccess{
		UserID: userID, TenantID: tenantID, SessionID: uuidOrNil(ac.LoginSessionID), Scopes: strings.Join(scopes, " "), Resource: resource, ClientID: clientID,
	})
	if err != nil {
		return nil, err
	}
	idTok := ""
	if contains(scopes, "openid") {
		t, err := s.signIDToken(ctx, idToken{
			UserID: userID, TenantID: tenantID, Audience: clientID, Nonce: derefStr(nonce), Scopes: scopes,
			AuthTime: timeOrZero(ac.AuthTime), SessionID: uuidOrNil(ac.LoginSessionID),
		})
		if err != nil {
			return nil, err
		}
		idTok = t
	}
	return &TokenResponse{
		AccessToken:  access,
		IDToken:      idTok,
		RefreshToken: refresh,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.issuer.AccessTTL().Seconds()),
		Scope:        strings.Join(scopes, " "),
	}, nil
}

// issueRefreshToken stores a refresh token for the client and user and returns
// it. resource is the RFC 8707 resource bound to the access token ("" for none),
// loginSessionID the hosted-login session and authTime when the person signed
// in there (NULL for none), and codeHash the redeemed code ("" for none). q
// lets it run in the caller's transaction.
func (s *Service) issueRefreshToken(ctx context.Context, q *dbgen.Queries, clientID string, userID, tenantID uuid.UUID, scopes []string, resource string, loginSessionID pgtype.UUID, codeHash string, authTime pgtype.Timestamptz) (string, error) {
	raw, hash, err := tokens.NewRefreshToken()
	if err != nil {
		return "", err
	}
	var res *string
	if resource != "" {
		res = &resource
	}
	exp := time.Now().UTC().Add(s.issuer.RefreshTTL())
	if err := q.InsertRefreshToken(ctx, dbgen.InsertRefreshTokenParams{
		ID:        uuid.New(),
		TokenHash: hash, ClientID: clientID, UserID: userID, TenantID: tenantID,
		Scopes: scopes, ExpiresAt: exp, Resource: res, LoginSessionID: loginSessionID,
		DefaultMaxAgeSeconds: s.grantMaxAge.Seconds(), AuthorizationCodeHash: optionalString(codeHash),
		AuthTime: authTime,
	}); err != nil {
		return "", err
	}
	return raw, nil
}

// RefreshToken handles the refresh_token grant: it rotates the token and
// reissues tokens for the original grant. Replaying a used token revokes every
// live token for the client and user. A resource (RFC 8707) other than the one
// the grant is bound to is invalid_target; none carries the bound one forward.
func (s *Service) RefreshToken(ctx context.Context, clientID, clientSecret, rawRefresh, resource string) (*TokenResponse, error) {
	client, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	// A client no longer registered for refresh renews nothing.
	if !contains(client.GrantTypes, "refresh_token") {
		return nil, errs.ErrOIDCGrantTypeNotAllowed
	}
	if rawRefresh == "" {
		return nil, errs.ErrOIDCRefreshTokenRequired
	}
	hash := tokens.HashRefresh(rawRefresh)

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	q := s.q.WithTx(tx)
	rt, err := q.LockRefreshToken(ctx, hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrOIDCRefreshTokenInvalid
	}
	if err != nil {
		return nil, err
	}
	// A refresh token may only be redeemed by the client it was issued to.
	if rt.ClientID != clientID {
		return nil, errs.ErrOIDCRefreshTokenClientMismatch
	}
	if rt.RevokedAt.Valid {
		return nil, errs.ErrOIDCRefreshTokenRevoked
	}
	// A suspended or deleted account renews nothing, and the application's
	// grants for it end, so reactivating the account doesn't revive them.
	active, err := accountActive(ctx, q, rt.UserID)
	if err != nil {
		return nil, err
	}
	if !active {
		if err := q.RevokeRefreshTokenChain(ctx, dbgen.RevokeRefreshTokenChainParams{ClientID: clientID, UserID: rt.UserID}); err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, errs.ErrAuthAccountSuspended
	}
	// Nor does it renew once the person has left the application's
	// organisation or the organisation has been suspended.
	if live, err := s.activeTenantPrincipal(ctx, q, rt.UserID, rt.TenantID); err != nil {
		return nil, err
	} else if !live {
		return nil, errs.ErrOIDCUserTenantMismatch
	}
	if rt.UsedAt.Valid {
		// Reuse — assume theft: revoke every live token for this (client, user) and audit it.
		if err := s.handleRefreshReuse(ctx, tx, clientID, rt.UserID, rt.TenantID, rt.ID); err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, errs.ErrOIDCRefreshTokenReuse
	}
	if time.Now().After(rt.ExpiresAt) {
		return nil, errs.ErrOIDCRefreshTokenExpired
	}
	// RFC 8707 §2.2: a refresh may name only the resource the grant is bound
	// to; naming none carries the bound one forward. Either way it must still be
	// registered, so a removed resource gets no new tokens.
	bound := derefStr(rt.Resource)
	if resource != "" && resource != bound {
		return nil, oauthErr("invalid_target", "resource differs from the one the grant was for")
	}
	resource = bound
	if err := checkResource(ctx, q, rt.TenantID, resource); err != nil {
		return nil, err
	}
	// Only the granted scopes the application still registers carry forward
	// (RFC 6749 §6 lets a refresh narrow); with none left it renews nothing.
	scopes := stillPermitted(client, rt.Scopes)
	if !slices.ContainsFunc(scopes, func(sc string) bool { return sc != scopeOfflineAccess }) {
		return nil, oauthErr("invalid_scope", "the application no longer registers any scope of this grant")
	}

	newRaw, newHash, err := tokens.NewRefreshToken()
	if err != nil {
		return nil, err
	}
	var newRes *string
	if resource != "" {
		newRes = &resource
	}
	newExp := time.Now().UTC().Add(s.issuer.RefreshTTL())
	newID, err := q.InsertRotatedRefreshToken(ctx, dbgen.InsertRotatedRefreshTokenParams{
		TokenHash: newHash, ClientID: clientID, UserID: rt.UserID, TenantID: rt.TenantID,
		Scopes: scopes, ExpiresAt: newExp, Resource: newRes, LoginSessionID: rt.LoginSessionID,
		GrantExpiresAt: rt.GrantExpiresAt, AuthorizationCodeHash: rt.AuthorizationCodeHash,
		GrantID: rt.GrantID, AuthTime: rt.AuthTime,
	})
	if err != nil {
		return nil, err
	}
	if err := q.MarkRefreshTokenUsed(ctx, dbgen.MarkRefreshTokenUsedParams{
		NewID: pgtype.UUID{Bytes: newID, Valid: true},
		ID:    rt.ID,
	}); err != nil {
		return nil, err
	}
	if err := user.RecordActive(ctx, tx, rt.TenantID, rt.UserID); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	userID := rt.UserID
	tenantID := rt.TenantID

	access, _, err := s.issuer.IssueClientAccess(tokens.ClientAccess{
		UserID: userID, TenantID: tenantID, SessionID: uuidOrNil(rt.LoginSessionID), Scopes: strings.Join(scopes, " "), Resource: resource, ClientID: clientID,
	})
	if err != nil {
		return nil, err
	}
	idTok := ""
	if contains(scopes, "openid") {
		// The original sign-in's time and session (OIDC Core 12.2), not now's.
		t, err := s.signIDToken(ctx, idToken{
			UserID: userID, TenantID: tenantID, Audience: clientID, Scopes: scopes,
			AuthTime: timeOrZero(rt.AuthTime), SessionID: uuidOrNil(rt.LoginSessionID),
		})
		if err != nil {
			return nil, err
		}
		idTok = t
	}
	return &TokenResponse{
		AccessToken:  access,
		IDToken:      idTok,
		RefreshToken: newRaw,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.issuer.AccessTTL().Seconds()),
		Scope:        strings.Join(scopes, " "),
	}, nil
}

// stillPermitted returns the scopes of granted that client may still request.
func stillPermitted(client authedClient, granted []string) []string {
	return slices.DeleteFunc(slices.Clone(granted), func(sc string) bool {
		return !scopePermitted(client.Scopes, client.GrantTypes, sc)
	})
}

// handleRefreshReuse revokes every live refresh token for a (client, user) on replay and audits it.
// accountActive reports whether a user may still be issued tokens by any
// application grant: not suspended and not deleted, the rule the first-party
// refresh applies. A user who no longer exists is not active.
func accountActive(ctx context.Context, q *dbgen.Queries, userID uuid.UUID) (bool, error) {
	row, err := q.GetAccountStanding(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return !row.Deleted && row.Status != "suspended", nil
}

// mayExchange reports whether clientID may exchange a subject token of its
// tenant: the token was issued to it, or for a registered resource it serves,
// or the person has consented to it (a delegation it holds), when it also
// returns the scopes consented to (nil otherwise).
func (s *Service) mayExchange(ctx context.Context, tenantID uuid.UUID, clientID string, userID uuid.UUID, claims *tokens.Claims) (bool, []string, error) {
	if ok, err := s.mayIntrospect(ctx, tenantID, clientID, claims); err != nil || ok {
		return ok, nil, err
	}
	consented, err := s.q.GetConsent(ctx, dbgen.GetConsentParams{UserID: userID, ClientID: clientID})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	if consented == nil {
		consented = []string{}
	}
	return true, consented, nil
}

// intersect is the scopes of a that b also holds, in a's order.
func intersect(a, b []string) []string {
	out := []string{}
	for _, v := range a {
		if contains(b, v) {
			out = append(out, v)
		}
	}
	return out
}

// auditExchange records a token exchange: caller, subject, actor, scopes,
// resource, and the session the subject token came from.
func (s *Service) auditExchange(ctx context.Context, subject *tokens.Claims, clientID string, userID, sid uuid.UUID, actor, scopes, resource string, exp time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tenantID := subject.TenantID
	meta := map[string]any{
		"client_id": clientID, "scope": scopes, "resource": resource, "actor": actor,
		"subject_client_id": subject.ClientID, "exchange_depth": subject.ExchangeDepth + 1,
		"session_id": sid, "expires_at": exp,
	}
	if subject.SessionID != uuid.Nil {
		meta["from_session_id"] = subject.SessionID
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: &tenantID, ActorUserID: &userID, ActorType: "client",
		Action: "oidc.token_exchanged", ResourceType: "oidc_client", IP: httpx.ClientIPFromContext(ctx),
		Metadata: meta,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// revokeGrantFromCode ends the grant redeemed from the authorization code
// with this hash, after the code was presented again, and records it.
func (s *Service) revokeGrantFromCode(ctx context.Context, tx pgx.Tx, clientID, codeHash string, userID, tenantID uuid.UUID) error {
	n, err := s.q.WithTx(tx).RevokeGrantFromCode(ctx, dbgen.RevokeGrantFromCodeParams{
		ClientID: clientID, AuthorizationCodeHash: &codeHash,
	})
	if err != nil {
		return err
	}
	tid, uid := tenantID, userID
	return audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  &uid,
		ActorType:    "system",
		Action:       "oidc.authorization_code_reused",
		ResourceType: "oidc_client",
		Metadata: map[string]any{
			"client_id":      clientID,
			"grants_revoked": n,
			"reason":         "authorization_code_reuse",
		},
	})
}

func (s *Service) handleRefreshReuse(ctx context.Context, tx pgx.Tx, clientID string, userID, tenantID, tokenID uuid.UUID) error {
	q := s.q.WithTx(tx)
	if err := q.RevokeRefreshTokenChain(ctx, dbgen.RevokeRefreshTokenChainParams{
		ClientID: clientID, UserID: userID,
	}); err != nil {
		return err
	}
	tid, uid, rid := tenantID, userID, tokenID
	return audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  &uid,
		ActorType:    "system",
		Action:       "oidc.refresh_reuse_detected",
		ResourceType: "oidc_refresh_token",
		ResourceID:   &rid,
		Metadata: map[string]any{
			"client_id":        clientID,
			"refresh_token_id": tokenID,
			"reason":           "refresh_token_reuse",
		},
	})
}

// idToken is what an ID token is minted from.
type idToken struct {
	UserID, TenantID uuid.UUID
	// Audience is the client the token is for; Nonce the one the
	// authorization request sent ("" for none).
	Audience, Nonce string
	// Scopes decide which standard claims it carries (see userClaims).
	Scopes []string
	// AuthTime is when the person signed in (zero: unknown), reported as
	// auth_time; SessionID is the hosted-login session (uuid.Nil: none),
	// reported as sid so a sign-out notice can name it.
	AuthTime  time.Time
	SessionID uuid.UUID
}

func (s *Service) signIDToken(ctx context.Context, in idToken) (string, error) {
	now := time.Now().UTC()
	exp := now.Add(s.issuer.AccessTTL())
	claims := jwt.MapClaims{
		"iss":       s.issuer.JWTIssuer(),
		"sub":       in.UserID.String(),
		"aud":       in.Audience,
		"exp":       exp.Unix(),
		"iat":       now.Unix(),
		"tenant_id": in.TenantID.String(),
	}
	if in.Nonce != "" {
		claims["nonce"] = in.Nonce
	}
	if !in.AuthTime.IsZero() {
		claims["auth_time"] = in.AuthTime.Unix()
	}
	if in.SessionID != uuid.Nil {
		claims["sid"] = in.SessionID.String()
	}
	user, err := s.userClaims(ctx, in.UserID, in.Scopes)
	if err != nil {
		return "", err
	}
	for k, v := range user {
		claims[k] = v
	}
	return s.issuer.Sign(claims)
}

// tokenSubjectLive reports whether what an access token acts for still holds:
// its user active, not deleted and a member of its organisation (itself
// active), its session, if it is the user's own token, not ended, and its
// agent, if any, active.
func (s *Service) tokenSubjectLive(ctx context.Context, claims *tokens.Claims) (bool, error) {
	if live, err := s.tokenSessionLive(ctx, claims); err != nil || !live {
		return false, err
	}
	if claims.UserID != uuid.Nil {
		if member, err := s.activeTenantPrincipal(ctx, s.q, claims.UserID, claims.TenantID); err != nil || !member {
			return false, err
		}
	}
	if claims.ActorType == "service" && s.principalLive != nil {
		id, err := uuid.Parse(claims.Subject)
		if err != nil {
			return false, nil //nolint:nilerr // an unparseable principal ID means the token is not active
		}
		if live, err := s.principalLive(ctx, id); err != nil || !live {
			return false, err
		}
	}
	if claims.AgentID != "" && s.agentStatus != nil {
		id, err := uuid.Parse(claims.AgentID)
		if err != nil {
			return false, nil //nolint:nilerr // an unparseable agent ID means the token is not active
		}
		status, err := s.agentStatus(ctx, id)
		if err != nil || status != "active" {
			return false, err
		}
	}
	return true, nil
}

// tokenSessionLive reports whether the sign-in a person's access token names
// (sid) has not ended: their own session, or for an application's token the
// hosted-login session it was issued in. A token naming none passes, as does
// an exchanged one, whose session is its own and ends with the token.
func (s *Service) tokenSessionLive(ctx context.Context, claims *tokens.Claims) (bool, error) {
	person := claims.ActorType == "" || claims.ActorType == "user"
	if !person || claims.SessionID == uuid.Nil || claims.UserID == uuid.Nil || claims.ExchangeDepth > 0 {
		return true, nil
	}
	if claims.ClientID != "" {
		return s.q.ApplicationSignInLive(ctx, dbgen.ApplicationSignInLiveParams{
			SessionID: claims.SessionID, UserID: claims.UserID, TenantID: claims.TenantID, ClientID: claims.ClientID,
		})
	}
	if s.sessionLive == nil {
		return true, nil
	}
	return s.sessionLive(ctx, claims.SessionID, claims.UserID)
}

// activeTenantPrincipal reports whether userID is an active member of the
// active tenantID (its own account, or holding a role there), so may receive a
// token for it: the rule a browser sign-in to an application applies.
func (s *Service) activeTenantPrincipal(ctx context.Context, q *dbgen.Queries, userID, tenantID uuid.UUID) (bool, error) {
	return q.IsActiveTenantMember(ctx, dbgen.IsActiveTenantMemberParams{TenantID: tenantID, UserID: userID})
}

// resourcesOf is an audience without the platform's own entry: the resources
// a token was issued for.
func resourcesOf(aud []string, platform string) []string {
	var out []string
	for _, a := range aud {
		if a != platform {
			out = append(out, a)
		}
	}
	return out
}

// audienceClaim renders an audience as JWT does: one value as a string,
// several as a list.
func audienceClaim(aud []string) any {
	if len(aud) == 1 {
		return aud[0]
	}
	return aud
}

package oidc

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// RFC 8693 token-exchange identifiers.
const (
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange" // #nosec G101 -- RFC 8693 URN, not a credential
	tokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"   // #nosec G101 -- RFC 8693 URN, not a credential
)

// TokenExchange implements RFC 8693 downscoping: a confidential client with the
// token_exchange grant swaps a valid access token for a new one with a subset of
// its scopes. It never adds scopes or changes the subject or organization.
func (s *Service) TokenExchange(ctx context.Context, clientID, clientSecret, subjectToken, subjectTokenType, requestedTokenType, scope, actorToken, actorTokenType, resource string) (*TokenResponse, error) {
	client, err := s.exchangingClient(ctx, clientID, clientSecret, resource)
	if err != nil {
		return nil, err
	}
	if subjectToken == "" {
		return nil, ErrSubjectTokenRequired
	}
	if subjectTokenType != "" && subjectTokenType != tokenTypeAccessToken {
		return nil, ErrSubjectTokenTypeUnsupported
	}
	if requestedTokenType != "" && requestedTokenType != tokenTypeAccessToken {
		return nil, ErrRequestedTokenTypeUnsupported
	}
	sub, err := s.exchangeSubject(ctx, clientID, subjectToken)
	if err != nil {
		return nil, err
	}
	// Downscope: at most the subject's scopes, and at most what the caller may hold (its registered
	// scopes and, when it holds the token by the person's consent, those consented to); otherwise
	// exchanging another application's token would hand the caller that application's access.
	held := intersect(strings.Fields(sub.claims.Scope), client.Scopes)
	if sub.consented != nil {
		held = intersect(held, sub.consented)
	}
	granted, ok := downscope(held, scope)
	if !ok {
		return nil, ErrScopeExceedsSubject
	}
	actorSubject, err := s.exchangeActor(actorToken, actorTokenType, sub.callerOrganization)
	if err != nil {
		return nil, err
	}
	return s.issueExchanged(ctx, clientID, sub, actorSubject, strings.Join(granted, " "), resource)
}

// exchangingClient authenticates the caller of a token exchange: a
// confidential client registered for the grant, asking for a resource its
// organization registered.
func (s *Service) exchangingClient(ctx context.Context, clientID, clientSecret, resource string) (authedClient, error) {
	client, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return client, err
	}
	if err := s.requireConfidential(ctx, client); err != nil {
		return client, err
	}
	if err := checkResource(ctx, s.q, client.OrganizationID, resource); err != nil {
		return client, err
	}
	if !containsAny(client.GrantTypes, "token_exchange", grantTypeTokenExchange) {
		return client, ErrGrantTypeNotAllowed
	}
	return client, nil
}

// exchangedSubject is the person whose access token a client exchanges: the
// token's claims, the person, the caller's organization, and the scopes the
// person consented to when the caller holds the token by that consent.
type exchangedSubject struct {
	claims             *tokens.Claims
	userID             uuid.UUID
	callerOrganization uuid.UUID
	consented          []string
}

// exchangeSubject checks the subject token clientID exchanges: a live
// person's access token, of the caller's organization, from a session still
// open, that the caller is entitled to, within the exchange depth.
func (s *Service) exchangeSubject(ctx context.Context, clientID, subjectToken string) (exchangedSubject, error) {
	var sub exchangedSubject
	// Whatever its audience; who may exchange it is decided below.
	claims, err := s.issuer.VerifyAccessAnyAudience(subjectToken)
	if err != nil {
		return sub, ErrSubjectTokenInvalid
	}
	// The subject token must belong to the calling client's organization; otherwise any
	// client could keep renewing an access token stolen from another organization.
	caller, err := s.q.GetClientName(ctx, clientID)
	if err != nil {
		return sub, err
	}
	if claims.OrganizationID != caller.OrganizationID {
		return sub, ErrSubjectTokenInvalid
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return sub, ErrSubjectTokenNoSubject
	}
	// Only a person's access token names them in user_id: an ID token, signed by
	// the same key, carries none and is no credential.
	if claims.UserID != userID {
		return sub, ErrSubjectTokenInvalid
	}
	// The caller must be entitled to the subject's token: issued to it, issued
	// for a resource it serves, or the person delegated to it (consented).
	// Otherwise an application allowed to exchange could mint tokens in the
	// name of anyone whose token passes through it, an administrator's too.
	entitled, consented, err := s.mayExchange(ctx, caller.OrganizationID, clientID, userID, claims)
	if err != nil {
		return sub, err
	}
	if !entitled {
		return sub, ErrSubjectTokenInvalid
	}
	// A suspended or deleted person, or a closed organization, gets nothing.
	live, err := s.activeOrganizationPrincipal(ctx, s.q, userID, claims.OrganizationID)
	if err != nil {
		return sub, err
	}
	if !live {
		return sub, errs.ErrAuthAccountSuspended
	}
	// Nor does the token of a session that has ended.
	sessionLive, err := s.tokenSessionLive(ctx, claims)
	if err != nil {
		return sub, err
	}
	if !sessionLive {
		return sub, ErrSubjectTokenInvalid
	}
	// A chain of exchanges is bounded.
	if claims.ExchangeDepth >= tokenExchangeMaxDepth {
		return sub, ErrExchangeDepthExceeded
	}
	return exchangedSubject{claims: claims, userID: userID, callerOrganization: caller.OrganizationID, consented: consented}, nil
}

// exchangeActor returns the subject of the actor token, "" for none.
// Delegation (RFC 8693): an actor_token names the party acting on the
// subject's behalf (e.g. an AI agent exercising a user's authority). The
// issued token records it in an `act` claim for downstream authz + audit.
func (s *Service) exchangeActor(actorToken, actorTokenType string, callerOrganization uuid.UUID) (string, error) {
	if actorToken == "" {
		return "", nil
	}
	if actorTokenType != "" && actorTokenType != tokenTypeAccessToken {
		return "", ErrActorTokenTypeUnsupported
	}
	actorClaims, aerr := s.issuer.VerifyAccess(actorToken)
	if aerr != nil {
		return "", ErrActorTokenInvalid
	}
	// The delegating actor must also be inside the caller's organization, or the
	// `act` claim could name a principal from another organization.
	if actorClaims.OrganizationID != callerOrganization {
		return "", ErrActorTokenInvalid
	}
	return actorClaims.Subject, nil
}

// issueExchanged issues the exchanged access token to clientID, for scopeStr
// and resource, naming actorSubject, and records the exchange.
func (s *Service) issueExchanged(ctx context.Context, clientID string, sub exchangedSubject, actorSubject, scopeStr, resource string) (*TokenResponse, error) {
	claims, userID := sub.claims, sub.userID
	// A session of its own, linked to the one it came from in the audit
	// record, so the chain doesn't read as one sign-in.
	sid := uuid.New()
	// Never outlive the subject token: exchange can't extend a credential.
	var notAfter time.Time
	if claims.ExpiresAt != nil {
		notAfter = claims.ExpiresAt.Time
	}
	// Issued to the requesting client, which it names: an exchange cannot turn
	// an application token into one the management API accepts.
	access, exp, err := s.issuer.IssueClientAccess(tokens.ClientAccess{
		UserID: userID, OrganizationID: claims.OrganizationID, SessionID: sid, Scopes: scopeStr,
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
		if !slices.Contains(subjectScopes, r) {
			return nil, false
		}
	}
	return requested, true
}

// mayExchange reports whether clientID may exchange a subject token of its
// organization: the token was issued to it, or for a registered resource it serves,
// or the person has consented to it (a delegation it holds), when it also
// returns the scopes consented to (nil otherwise).
func (s *Service) mayExchange(ctx context.Context, organizationID uuid.UUID, clientID string, userID uuid.UUID, claims *tokens.Claims) (bool, []string, error) {
	if ok, err := s.mayIntrospect(ctx, organizationID, clientID, claims); err != nil || ok {
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
		if slices.Contains(b, v) {
			out = append(out, v)
		}
	}
	return out
}

// auditExchange records a token exchange: caller, subject, actor, scopes,
// resource, and the session the subject token came from.
func (s *Service) auditExchange(ctx context.Context, subject *tokens.Claims, clientID string, userID, sid uuid.UUID, actor, scopes, resource string, exp time.Time) error {
	meta := map[string]any{
		"client_id": clientID, "scope": scopes, "resource": resource, "actor": actor,
		"subject_client_id": subject.ClientID, "exchange_depth": subject.ExchangeDepth + 1,
		"session_id": sid, "expires_at": exp,
	}
	if subject.SessionID != uuid.Nil {
		meta["from_session_id"] = subject.SessionID
	}
	caller := audit.Actor{UserID: &userID, Type: "client", IP: httpx.ClientIPFromContext(ctx)}
	return audit.RecordAlone(ctx, s.pool, caller.Event(subject.OrganizationID, "oidc.token_exchanged", "oidc_client", uuid.Nil, meta))
}

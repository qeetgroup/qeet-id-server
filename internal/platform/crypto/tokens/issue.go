package tokens

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
)

// Sign returns a compact JWS of claims signed with the active key, with its kid
// header set. Use it rather than jwt.NewWithClaims so the kid is never missing.
func (i *Issuer) Sign(claims jwt.Claims) (string, error) {
	i.mu.RLock()
	active := i.active
	i.mu.RUnlock()
	if active == nil || active.priv == nil {
		return "", errors.New("no active signing key")
	}
	tok := jwt.NewWithClaims(active.method, claims)
	tok.Header["kid"] = active.kid
	return tok.SignedString(active.priv)
}

// IssueAccess mints a first-party access token for the platform audience and
// returns it with its expiry.
func (i *Issuer) IssueAccess(userID, organizationID, sessionID uuid.UUID, scopes string) (string, time.Time, error) {
	return i.issueAccess(userID, organizationID, sessionID, scopes, nil, "", nil, "", time.Time{}, 0)
}

// IssueAccessActor mints an access token like IssueAccess but with an RFC 8693
// actor (act) claim, marking it a delegated token: the subject's authority is
// being exercised by actorSubject (e.g. an AI agent acting for a user).
func (i *Issuer) IssueAccessActor(userID, organizationID, sessionID uuid.UUID, scopes, actorSubject string) (string, time.Time, error) {
	return i.issueAccess(userID, organizationID, sessionID, scopes, &ActClaim{Subject: actorSubject}, "", nil, "", time.Time{}, 0)
}

// IssueAccessResource mints an access token whose audience is the RFC 8707
// resource alone, so this server's API and every other service refuse it. An
// empty resource behaves like IssueAccess.
func (i *Issuer) IssueAccessResource(userID, organizationID, sessionID uuid.UUID, scopes, resource string) (string, time.Time, error) {
	return i.issueAccess(userID, organizationID, sessionID, scopes, nil, resource, nil, "", time.Time{}, 0)
}

// IssueAccessClaims mints an access token like IssueAccess but with additional
// organization-supplied custom claims (see Claims.Custom), sourced from a post-login
// Auth Hook. A nil/empty map behaves like IssueAccess.
func (i *Issuer) IssueAccessClaims(userID, organizationID, sessionID uuid.UUID, scopes string, custom map[string]any) (string, time.Time, error) {
	return i.issueAccess(userID, organizationID, sessionID, scopes, nil, "", custom, "", time.Time{}, 0)
}

// IssueSessionAccess mints the access token of a first-party session, like
// IssueAccessClaims, but never past sessionEnd: a token issued shortly before
// its session's maximum age ends with the session instead of outliving it.
func (i *Issuer) IssueSessionAccess(userID, organizationID, sessionID uuid.UUID, custom map[string]any, sessionEnd time.Time) (string, time.Time, error) {
	return i.issueAccess(userID, organizationID, sessionID, "", nil, "", custom, "", sessionEnd, 0)
}

// IssueAccessActorResource combines IssueAccessActor and IssueAccessResource: a
// delegated (RFC 8693 act) token whose audience is one RFC 8707 resource, such
// as an agent's token for a single MCP server.
func (i *Issuer) IssueAccessActorResource(userID, organizationID, sessionID uuid.UUID, scopes, actorSubject, resource string) (string, time.Time, error) {
	return i.issueAccess(userID, organizationID, sessionID, scopes, &ActClaim{Subject: actorSubject}, resource, nil, "", time.Time{}, 0)
}

// ClientAccess describes an access token issued to an application on a
// user's behalf (see IssueClientAccess).
type ClientAccess struct {
	UserID, OrganizationID, SessionID uuid.UUID // the token's subject, organization and session
	Scopes                            string    // granted scopes
	ActorSubject                      string    // if set, adds an RFC 8693 act claim
	Resource                          string    // if set, the RFC 8707 resource that is the audience
	ClientID                          string    // the application the token is issued to
	NotAfter                          time.Time // if set, the latest expiry; an exchanged token never outlives its source
	ExchangeDepth                     int       // token exchanges that produced this token (0: none)
}

// IssueClientAccess mints the access token an application receives from the
// authorization server. It carries client_id, so the management API can tell
// it from the user's own tokens and refuse it.
func (i *Issuer) IssueClientAccess(in ClientAccess) (string, time.Time, error) {
	var act *ActClaim
	if in.ActorSubject != "" {
		act = &ActClaim{Subject: in.ActorSubject}
	}
	return i.issueAccess(in.UserID, in.OrganizationID, in.SessionID, in.Scopes, act, in.Resource, nil, in.ClientID, in.NotAfter, in.ExchangeDepth)
}

// MachineAccess describes the access token a machine identity, a service
// principal or an agent, receives for itself (see IssueMachineAccess).
type MachineAccess struct {
	Subject        uuid.UUID     // the service principal or agent, the token's sub
	OrganizationID uuid.UUID     // its organization
	Scopes         []string      // the scopes it holds
	Agent          bool          // an agent: actor_type "agent" with agent_id, else "service"
	TTL            time.Duration // the token's lifetime; zero: AccessTTL
}

// MachineToken is a machine identity's access token: the token, its scopes
// space-separated, when it expires and how long it lasts.
type MachineToken struct {
	AccessToken string
	Scope       string
	ExpiresAt   time.Time
	Lifetime    time.Duration
}

// machineClaims is a machine identity's token payload, which names no user or
// session. The platform audience lets it verify on the API's own path.
type machineClaims struct {
	OrganizationID uuid.UUID `json:"organization_id"`
	Scope          string    `json:"scope,omitempty"`
	ActorType      string    `json:"actor_type"`
	AgentID        string    `json:"agent_id,omitempty"`
	jwt.RegisteredClaims
}

// IssueMachineAccess mints the access token a service principal or an agent
// receives at the client_credentials grant.
func (i *Issuer) IssueMachineAccess(in MachineAccess) (*MachineToken, error) {
	ttl := in.TTL
	if ttl <= 0 {
		ttl = i.accessTTL
	}
	now := time.Now().UTC()
	exp := now.Add(ttl)
	claims := machineClaims{
		OrganizationID: in.OrganizationID,
		Scope:          strings.Join(in.Scopes, " "),
		ActorType:      "service",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuer,
			Audience:  jwt.ClaimStrings{i.audience},
			Subject:   in.Subject.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        uuid.NewString(),
		},
	}
	if in.Agent {
		claims.ActorType, claims.AgentID = "agent", in.Subject.String()
	}
	signed, err := i.Sign(claims)
	if err != nil {
		return nil, fmt.Errorf("sign machine access: %w", err)
	}
	return &MachineToken{AccessToken: signed, Scope: claims.Scope, ExpiresAt: exp, Lifetime: ttl}, nil
}

func (i *Issuer) issueAccess(userID, organizationID, sessionID uuid.UUID, scopes string, act *ActClaim, resource string, custom map[string]any, clientID string, notAfter time.Time, exchangeDepth int) (string, time.Time, error) {
	now := time.Now().UTC()
	exp := now.Add(i.accessTTL)
	if !notAfter.IsZero() && notAfter.Before(exp) {
		exp = notAfter.UTC()
	}
	// RFC 8707: a token issued for a resource is for that resource alone, so
	// the platform API (which requires its own audience) and every other
	// service refuse it.
	aud := jwt.ClaimStrings{i.audience}
	if resource != "" {
		aud = jwt.ClaimStrings{resource}
	}
	claims := Claims{
		UserID:         userID,
		OrganizationID: organizationID,
		SessionID:      sessionID,
		Scope:          scopes,
		Act:            act,
		Custom:         custom,
		ClientID:       clientID,
		// How many exchanges deep the token is, so a chain can be bounded.
		ExchangeDepth: exchangeDepth,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuer,
			Audience:  aud,
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        uuid.NewString(),
		},
	}
	s, err := i.Sign(claims)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign access: %w", err)
	}
	return s, exp, nil
}

// NewRefreshToken returns a new refresh token and its HashRefresh. Only the
// hash is stored.
func NewRefreshToken() (string, string, error) { return codes.URLToken() }

// HashRefresh returns the form a refresh token is stored as (codes.Hash).
func HashRefresh(raw string) string { return codes.Hash(raw) }

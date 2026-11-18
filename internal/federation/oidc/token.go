package oidc

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
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
	// ExpiresAt is when the access token expires, on client_credentials
	// answers only.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func containsAny(set []string, vs ...string) bool {
	for _, v := range vs {
		if slices.Contains(set, v) {
			return true
		}
	}
	return false
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

// idToken is what an ID token is minted from.
type idToken struct {
	UserID, OrganizationID uuid.UUID
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
		"iss":             s.issuer.JWTIssuer(),
		"sub":             in.UserID.String(),
		"aud":             in.Audience,
		"exp":             exp.Unix(),
		"iat":             now.Unix(),
		"organization_id": in.OrganizationID.String(),
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
// its user active, not deleted and a member of its organization (itself
// active), its session, if it is the user's own token, not ended, and its
// agent, if any, active.
func (s *Service) tokenSubjectLive(ctx context.Context, claims *tokens.Claims) (bool, error) {
	if live, err := s.tokenSessionLive(ctx, claims); err != nil || !live {
		return false, err
	}
	if claims.UserID != uuid.Nil {
		if member, err := s.activeOrganizationPrincipal(ctx, s.q, claims.UserID, claims.OrganizationID); err != nil || !member {
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
			SessionID: claims.SessionID, UserID: claims.UserID, OrganizationID: claims.OrganizationID, ClientID: claims.ClientID,
		})
	}
	if s.sessionLive == nil {
		return true, nil
	}
	return s.sessionLive(ctx, claims.SessionID, claims.UserID)
}

// activeOrganizationPrincipal reports whether userID is an active member of the
// active organizationID (its own account, or holding a role there), so may receive a
// token for it: the rule a browser sign-in to an application applies.
func (s *Service) activeOrganizationPrincipal(ctx context.Context, q *dbgen.Queries, userID, organizationID uuid.UUID) (bool, error) {
	return q.IsActiveOrganizationMember(ctx, dbgen.IsActiveOrganizationMemberParams{OrganizationID: organizationID, UserID: userID})
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

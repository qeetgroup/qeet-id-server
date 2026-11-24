package oidc

import (
	"context"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
)

// grantTypeClientCredentials is the RFC 6749 §4.4 grant_type, served to the
// machine identities only.
const grantTypeClientCredentials = "client_credentials"

// MachineClient authenticates one kind of machine identity, service
// principals or agents, at the client_credentials grant and mints its token.
// known is false, with no error, when clientID names none of its kind.
type MachineClient interface {
	ClientCredentials(ctx context.Context, clientID, secret string) (tok *tokens.MachineToken, known bool, err error)
}

// ClientCredentials is the client_credentials grant (RFC 6749 §4.4): a service
// principal or an agent authenticates with its id and secret and receives an
// access token for itself. An application is refused it, as
// unauthorized_client once its own credentials check out.
func (s *Service) ClientCredentials(ctx context.Context, clientID, clientSecret string) (*TokenResponse, error) {
	for _, m := range s.machineClients {
		tok, known, err := m.ClientCredentials(ctx, clientID, clientSecret)
		if err != nil {
			return nil, err
		}
		if known {
			expiresAt := tok.ExpiresAt
			return &TokenResponse{
				AccessToken: tok.AccessToken,
				TokenType:   "Bearer",
				ExpiresIn:   int(tok.Lifetime.Seconds()),
				ExpiresAt:   &expiresAt,
				Scope:       tok.Scope,
			}, nil
		}
	}
	if _, err := s.authenticateClient(ctx, clientID, clientSecret); err != nil {
		return nil, err
	}
	return nil, ErrGrantTypeNotAllowed
}

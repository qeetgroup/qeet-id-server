package oidc

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
)

// TestTokenSessionLive checks that a person's own access token is checked
// against the session it names, and that an ended session or a failed lookup
// makes it not live; an exchanged token, an agent's and one naming no session
// pass. An application's hosted-login session needs the database: logout's tests.
func TestTokenSessionLive(t *testing.T) {
	liveSession, failingSession, lookupErr := uuid.New(), uuid.New(), errors.New("lookup failed")
	s := &Service{sessionLive: func(_ context.Context, sessionID, _ uuid.UUID) (bool, error) {
		switch sessionID {
		case liveSession:
			return true, nil
		case failingSession:
			return false, lookupErr
		}
		return false, nil
	}}
	user := uuid.New()
	cases := map[string]struct {
		claims  tokens.Claims
		want    bool
		wantErr error
	}{
		"own token, live session":                  {tokens.Claims{UserID: user, SessionID: liveSession}, true, nil},
		"own token, ended session":                 {tokens.Claims{UserID: user, SessionID: uuid.New()}, false, nil},
		"own token, failed lookup":                 {tokens.Claims{UserID: user, SessionID: failingSession}, false, lookupErr},
		"an exchanged token":                       {tokens.Claims{UserID: user, SessionID: uuid.New(), ClientID: "app", ExchangeDepth: 1}, true, nil},
		"an application's token naming no session": {tokens.Claims{UserID: user, ClientID: "app"}, true, nil},
		"an agent's token":                         {tokens.Claims{UserID: user, SessionID: uuid.New(), ActorType: "agent"}, true, nil},
		"a token with no session":                  {tokens.Claims{UserID: user}, true, nil},
	}
	for name, tc := range cases {
		live, err := s.tokenSessionLive(context.Background(), &tc.claims)
		if live != tc.want || !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: live %v, %v; want %v, %v", name, live, err, tc.want, tc.wantErr)
		}
	}
}

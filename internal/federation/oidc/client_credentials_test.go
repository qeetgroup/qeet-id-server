package oidc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/tokens"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// fakeMachine is a MachineClient knowing one id, which counts how often it is
// asked.
type fakeMachine struct {
	id    string
	tok   *tokens.MachineToken
	err   error
	asked *int
}

func (m fakeMachine) ClientCredentials(_ context.Context, clientID, _ string) (*tokens.MachineToken, bool, error) {
	*m.asked++
	if clientID != m.id {
		return nil, false, nil
	}
	return m.tok, true, m.err
}

// TestClientCredentialsAsksEachMachineKindInTurn checks that the
// client_credentials grant answers with the token of the first kind of
// machine identity that knows the id, asking the next only when one doesn't,
// and stops at a refusal. An id no kind knows needs the database: the token
// endpoint's tests in bootstrap.
func TestClientCredentialsAsksEachMachineKindInTurn(t *testing.T) {
	expires := time.Now().Add(10 * time.Minute).UTC()
	principalToken := &tokens.MachineToken{AccessToken: "principal-token", Scope: "users:read", ExpiresAt: expires, Lifetime: 15 * time.Minute}
	agentToken := &tokens.MachineToken{AccessToken: "agent-token", ExpiresAt: expires, Lifetime: 10 * time.Minute}
	for _, tc := range []struct {
		name                  string
		clientID              string
		principalErr          error
		want                  *TokenResponse
		wantErr               error
		principalAsked, agent int
	}{
		{"a service principal", "p", nil, &TokenResponse{AccessToken: "principal-token", TokenType: "Bearer", ExpiresIn: 900, ExpiresAt: &expires, Scope: "users:read"}, nil, 1, 0},
		{"an agent", "a", nil, &TokenResponse{AccessToken: "agent-token", TokenType: "Bearer", ExpiresIn: 600, ExpiresAt: &expires}, nil, 1, 1},
		{"a refused service principal", "p", errs.ErrPrincipalDisabled, nil, errs.ErrPrincipalDisabled, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var principalAsked, agentAsked int
			svc := &Service{}
			svc.SetMachineClients(
				fakeMachine{id: "p", tok: principalToken, err: tc.principalErr, asked: &principalAsked},
				fakeMachine{id: "a", tok: agentToken, asked: &agentAsked},
			)
			got, err := svc.ClientCredentials(context.Background(), tc.clientID, "secret")
			if !errors.Is(err, tc.wantErr) || (tc.want == nil) != (got == nil) {
				t.Fatalf("got %+v, %v; want %+v, %v", got, err, tc.want, tc.wantErr)
			}
			if tc.want != nil {
				if got.ExpiresAt == nil || !got.ExpiresAt.Equal(*tc.want.ExpiresAt) {
					t.Errorf("expires_at %v, want %v", got.ExpiresAt, tc.want.ExpiresAt)
				}
				got.ExpiresAt = tc.want.ExpiresAt
				if *got != *tc.want {
					t.Errorf("token %+v, want %+v", got, tc.want)
				}
			}
			if principalAsked != tc.principalAsked || agentAsked != tc.agent {
				t.Errorf("asked the principals %d and the agents %d times, want %d and %d", principalAsked, agentAsked, tc.principalAsked, tc.agent)
			}
		})
	}
}

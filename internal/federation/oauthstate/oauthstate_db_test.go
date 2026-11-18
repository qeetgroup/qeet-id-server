//go:build integration

package oauthstate

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

func TestMain(m *testing.M) { dbtest.Main(m) }

var (
	errInvalid = errors.New("invalid")
	errExpired = errors.New("expired")
	refusals   = Refusals{Invalid: errInvalid, Expired: errExpired}
)

// TestAStateIsTakenOnce checks, for every kind, that a state gives back what
// its sign-in kept exactly once, only as its own kind, and not once it has
// expired; and that a connection's state can't be spent by another
// connection's callback.
func TestAStateIsTakenOnce(t *testing.T) {
	ctx := dbtest.Context(t)
	pool := dbtest.Pool(t)
	organization := dbtest.Organization(t)
	linker := dbtest.User(t, organization, organization).ID
	connection := uuid.New()
	for _, st := range []State{
		{Kind: KindOIDCConnection, OrganizationID: organization, ConnectionID: connection, CodeVerifier: "v", NonceHash: "n", RedirectURI: "https://id.example.test/cb", ReturnTo: "/oauth/authorize"},
		{Kind: KindSocial, OrganizationID: organization, Provider: "okta", CodeVerifier: "v", NonceHash: "n", RedirectURI: "https://id.example.test/cb"},
		{Kind: KindPlatformSocial, Provider: "github", RedirectURI: "https://id.example.test/cb", LinkUserID: linker, AllowCreate: true},
	} {
		t.Run(st.Kind, func(t *testing.T) {
			raw, err := Save(ctx, pool, st, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			other := KindSocial
			if st.Kind == KindSocial {
				other = KindPlatformSocial
			}
			if _, err := Take(ctx, pool, other, raw, uuid.Nil, refusals); !errors.Is(err, errInvalid) {
				t.Errorf("the state as a %s state: %v, want invalid", other, err)
			}
			if st.ConnectionID != uuid.Nil {
				if _, err := Take(ctx, pool, st.Kind, raw, uuid.New(), refusals); !errors.Is(err, errInvalid) {
					t.Errorf("the state at another connection's callback: %v, want invalid", err)
				}
			}
			got, err := Take(ctx, pool, st.Kind, raw, st.ConnectionID, refusals)
			if err != nil {
				t.Fatal(err)
			}
			got.ExpiresAt = time.Time{}
			if got != st {
				t.Errorf("state %+v, want %+v", got, st)
			}
			if _, err := Take(ctx, pool, st.Kind, raw, st.ConnectionID, refusals); !errors.Is(err, errInvalid) {
				t.Errorf("the state again: %v, want invalid", err)
			}
			stale, err := Save(ctx, pool, st, -time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Take(ctx, pool, st.Kind, stale, st.ConnectionID, refusals); !errors.Is(err, errExpired) {
				t.Errorf("an expired state: %v, want expired", err)
			}
			if _, err := Take(ctx, pool, st.Kind, stale, st.ConnectionID, refusals); !errors.Is(err, errInvalid) {
				t.Errorf("an expired state again: %v, want it spent", err)
			}
			if _, err := Take(ctx, pool, st.Kind, "", st.ConnectionID, refusals); !errors.Is(err, errInvalid) {
				t.Errorf("no state: %v, want invalid", err)
			}
		})
	}
}

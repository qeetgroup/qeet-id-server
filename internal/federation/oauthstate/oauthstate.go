// Package oauthstate keeps what a begun OAuth 2.0 or OpenID Connect sign-in
// needs at its callback (OpenID Connect single sign-on, an organization's
// social providers, the console's own social sign-in), under the hash of the
// random state it sends the provider. A state is spent as it is read.
package oauthstate

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oauthstate/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/strutil"
)

// The sign-ins a state belongs to, as auth.oauth_states records them.
const (
	KindOIDCConnection = "oidc_connection" // an organization's OpenID Connect connection
	KindSocial         = "social"          // an organization's social provider
	KindPlatformSocial = "platform_social" // the console's own social sign-in
)

// State is what a sign-in keeps for its callback. OrganizationID is uuid.Nil
// for the console's own sign-in; ConnectionID names an OpenID Connect
// connection, Provider a social provider. CodeVerifier is the PKCE verifier
// and NonceHash the hash of the nonce sent ("" for none). ReturnTo is where a
// hosted sign-in goes back to, LinkUserID the account a link ceremony attaches
// the identity to, and AllowCreate lets a console sign-up create an account.
type State struct {
	Kind           string
	OrganizationID uuid.UUID
	ConnectionID   uuid.UUID
	Provider       string
	CodeVerifier   string
	NonceHash      string
	RedirectURI    string
	ReturnTo       string
	LinkUserID     uuid.UUID
	AllowCreate    bool
	ExpiresAt      time.Time
}

// Save stores s, valid for ttl, under a new random state, which it returns.
func Save(ctx context.Context, db dbgen.DBTX, s State, ttl time.Duration) (string, error) {
	raw, hash, err := codes.URLToken()
	if err != nil {
		return "", err
	}
	if err := dbgen.New(db).InsertState(ctx, dbgen.InsertStateParams{
		StateHash:      hash,
		Kind:           s.Kind,
		OrganizationID: postgres.NullIfZero(s.OrganizationID),
		ConnectionID:   postgres.NullIfZero(s.ConnectionID),
		Provider:       strutil.NilIfEmpty(s.Provider),
		CodeVerifier:   s.CodeVerifier,
		NonceHash:      strutil.NilIfEmpty(s.NonceHash),
		RedirectUri:    s.RedirectURI,
		ReturnTo:       strutil.NilIfEmpty(s.ReturnTo),
		LinkUserID:     postgres.NullIfZero(s.LinkUserID),
		AllowCreate:    s.AllowCreate,
		ExpiresAt:      time.Now().UTC().Add(ttl),
	}); err != nil {
		return "", err
	}
	return raw, nil
}

// Refusals are a flow's errors for a state it doesn't take.
type Refusals struct {
	Invalid error // no state of the kind (and connection)
	Expired error
}

// Take spends the state raw of kind, of connectionID unless that is uuid.Nil,
// and returns what it kept. One that has expired is spent and refused.
func Take(ctx context.Context, db dbgen.DBTX, kind, raw string, connectionID uuid.UUID, r Refusals) (State, error) {
	if raw == "" {
		return State{}, refused(r.Invalid)
	}
	row, err := dbgen.New(db).TakeState(ctx, dbgen.TakeStateParams{StateHash: codes.Hash(raw), Kind: kind, ConnectionID: postgres.NullIfZero(connectionID)})
	if errors.Is(err, pgx.ErrNoRows) {
		return State{}, refused(r.Invalid)
	}
	if err != nil {
		return State{}, err
	}
	if !time.Now().Before(row.ExpiresAt) {
		return State{}, refused(r.Expired)
	}
	return State{
		Kind:           kind,
		OrganizationID: postgres.ZeroIfNull(row.OrganizationID),
		ConnectionID:   postgres.ZeroIfNull(row.ConnectionID),
		Provider:       strutil.Deref(row.Provider),
		CodeVerifier:   row.CodeVerifier,
		NonceHash:      strutil.Deref(row.NonceHash),
		RedirectURI:    row.RedirectUri,
		ReturnTo:       strutil.Deref(row.ReturnTo),
		LinkUserID:     postgres.ZeroIfNull(row.LinkUserID),
		AllowCreate:    row.AllowCreate,
		ExpiresAt:      row.ExpiresAt,
	}, nil
}

// errRefused refuses a state for a reason the flow names no error for.
var errRefused = errors.New("oauthstate: state refused")

// refused returns err, or errRefused when the flow names none, so a missing
// refusal never lets a state through.
func refused(err error) error {
	if err == nil {
		return errRefused
	}
	return err
}

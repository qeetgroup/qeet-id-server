// Package logincode keeps the one-time codes a federated sign-in's callback (SAML, OIDC single
// sign-on, social) hands the browser, which the console or hosted login trades once for a session.
// Every flow spends them through Consume, which also refuses a code once the connection or provider
// that issued it no longer signs anyone in.
package logincode

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/federation/logincode/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/crypto/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/strutil"
)

// The sign-ins a code hands over, as auth.login_codes records them.
const (
	KindSAML           = "saml"            // an organization's SAML connection
	KindOIDCConnection = "oidc_connection" // an organization's OpenID Connect connection
	KindSocial         = "social"          // an organization's social provider
	KindPlatformSocial = "platform_social" // the console's own social sign-in
)

// Code is whom a code signs in and what issued it: a connection or a social
// provider of OrganizationID, or neither for the console's own sign-in, whose
// OrganizationID is uuid.Nil.
type Code struct {
	Kind           string
	UserID         uuid.UUID
	OrganizationID uuid.UUID
	ConnectionID   uuid.UUID
	Provider       string
}

// Issue stores a new code for c, valid for ttl, and returns it.
func Issue(ctx context.Context, db dbgen.DBTX, c Code, ttl time.Duration) (string, error) {
	raw, hash, err := codes.URLToken()
	if err != nil {
		return "", err
	}
	if err := dbgen.New(db).InsertLoginCode(ctx, dbgen.InsertLoginCodeParams{
		CodeHash:       hash,
		Kind:           c.Kind,
		UserID:         c.UserID,
		OrganizationID: postgres.NullIfZero(c.OrganizationID),
		ConnectionID:   postgres.NullIfZero(c.ConnectionID),
		Provider:       strutil.NilIfEmpty(c.Provider),
		ExpiresAt:      time.Now().UTC().Add(ttl),
	}); err != nil {
		return "", err
	}
	return raw, nil
}

// Refusals are a flow's errors for a code it doesn't take.
type Refusals struct {
	Required error // no code was given
	Invalid  error // no code of the kind, or what issued it was deleted
	Used     error
	Expired  error
	Draft    error // its connection was put back to draft
	Disabled error // its connection was turned off, or its provider switched off
}

// Consume spends the code raw of kind and returns whom it signs in. It is
// spent once, atomically, whether or not it is then refused: when it has
// expired, or its connection or provider has since been turned off.
func Consume(ctx context.Context, pool *pgxpool.Pool, kind, raw string, r Refusals) (Code, error) {
	if raw == "" {
		return Code{}, refused(r.Required)
	}
	hash := codes.Hash(raw)
	tx, err := pool.Begin(ctx)
	if err != nil {
		return Code{}, err
	}
	defer tx.Rollback(ctx)
	q := dbgen.New(tx)
	row, err := q.ClaimLoginCode(ctx, dbgen.ClaimLoginCodeParams{CodeHash: hash, Kind: kind})
	if errors.Is(err, pgx.ErrNoRows) {
		return Code{}, refused(r.Invalid)
	}
	if err != nil {
		return Code{}, err
	}
	if row.UsedAt != nil {
		return Code{}, refused(r.Used)
	}
	if err := q.SpendLoginCode(ctx, dbgen.SpendLoginCodeParams{CodeHash: hash, OrganizationID: row.OrganizationID}); err != nil {
		return Code{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Code{}, err
	}
	switch {
	case !time.Now().Before(row.ExpiresAt):
		return Code{}, refused(r.Expired)
	case row.IssuerStatus == "deleted":
		return Code{}, refused(r.Invalid)
	case row.IssuerStatus == "draft":
		return Code{}, refused(r.Draft)
	case row.IssuerStatus != "active":
		return Code{}, refused(r.Disabled)
	}
	return Code{
		Kind:           kind,
		UserID:         row.UserID,
		OrganizationID: postgres.ZeroIfNull(row.OrganizationID),
		ConnectionID:   postgres.ZeroIfNull(row.ConnectionID),
		Provider:       strutil.Deref(row.Provider),
	}, nil
}

// errRefused refuses a code for a reason the flow names no error for.
var errRefused = errors.New("logincode: code refused")

// refused returns err, or errRefused when the flow names none, so a missing
// refusal never lets a code through.
func refused(err error) error {
	if err == nil {
		return errRefused
	}
	return err
}

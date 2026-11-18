package user

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// signInEnder ends, inside tx, every way a user is signed in and reports how
// many of each it ended. An interface because the authentication package
// imports this one.
type signInEnder interface {
	EndAllSignIns(ctx context.Context, tx pgx.Tx, userID uuid.UUID, reason string) (SignInsEnded, error)
}

// SignInsEnded counts, by kind, what ending every way a person is signed in
// ended.
type SignInsEnded struct {
	Sessions              int64 // API and console sessions, with their refresh tokens
	LoginSessions         int64 // hosted-login browser sessions
	AppGrants             int64 // applications' refresh grants
	TrustedDevices        int64 // devices remembered to skip the second factor
	PendingAuthorizations int64 // unredeemed codes and uncollected device or CIBA requests
}

// Total is the number of sessions, login sessions and app grants ended.
func (e SignInsEnded) Total() int64 { return e.Sessions + e.LoginSessions + e.AppGrants }

// endEverySignIn ends, inside tx, every way userID is signed in: sessions,
// hosted-login sessions, application grants, trusted devices and pending
// authorizations, so none of them works again if the account comes back.
func (a accounts) endEverySignIn(ctx context.Context, tx pgx.Tx, userID uuid.UUID, reason string) error {
	_, err := a.signIns.EndAllSignIns(ctx, tx, userID, reason)
	return err
}

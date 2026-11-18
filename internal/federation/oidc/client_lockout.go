package oidc

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/oidc/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// ClientLockout is how many wrong secrets a confidential application may
// present from one source network within Window, on every endpoint that takes
// one together, before that network is refused for Duration. A client_id is
// public, so a lockout of the application everywhere would let anyone shut it
// off for all its users.
type ClientLockout struct {
	Threshold int
	Window    time.Duration
	Duration  time.Duration
}

// DefaultClientLockout is ten wrong secrets in 15 minutes, then 15 minutes out.
func DefaultClientLockout() ClientLockout {
	return ClientLockout{Threshold: 10, Window: 15 * time.Minute, Duration: 15 * time.Minute}
}

// SetClientLockout sets the application secret lockout.
func (s *Service) SetClientLockout(l ClientLockout) { s.lockout = l }

// clientLocked reports whether a lockout is in force for the application from
// the caller's source network. A failure to read it is returned, so
// authentication fails closed.
func (s *Service) clientLocked(ctx context.Context, rowID uuid.UUID) (bool, error) {
	_, err := s.q.GetClientLockedUntil(ctx, dbgen.GetClientLockedUntilParams{ClientRowID: rowID, SourceNetwork: callerNetwork(ctx)})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// callerNetwork is the source network of the request in ctx (httpx.SourceNetwork
// of its client address; "" when unknown), the unit a lockout refuses.
func callerNetwork(ctx context.Context) string {
	return httpx.SourceNetwork(httpx.ClientIPFromContext(ctx))
}

// clientAuthFailed counts a wrong secret against the application from the
// caller's source network and records it (the application and the caller's
// address, never the secret). Crossing the threshold starts a lockout of that
// network, recorded and announced as oidc.client_locked_out, once per lockout.
func (s *Service) clientAuthFailed(ctx context.Context, c authedClient) {
	s.auditClientAuthFailure(ctx, c, "invalid_secret")
	l := s.lockout
	network := callerNetwork(ctx)
	failures, err := s.q.RecordClientAuthFailure(ctx, dbgen.RecordClientAuthFailureParams{
		ClientRowID: c.ID, SourceNetwork: network, WindowSeconds: l.Window.Seconds(),
	})
	if err != nil {
		slog.Warn("oidc: count application auth failure", "client_id", c.ClientID, "err", err)
		return
	}
	if int(failures) < l.Threshold {
		return
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return
	}
	defer tx.Rollback(ctx)
	until, err := s.q.WithTx(tx).LockClient(ctx, dbgen.LockClientParams{
		ClientRowID: c.ID, SourceNetwork: network, DurationSeconds: l.Duration.Seconds(),
	})
	if err != nil { // pgx.ErrNoRows: another attempt started this lockout
		return
	}
	if err := audit.Record(ctx, tx, audit.Actor{Type: "system", IP: httpx.ClientIPFromContext(ctx)}.Event(c.OrganizationID, "oidc.client_locked_out", "oidc_client", c.ID,
		map[string]any{"client_id": c.ClientID, "failures": failures, "locked_until": postgres.ZeroIfNull(until), "source_network": network})); err != nil {
		return
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: c.ID, Topic: "oidc", EventType: "oidc.client_locked_out",
		Payload: map[string]any{
			"organization_id": c.OrganizationID, "client_id": c.ClientID, "failures": failures, "locked_until": postgres.ZeroIfNull(until),
			"source_network": network,
		},
	}); err != nil {
		return
	}
	_ = tx.Commit(ctx)
}

// ClientAuthFailures is an application's lockout and its recent wrong
// secrets, for its admin page. LockedUntil is when the last lockout in force,
// of any source network, ends.
type ClientAuthFailures struct {
	LockedUntil *time.Time          `json:"locked_until"`
	Items       []ClientAuthFailure `json:"items"`
}

// ClientAuthFailure is one recorded wrong secret: when, and from which
// address. No secret material is ever recorded.
type ClientAuthFailure struct {
	At     time.Time `json:"at"`
	IP     string    `json:"ip"`
	Reason string    `json:"reason"`
}

// RecentClientAuthFailures returns when the lockouts in force for an organization's
// application end (nil: none) and its last 20 failed authentications.
func (s *Service) RecentClientAuthFailures(ctx context.Context, organizationID, id uuid.UUID) (*ClientAuthFailures, error) {
	if _, err := s.GetClient(ctx, organizationID, id); err != nil {
		return nil, err
	}
	out := &ClientAuthFailures{Items: []ClientAuthFailure{}}
	if until, err := s.q.GetClientLatestLockout(ctx, id); err == nil {
		out.LockedUntil = &until
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	rows, err := s.q.ListClientAuthFailures(ctx, dbgen.ListClientAuthFailuresParams{
		OrganizationID: postgres.NullIfZero(organizationID), ClientRowID: postgres.NullIfZero(id), MaxRows: 20,
	})
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out.Items = append(out.Items, ClientAuthFailure{At: r.CreatedAt, IP: r.Ip, Reason: r.Reason})
	}
	return out, nil
}

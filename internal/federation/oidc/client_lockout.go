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
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// ClientLockout is how many wrong secrets a confidential application may
// present within Window, on every endpoint that takes one together, before it
// is refused for Duration (config CLIENT_AUTH_LOCKOUT_*).
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

// clientLocked reports whether a lockout is in force for the application. A
// failure to read it is returned, so authentication fails closed.
func (s *Service) clientLocked(ctx context.Context, rowID uuid.UUID) (bool, error) {
	_, err := s.q.GetClientLockedUntil(ctx, rowID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// clientAuthFailed counts a wrong secret against the application and records
// it (the application and the caller's address, never the secret). Crossing
// the threshold starts a lockout, recorded and announced as
// oidc.client_locked_out, once per lockout.
func (s *Service) clientAuthFailed(ctx context.Context, c authedClient) {
	s.auditClientAuthFailure(ctx, c, "invalid_secret")
	l := s.lockout
	failures, err := s.q.RecordClientAuthFailure(ctx, dbgen.RecordClientAuthFailureParams{
		ClientRowID: c.ID, WindowSeconds: l.Window.Seconds(),
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
		ClientRowID: c.ID, DurationSeconds: l.Duration.Seconds(),
	})
	if err != nil { // pgx.ErrNoRows: another attempt started this lockout
		return
	}
	tenantID, id := c.TenantID, c.ID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID: &tenantID, ActorType: "system", Action: "oidc.client_locked_out",
		ResourceType: "oidc_client", ResourceID: &id, IP: httpx.ClientIPFromContext(ctx),
		Metadata: map[string]any{"client_id": c.ClientID, "failures": failures, "locked_until": until.Time},
	}); err != nil {
		return
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: c.ID, Topic: "oidc", EventType: "oidc.client_locked_out",
		Payload: map[string]any{
			"tenant_id": c.TenantID, "client_id": c.ClientID, "failures": failures, "locked_until": until.Time,
		},
	}); err != nil {
		return
	}
	_ = tx.Commit(ctx)
}

// ClientAuthFailures is an application's lockout and its recent wrong
// secrets, for its admin page.
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

// RecentClientAuthFailures returns the lockout in force for a tenant's
// application (nil: none) and its last 20 failed authentications.
func (s *Service) RecentClientAuthFailures(ctx context.Context, tenantID, id uuid.UUID) (*ClientAuthFailures, error) {
	if _, err := s.GetClient(ctx, tenantID, id); err != nil {
		return nil, err
	}
	out := &ClientAuthFailures{Items: []ClientAuthFailure{}}
	if until, err := s.q.GetClientLockedUntil(ctx, id); err == nil {
		out.LockedUntil = timePtr(until)
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	rows, err := s.q.ListClientAuthFailures(ctx, dbgen.ListClientAuthFailuresParams{
		TenantID: optionalUUID(tenantID), ClientRowID: optionalUUID(id), MaxRows: 20,
	})
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		out.Items = append(out.Items, ClientAuthFailure{At: r.CreatedAt, IP: r.Ip, Reason: r.Reason})
	}
	return out, nil
}

package siem

import (
	"context"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/siem/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// Create registers a sink with its token encrypted, recording it in
// the audit log and the outbox. The sink streams from now, so it never receives
// the existing audit history.
func (s *Service) Create(ctx context.Context, organizationID uuid.UUID, typ, endpoint, token string, actor audit.Actor) (*Sink, error) {
	if !validType(typ) {
		return nil, ErrSinkTypeInvalid
	}
	if _, err := s.egress.ValidateHTTPURL(endpoint); err != nil {
		return nil, ErrEndpointInvalid
	}
	id := uuid.New()
	ciphertext, nonce, err := s.box.Seal(organizationID, "siem-token", id.String(), []byte(token))
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	row, err := s.q.WithTx(tx).InsertLogSink(ctx, dbgen.InsertLogSinkParams{
		ID: id, OrganizationID: organizationID, Type: typ, Endpoint: endpoint, TokenCt: ciphertext, TokenNonce: nonce,
	})
	if err != nil {
		return nil, err
	}
	sk := &Sink{
		ID: row.ID, Type: row.Type, Endpoint: row.Endpoint, Enabled: row.Enabled,
		LastForwardedAt: row.LastForwardedAt, LastError: row.LastError, CreatedAt: row.CreatedAt,
	}
	metadata := map[string]any{"type": sk.Type, "endpoint": sk.Endpoint}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "siem.sink_created", "log_sink", sk.ID, metadata)); err != nil {
		return nil, err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: sk.ID, Topic: "siem.events", EventType: "siem.sink_created",
		Payload: map[string]any{"sink_id": sk.ID, "organization_id": organizationID, "type": sk.Type, "endpoint": sk.Endpoint},
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return sk, nil
}

// List returns the organization's sinks.
func (s *Service) List(ctx context.Context, organizationID uuid.UUID) ([]Sink, error) {
	rows, err := s.q.ListLogSinks(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]Sink, 0, len(rows))
	for _, r := range rows {
		sk := Sink{
			ID: r.ID, Type: r.Type, Endpoint: r.Endpoint,
			Enabled: r.Enabled, LastError: r.LastError, CreatedAt: r.CreatedAt,
		}
		sk.LastForwardedAt = r.LastForwardedAt
		out = append(out, sk)
	}
	return out, nil
}

// SetEnabled enables or disables one of the organization's sinks. It returns
// errs.ErrNotFound if there is no such sink.
func (s *Service) SetEnabled(ctx context.Context, id, organizationID uuid.UUID, enabled bool, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).SetLogSinkEnabled(ctx, dbgen.SetLogSinkEnabledParams{
		Enabled: enabled, ID: id, OrganizationID: organizationID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	metadata := map[string]any{"enabled": enabled}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "siem.sink_updated", "log_sink", id, metadata)); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: id, Topic: "siem.events", EventType: "siem.sink_updated", Payload: map[string]any{"sink_id": id, "organization_id": organizationID, "enabled": enabled}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Delete deletes one of the organization's sinks. It returns
// errs.ErrNotFound if there is no such sink.
func (s *Service) Delete(ctx context.Context, id, organizationID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).DeleteLogSink(ctx, dbgen.DeleteLogSinkParams{
		ID: id, OrganizationID: organizationID,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	if err := audit.Record(ctx, tx, actor.Event(organizationID, "siem.sink_deleted", "log_sink", id, nil)); err != nil {
		return err
	}
	if err := outbox.Enqueue(ctx, tx, outbox.Event{AggregateID: id, Topic: "siem.events", EventType: "siem.sink_deleted", Payload: map[string]any{"sink_id": id, "organization_id": organizationID}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

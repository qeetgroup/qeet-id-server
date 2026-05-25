// Package audit records actor-visible mutations to audit.events. Every
// write happens inside the caller's pgx.Tx so the audit row is committed
// atomically with the business write.
package audit

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Event struct {
	TenantID     *uuid.UUID
	ActorUserID  *uuid.UUID
	ActorType    string
	Action       string
	ResourceType string
	ResourceID   *uuid.UUID
	IP           string
	UserAgent    string
	RequestID    string
	Metadata     map[string]any
}

// Record writes one audit row inside the given transaction.
func Record(ctx context.Context, tx pgx.Tx, e Event) error {
	if e.ActorType == "" {
		e.ActorType = "user"
	}
	meta, err := json.Marshal(e.Metadata)
	if err != nil {
		return err
	}
	if len(meta) == 0 || string(meta) == "null" {
		meta = []byte("{}")
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO audit.events (
			tenant_id, actor_user_id, actor_type, action,
			resource_type, resource_id, ip, user_agent, request_id, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7,'')::inet, $8, $9, $10)
	`,
		e.TenantID, e.ActorUserID, e.ActorType, e.Action,
		e.ResourceType, e.ResourceID, e.IP, e.UserAgent, e.RequestID, meta,
	)
	return err
}

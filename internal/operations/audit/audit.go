// Package audit records mutations to audit.events inside the caller's
// transaction, so each row commits with the change it describes. Each row's
// SHA-256 hash chains to the previous row of its tenant: deleting, editing or
// reordering a row breaks the chain, which Verifier detects.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/audit/dbgen"
)

// chainSeed is the prev_hash of the first row of a chain.
const chainSeed = "0000000000000000000000000000000000000000000000000000000000000000"

// Event is an audit row to record. A nil TenantID puts it on the platform
// chain, and an empty ActorType means "user".
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

// Actor is the request's provenance (who and from where) that a service
// attaches to the audit rows it writes.
type Actor struct {
	UserID    *uuid.UUID
	Type      string
	IP        string
	UserAgent string
	RequestID string
}

// Event returns an audit Event of a tenant-scoped action by a.
func (a Actor) Event(tenantID uuid.UUID, action, resourceType string, resourceID uuid.UUID, metadata map[string]any) Event {
	e := a.PlatformEvent(action, resourceType, resourceID, metadata)
	tid := tenantID
	e.TenantID = &tid
	return e
}

// PlatformEvent returns an audit Event on the platform chain, not scoped to a
// tenant.
func (a Actor) PlatformEvent(action, resourceType string, resourceID uuid.UUID, metadata map[string]any) Event {
	rid := resourceID
	return Event{
		ActorUserID:  a.UserID,
		ActorType:    a.Type,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   &rid,
		IP:           a.IP,
		UserAgent:    a.UserAgent,
		RequestID:    a.RequestID,
		Metadata:     metadata,
	}
}

// canonicalRow is the serialisation each row's hash covers; its field order is
// fixed by this declaration. Changing it breaks every existing chain, so add a
// chain-version column first.
type canonicalRow struct {
	ID           string          `json:"id"`
	TenantID     string          `json:"tenant_id"`
	ActorUserID  string          `json:"actor_user_id"`
	ActorType    string          `json:"actor_type"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	IP           string          `json:"ip"`
	UserAgent    string          `json:"user_agent"`
	RequestID    string          `json:"request_id"`
	Metadata     json.RawMessage `json:"metadata"`
	CreatedAt    string          `json:"created_at"`
	PrevHash     string          `json:"prev_hash"`
}

func canonicalize(e Event, id uuid.UUID, createdAt time.Time, metaJSON []byte, prevHash string) ([]byte, error) {
	return json.Marshal(canonicalRow{
		ID:           id.String(),
		TenantID:     uuidStr(e.TenantID),
		ActorUserID:  uuidStr(e.ActorUserID),
		ActorType:    e.ActorType,
		Action:       e.Action,
		ResourceType: e.ResourceType,
		ResourceID:   uuidStr(e.ResourceID),
		IP:           e.IP,
		UserAgent:    e.UserAgent,
		RequestID:    e.RequestID,
		Metadata:     metaJSON,
		CreatedAt:    createdAt.UTC().Format(time.RFC3339Nano),
		PrevHash:     prevHash,
	})
}

func hashHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func uuidStr(u *uuid.UUID) string {
	if u == nil {
		return ""
	}
	return u.String()
}

// pgUUIDNullable converts id to a nullable pgtype.UUID; nil becomes NULL.
func pgUUIDNullable(id *uuid.UUID) pgtype.UUID {
	if id == nil {
		return pgtype.UUID{Valid: false}
	}
	return pgtype.UUID{Bytes: *id, Valid: true}
}

// strRef returns a pointer to s, so an empty string is stored as "" rather than
// NULL.
func strRef(s string) *string { return &s }

// Record writes one audit row in tx, as the next link of its tenant's hash
// chain. A per-tenant advisory lock serialises concurrent writers until tx
// ends.
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

	lockKey := "audit:"
	if e.TenantID != nil {
		lockKey += e.TenantID.String()
	} else {
		lockKey += "platform"
	}
	// Raw SQL: pg_advisory_xact_lock returns void, which sqlc cannot model.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		return err
	}

	q := dbgen.New(tx)

	prevHash := chainSeed
	tip, err := q.GetAuditChainTip(ctx, pgUUIDNullable(e.TenantID))
	switch {
	case err == nil:
		prevHash = strings.TrimSpace(*tip)
	case errors.Is(err, pgx.ErrNoRows):
		// First row in chain; keep the seed.
	default:
		return err
	}

	id := uuid.New()
	createdAt := time.Now().UTC().Truncate(time.Microsecond)
	canonical, err := canonicalize(e, id, createdAt, meta, prevHash)
	if err != nil {
		return err
	}
	rowHash := hashHex(canonical)

	return q.InsertAuditEvent(ctx, dbgen.InsertAuditEventParams{
		ID:           id,
		TenantID:     pgUUIDNullable(e.TenantID),
		ActorUserID:  pgUUIDNullable(e.ActorUserID),
		ActorType:    e.ActorType,
		Action:       e.Action,
		ResourceType: e.ResourceType,
		ResourceID:   pgUUIDNullable(e.ResourceID),
		Ip:           e.IP, // NULLIF($8,'')::inet in the SQL handles empty→NULL
		UserAgent:    strRef(e.UserAgent),
		RequestID:    strRef(e.RequestID),
		Metadata:     meta,
		CreatedAt:    createdAt,
		PrevHash:     strRef(prevHash),
		RowHash:      strRef(rowHash),
	})
}

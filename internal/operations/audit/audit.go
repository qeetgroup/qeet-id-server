// Package audit records actor-visible mutations to audit.events. Each write
// happens inside the caller's pgx.Tx, so the row commits atomically with the
// business write. Every row carries a SHA-256 hash chaining to the previous row
// in the same tenant; tampering (delete, edit, reorder) breaks the chain and is
// caught by Verifier.Verify.
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

const chainSeed = "0000000000000000000000000000000000000000000000000000000000000000"

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

// Actor is the request-scoped provenance (who/where) a service attaches to the
// audit rows it writes, so handlers can hand it off without building Events.
type Actor struct {
	UserID    *uuid.UUID
	Type      string
	IP        string
	UserAgent string
	RequestID string
}

// Event builds an audit Event for a tenant-scoped action from this actor.
func (a Actor) Event(tenantID uuid.UUID, action, resourceType string, resourceID uuid.UUID, metadata map[string]any) Event {
	e := a.PlatformEvent(action, resourceType, resourceID, metadata)
	tid := tenantID
	e.TenantID = &tid
	return e
}

// PlatformEvent builds an audit Event not scoped to any tenant (platform chain).
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

// canonicalRow is the deterministic serialisation hashed for the chain.
// Field order is fixed by struct declaration; nested maps in Metadata are
// sorted by encoding/json. Changing this struct breaks all existing
// chains — bump a chain-version column first if that becomes necessary.
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

// pgUUIDNullable converts a *uuid.UUID to a pgtype.UUID suitable for
// nullable UUID columns. A nil pointer maps to the invalid (NULL) form.
func pgUUIDNullable(id *uuid.UUID) pgtype.UUID {
	if id == nil {
		return pgtype.UUID{Valid: false}
	}
	return pgtype.UUID{Bytes: *id, Valid: true}
}

// strRef returns a pointer to s, always non-nil. Used to pass strings to
// generated *string params without converting empty strings to NULL.
func strRef(s string) *string { return &s }

// Record writes one audit row inside the given transaction. It computes
// the next link in the per-tenant hash chain under a per-tenant advisory
// lock; concurrent audit writes for the same tenant serialise on commit.
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
	// Advisory lock stays raw — pg_advisory_xact_lock is a void-returning
	// side-effect; it does not return rows and cannot be modelled as a
	// named sqlc query.
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

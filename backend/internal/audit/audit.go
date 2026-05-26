// Package audit records actor-visible mutations to audit.events. Every
// write happens inside the caller's pgx.Tx so the audit row is committed
// atomically with the business write.
//
// Each row carries a SHA-256 hash that chains to the previous row in the
// same tenant. Tampering with any row (delete, edit, reorder) breaks the
// chain and is detected by Verifier.Verify. The chain seed for the first
// row in a tenant is sixty-four zero hex characters.
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
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		return err
	}

	prevHash := chainSeed
	var tip string
	err = tx.QueryRow(ctx, `
		SELECT row_hash FROM audit.events
		WHERE tenant_id IS NOT DISTINCT FROM $1
		  AND row_hash IS NOT NULL
		ORDER BY created_at DESC, id DESC
		LIMIT 1
	`, e.TenantID).Scan(&tip)
	switch {
	case err == nil:
		prevHash = strings.TrimSpace(tip)
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

	_, err = tx.Exec(ctx, `
		INSERT INTO audit.events (
			id, tenant_id, actor_user_id, actor_type, action,
			resource_type, resource_id, ip, user_agent, request_id,
			metadata, created_at, prev_hash, row_hash
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8,'')::inet, $9, $10, $11, $12, $13, $14)
	`,
		id, e.TenantID, e.ActorUserID, e.ActorType, e.Action,
		e.ResourceType, e.ResourceID, e.IP, e.UserAgent, e.RequestID,
		meta, createdAt, prevHash, rowHash,
	)
	return err
}

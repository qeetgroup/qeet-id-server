package audit

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// VerifyResult summarises a chain-verification pass for a single tenant.
type VerifyResult struct {
	OK             bool       `json:"ok"`
	RowsChecked    int        `json:"rows_checked"`
	LastVerifiedID *uuid.UUID `json:"last_verified_id,omitempty"`
	BrokenAtID     *uuid.UUID `json:"broken_at_id,omitempty"`
	BrokenReason   string     `json:"broken_reason,omitempty"`
}

type Verifier struct {
	pool *pgxpool.Pool
}

func NewVerifier(pool *pgxpool.Pool) *Verifier {
	return &Verifier{pool: pool}
}

// Verify walks the per-tenant hash chain in chronological order, recomputing
// each row's hash and comparing it against what is stored. Returns OK=false
// with BrokenAtID populated at the first row that fails validation.
//
// Pass tenantID=nil to verify the platform-level chain (rows with NULL
// tenant_id). Pre-migration rows (NULL hash columns) are skipped.
func (v *Verifier) Verify(ctx context.Context, tenantID *uuid.UUID) (VerifyResult, error) {
	rows, err := v.pool.Query(ctx, `
		SELECT id, tenant_id, actor_user_id, actor_type, action,
		       resource_type, resource_id,
		       COALESCE(host(ip), '') AS ip,
		       COALESCE(user_agent, ''),
		       COALESCE(request_id, ''),
		       metadata,
		       created_at,
		       prev_hash, row_hash
		FROM audit.events
		WHERE tenant_id IS NOT DISTINCT FROM $1
		  AND row_hash IS NOT NULL
		ORDER BY created_at ASC, id ASC
	`, tenantID)
	if err != nil {
		return VerifyResult{}, err
	}
	defer rows.Close()

	expectedPrev := chainSeed
	var (
		rowsChecked int
		lastID      *uuid.UUID
	)
	for rows.Next() {
		var (
			id         uuid.UUID
			tid        *uuid.UUID
			actor      *uuid.UUID
			actorType  string
			action     string
			resType    string
			resID      *uuid.UUID
			ip         string
			ua         string
			reqID      string
			metaRaw    []byte
			createdAt  time.Time
			prevHashDB string
			rowHashDB  string
		)
		if err := rows.Scan(&id, &tid, &actor, &actorType, &action,
			&resType, &resID, &ip, &ua, &reqID, &metaRaw, &createdAt,
			&prevHashDB, &rowHashDB); err != nil {
			return VerifyResult{}, err
		}
		prevHashDB = strings.TrimSpace(prevHashDB)
		rowHashDB = strings.TrimSpace(rowHashDB)

		if prevHashDB != expectedPrev {
			brokenID := id
			return VerifyResult{
				OK:             false,
				RowsChecked:    rowsChecked,
				LastVerifiedID: lastID,
				BrokenAtID:     &brokenID,
				BrokenReason:   "prev_hash does not match preceding row_hash",
			}, nil
		}

		metaJSON, err := normaliseMetadata(metaRaw)
		if err != nil {
			return VerifyResult{}, err
		}
		canonical, err := canonicalize(Event{
			TenantID:     tid,
			ActorUserID:  actor,
			ActorType:    actorType,
			Action:       action,
			ResourceType: resType,
			ResourceID:   resID,
			IP:           ip,
			UserAgent:    ua,
			RequestID:    reqID,
		}, id, createdAt, metaJSON, prevHashDB)
		if err != nil {
			return VerifyResult{}, err
		}
		expectedRowHash := hashHex(canonical)
		if expectedRowHash != rowHashDB {
			brokenID := id
			return VerifyResult{
				OK:             false,
				RowsChecked:    rowsChecked,
				LastVerifiedID: lastID,
				BrokenAtID:     &brokenID,
				BrokenReason:   "row_hash does not match recomputed hash",
			}, nil
		}

		expectedPrev = rowHashDB
		rowsChecked++
		idCopy := id
		lastID = &idCopy
	}
	if err := rows.Err(); err != nil {
		return VerifyResult{}, err
	}
	return VerifyResult{OK: true, RowsChecked: rowsChecked, LastVerifiedID: lastID}, nil
}

// normaliseMetadata round-trips JSONB bytes through json.Unmarshal +
// json.Marshal so the canonical bytes match what Record produced at insert
// time, regardless of how Postgres formatted the JSONB on the way out.
func normaliseMetadata(raw []byte) ([]byte, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return []byte("{}"), nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(m)
}

package audit

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/audit/dbgen"
)

// VerifyResult is the outcome of verifying one chain.
type VerifyResult struct {
	OK             bool       `json:"ok"`
	RowsChecked    int        `json:"rows_checked"`
	LastVerifiedID *uuid.UUID `json:"last_verified_id,omitempty"`
	BrokenAtID     *uuid.UUID `json:"broken_at_id,omitempty"`
	BrokenReason   string     `json:"broken_reason,omitempty"`
}

// verifyPageSize is how many rows of a chain each verification query reads.
var verifyPageSize int32 = 5000

// Verifier verifies audit hash chains.
type Verifier struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
}

// NewVerifier returns a Verifier over pool.
func NewVerifier(pool *pgxpool.Pool) *Verifier {
	return &Verifier{pool: pool, q: dbgen.New(pool)}
}

// Verify recomputes the hash chain of tenantID's audit rows, oldest first, or
// of the platform chain when tenantID is nil. At the first row that fails it
// returns OK=false with BrokenAtID set. Rows without a hash are skipped.
func (v *Verifier) Verify(ctx context.Context, tenantID *uuid.UUID) (VerifyResult, error) {
	expectedPrev := chainSeed
	var (
		rowsChecked int
		lastID      *uuid.UUID
	)
	// The chain is read a page at a time, so memory doesn't grow with it.
	page := dbgen.ListAuditEventsForVerifyParams{TenantID: pgUUIDNullable(tenantID), PageSize: verifyPageSize}
	for {
		rows, err := v.q.ListAuditEventsForVerify(ctx, page)
		if err != nil {
			return VerifyResult{}, err
		}
		for _, row := range rows {
			tid := toUUIDPtr(row.TenantID)
			actor := toUUIDPtr(row.ActorUserID)
			resID := toUUIDPtr(row.ResourceID)

			// ip is COALESCE(host(ip), ''), which sqlc types as interface{}.
			ip, _ := row.Ip.(string)

			prevHashDB := ""
			if row.PrevHash != nil {
				prevHashDB = strings.TrimSpace(*row.PrevHash)
			}
			rowHashDB := ""
			if row.RowHash != nil {
				rowHashDB = strings.TrimSpace(*row.RowHash)
			}

			if prevHashDB != expectedPrev {
				brokenID := row.ID
				return VerifyResult{
					OK:             false,
					RowsChecked:    rowsChecked,
					LastVerifiedID: lastID,
					BrokenAtID:     &brokenID,
					BrokenReason:   "prev_hash does not match preceding row_hash",
				}, nil
			}

			metaJSON, err := normaliseMetadata(row.Metadata)
			if err != nil {
				return VerifyResult{}, err
			}
			canonical, err := canonicalize(Event{
				TenantID:     tid,
				ActorUserID:  actor,
				ActorType:    row.ActorType,
				Action:       row.Action,
				ResourceType: row.ResourceType,
				ResourceID:   resID,
				IP:           ip,
				UserAgent:    row.UserAgent, // already COALESCE'd to ""
				RequestID:    row.RequestID, // already COALESCE'd to ""
			}, row.ID, row.CreatedAt, metaJSON, prevHashDB)
			if err != nil {
				return VerifyResult{}, err
			}
			expectedRowHash := hashHex(canonical)
			if expectedRowHash != rowHashDB {
				brokenID := row.ID
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
			idCopy := row.ID
			lastID = &idCopy
		}
		if len(rows) < int(page.PageSize) {
			return VerifyResult{OK: true, RowsChecked: rowsChecked, LastVerifiedID: lastID}, nil
		}
		last := rows[len(rows)-1]
		page.AfterCreatedAt, page.AfterID = last.CreatedAt, last.ID
	}
}

// toUUIDPtr converts a nullable pgtype.UUID to a *uuid.UUID; NULL becomes nil.
func toUUIDPtr(u pgtype.UUID) *uuid.UUID {
	if !u.Valid {
		return nil
	}
	id := uuid.UUID(u.Bytes)
	return &id
}

// normaliseMetadata re-encodes JSONB bytes the way Record encoded them, so the
// hash matches however Postgres formats the column.
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

// Keeps the time import, which nothing else in this file uses.
var _ = time.Time{}

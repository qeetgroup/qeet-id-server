package audit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/audit/dbgen"
)

// VerifyResult is the outcome of verifying one chain. When it is broken,
// ReasonCode is one of the Chain* codes and BrokenReason the same in English.
type VerifyResult struct {
	OK             bool       `json:"ok"`
	RowsChecked    int        `json:"rows_checked"`
	LastVerifiedID *uuid.UUID `json:"last_verified_id,omitempty"`
	BrokenAtID     *uuid.UUID `json:"broken_at_id,omitempty"`
	BrokenReason   string     `json:"broken_reason,omitempty"`
	ReasonCode     string     `json:"reason_code,omitempty"`
}

// Why a chain is broken at a row.
const (
	ChainPrevHashMismatch = "audit.chain_prev_hash_mismatch" // its prev_hash isn't the preceding row's row_hash
	ChainRowHashMismatch  = "audit.chain_row_hash_mismatch"  // its row_hash isn't the hash of its contents
)

// chainCheckpointGone is why a chain is broken when the row its checkpoint
// names is gone. Only a scheduled run, which starts from checkpoints, finds it.
const chainCheckpointGone = "audit.chain_checkpoint_gone"

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
	res, _, err := v.walk(ctx, tenantID, nil, true)
	return res, err
}

// checkpoint is a chain's last verified row, where a later walk can go on.
// Broken marks a chain found broken since.
type checkpoint struct {
	EventID   uuid.UUID
	CreatedAt time.Time
	RowHash   string
	Broken    bool
}

// walk verifies tenantID's chain as Verify does. Given from, a checkpoint, it
// first checks that from's row is unchanged and, unless fromStart, walks on
// from the row after it instead of the first row. It also returns the last row
// it found intact: nil for none, from itself when no row follows it.
func (v *Verifier) walk(ctx context.Context, tenantID *uuid.UUID, from *checkpoint, fromStart bool) (VerifyResult, *checkpoint, error) {
	expectedPrev := chainSeed
	var (
		rowsChecked int
		lastID      *uuid.UUID
		last        *checkpoint
	)
	broken := func(id uuid.UUID, code, reason string) (VerifyResult, *checkpoint, error) {
		return VerifyResult{
			OK: false, RowsChecked: rowsChecked, LastVerifiedID: lastID,
			BrokenAtID: &id, BrokenReason: reason, ReasonCode: code,
		}, last, nil
	}
	// The chain is read a page at a time, so memory doesn't grow with it.
	page := dbgen.ListAuditEventsForVerifyParams{TenantID: pgUUIDNullable(tenantID), PageSize: verifyPageSize}
	if from != nil {
		row, err := v.q.GetAuditEventForVerify(ctx, dbgen.GetAuditEventForVerifyParams{ID: from.EventID, TenantID: page.TenantID})
		if errors.Is(err, pgx.ErrNoRows) {
			return broken(from.EventID, chainCheckpointGone, "the last verified row is gone")
		}
		if err != nil {
			return VerifyResult{}, nil, err
		}
		got, err := rowHash(dbgen.ListAuditEventsForVerifyRow(row))
		if err != nil {
			return VerifyResult{}, nil, err
		}
		if stored := trimmed(row.RowHash); stored != from.RowHash || got != stored {
			return broken(from.EventID, ChainRowHashMismatch, "the last verified row has changed")
		}
		if !fromStart {
			expectedPrev, last = from.RowHash, from
			page.AfterCreatedAt, page.AfterID = from.CreatedAt, from.EventID
		}
	}
	for {
		rows, err := v.q.ListAuditEventsForVerify(ctx, page)
		if err != nil {
			return VerifyResult{}, nil, err
		}
		for _, row := range rows {
			if trimmed(row.PrevHash) != expectedPrev {
				return broken(row.ID, ChainPrevHashMismatch, "prev_hash does not match preceding row_hash")
			}
			got, err := rowHash(row)
			if err != nil {
				return VerifyResult{}, nil, err
			}
			stored := trimmed(row.RowHash)
			if got != stored {
				return broken(row.ID, ChainRowHashMismatch, "row_hash does not match recomputed hash")
			}
			expectedPrev = stored
			rowsChecked++
			idCopy := row.ID
			lastID = &idCopy
			last = &checkpoint{EventID: row.ID, CreatedAt: row.CreatedAt, RowHash: stored}
		}
		if len(rows) < int(page.PageSize) {
			return VerifyResult{OK: true, RowsChecked: rowsChecked, LastVerifiedID: lastID}, last, nil
		}
		end := rows[len(rows)-1]
		page.AfterCreatedAt, page.AfterID = end.CreatedAt, end.ID
	}
}

// rowHash is the hash row should carry: of its contents and its prev_hash.
func rowHash(row dbgen.ListAuditEventsForVerifyRow) (string, error) {
	metaJSON, err := normaliseMetadata(row.Metadata)
	if err != nil {
		return "", err
	}
	// ip is COALESCE(host(ip), ''), which sqlc types as interface{}.
	ip, _ := row.Ip.(string)
	canonical, err := canonicalize(Event{
		TenantID:     toUUIDPtr(row.TenantID),
		ActorUserID:  toUUIDPtr(row.ActorUserID),
		ActorType:    row.ActorType,
		Action:       row.Action,
		ResourceType: row.ResourceType,
		ResourceID:   toUUIDPtr(row.ResourceID),
		IP:           ip,
		UserAgent:    row.UserAgent, // already COALESCE'd to ""
		RequestID:    row.RequestID, // already COALESCE'd to ""
	}, row.ID, row.CreatedAt, metaJSON, trimmed(row.PrevHash))
	if err != nil {
		return "", err
	}
	return hashHex(canonical), nil
}

// trimmed is a stored hash without its CHAR padding, "" for NULL.
func trimmed(hash *string) string {
	if hash == nil {
		return ""
	}
	return strings.TrimSpace(*hash)
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

package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/strutil"
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

// chainCheckpointUnsigned is why a chain is broken when a checkpoint it relies
// on doesn't carry the MAC of the server's key: one rewritten with the chain.
const chainCheckpointUnsigned = "audit.chain_checkpoint_unsigned"

// CheckpointKey signs and checks checkpoints, as a row's plain hash can be
// recomputed by anyone able to write it. Satisfied by *envelope.Cipher; nil
// leaves checkpoints unsigned and unchecked.
type CheckpointKey interface {
	MAC(purpose string, msg []byte) (keyID string, mac []byte)
	CheckMAC(purpose, keyID string, msg, mac []byte) bool
}

// checkpointPurpose keeps a checkpoint's MAC key apart from other uses of the key.
const checkpointPurpose = "audit-checkpoint"

// What a checkpoint marks, which its MAC covers so one can't stand in for the other.
const (
	chainCheckpointKind = "chain" // the last row a scheduled verification found intact
	purgeCheckpointKind = "purge" // where a chain starts since its oldest events were deleted
)

// Why the platform chains are broken where no row of a chain is at fault.
const (
	chainShardMissing    = "audit.chain_shard_missing"      // a platform chain has no row, not even its first
	chainShardOutOfRange = "audit.chain_shard_out_of_range" // a platform row is on none of the platform chains
)

// verifyPageSize is how many rows of a chain each verification query reads.
var verifyPageSize int32 = 5000

// Verifier verifies audit hash chains.
type Verifier struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
	key  CheckpointKey
}

// NewVerifier returns a Verifier over pool whose checkpoints key signs.
func NewVerifier(pool *pgxpool.Pool, key CheckpointKey) *Verifier {
	return &Verifier{pool: pool, q: dbgen.New(pool), key: key}
}

// Verify recomputes the hash chain of organizationID's audit rows, oldest first, or
// when organizationID is nil every platform chain in turn, each of which must have a
// row, and checks no platform row is outside them. At the first row that fails
// it returns OK=false with BrokenAtID set. Rows without a hash are skipped. A
// chain's checkpoint must be signed and name an unchanged row.
func (v *Verifier) Verify(ctx context.Context, organizationID *uuid.UUID) (VerifyResult, error) {
	if organizationID != nil {
		from, err := v.savedCheckpoint(ctx, organizationID, 0)
		if err != nil {
			return VerifyResult{}, err
		}
		res, _, err := v.walk(ctx, organizationID, 0, from, true)
		return res, err
	}
	all := VerifyResult{OK: true}
	for shard := range int16(PlatformChainShards) {
		from, err := v.savedCheckpoint(ctx, nil, shard)
		if err != nil {
			return VerifyResult{}, err
		}
		res, _, err := v.walk(ctx, nil, shard, from, true)
		if err != nil {
			return VerifyResult{}, err
		}
		res.RowsChecked += all.RowsChecked
		if !res.OK {
			return res, nil
		}
		all = res
	}
	if stray, err := v.strayPlatformRow(ctx); err != nil || stray != nil {
		if stray != nil {
			all.OK, all.BrokenAtID, all.ReasonCode, all.BrokenReason = false, stray.EventID, chainShardOutOfRange, stray.Reason
		}
		return all, err
	}
	return all, nil
}

// strayPlatformRow is the first platform row on none of the platform chains,
// as a BrokenChain, or nil when there is none.
func (v *Verifier) strayPlatformRow(ctx context.Context) (*BrokenChain, error) {
	row, err := v.q.FindAuditRowOutsideShards(ctx, PlatformChainShards)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	reason := fmt.Sprintf("a platform row is on chain %d, outside 0..%d", row.ChainShard, PlatformChainShards-1)
	return &BrokenChain{EventID: &row.ID, Shard: row.ChainShard, Reason: reason}, nil
}

// checkpoint is a chain's last verified row, where a later walk can go on,
// with the MAC and key id that sign it. Broken marks a chain found broken since.
type checkpoint struct {
	EventID   uuid.UUID
	CreatedAt time.Time
	RowHash   string
	KeyID     string
	MAC       []byte
	Broken    bool
}

// checkpointMessage is what a checkpoint's MAC covers: its kind, its chain,
// the row it names and that row's hash.
func checkpointMessage(kind string, organizationID *uuid.UUID, shard int16, cp *checkpoint) []byte {
	return []byte(strings.Join([]string{kind, uuidStr(organizationID), strconv.Itoa(int(shard)), cp.EventID.String(),
		cp.CreatedAt.UTC().Format(time.RFC3339Nano), cp.RowHash}, "|"))
}

// signCheckpoint returns cp's key id and MAC under key, nil without one.
func signCheckpoint(key CheckpointKey, kind string, organizationID *uuid.UUID, shard int16, cp *checkpoint) (*string, []byte) {
	if key == nil {
		return nil, nil
	}
	id, mac := key.MAC(checkpointPurpose, checkpointMessage(kind, organizationID, shard, cp))
	return &id, mac
}

// signedCheckpoint reports whether cp carries a MAC of one of key's keys;
// without a key, checkpoints aren't checked.
func signedCheckpoint(key CheckpointKey, kind string, organizationID *uuid.UUID, shard int16, cp *checkpoint) bool {
	return key == nil || (cp.KeyID != "" && key.CheckMAC(checkpointPurpose, cp.KeyID, checkpointMessage(kind, organizationID, shard, cp), cp.MAC))
}

// savedCheckpoint is a chain's checkpoint, nil when it has none.
func (v *Verifier) savedCheckpoint(ctx context.Context, organizationID *uuid.UUID, shard int16) (*checkpoint, error) {
	row, err := v.q.GetAuditChainCheckpoint(ctx, dbgen.GetAuditChainCheckpointParams{ChainShard: shard, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &checkpoint{EventID: row.EventID, CreatedAt: row.EventCreatedAt, RowHash: trimmed(&row.RowHash), KeyID: strutil.Deref(row.KeyID), MAC: row.Mac}, nil
}

// walk verifies organizationID's chain, or with a nil organizationID platform chain shard,
// as Verify does. Given from, a checkpoint, it first checks that from's row is
// unchanged and, unless fromStart, walks on from the row after it instead of
// the first row. It also returns the last row it found intact: nil for none,
// from itself when no row follows it. A platform chain with no row is broken.
// An organization's chain whose oldest events were purged starts at its purge
// checkpoint; a purge made while the walk ran makes it walk once more.
func (v *Verifier) walk(ctx context.Context, organizationID *uuid.UUID, shard int16, from *checkpoint, fromStart bool) (VerifyResult, *checkpoint, error) {
	start, err := v.purgeStart(ctx, organizationID)
	if err != nil {
		return VerifyResult{}, nil, err
	}
	res, last, err := v.walkFrom(ctx, organizationID, shard, from, fromStart, start)
	if err != nil || res.OK || organizationID == nil || (res.ReasonCode != ChainPrevHashMismatch && res.ReasonCode != chainCheckpointGone) {
		return res, last, err
	}
	again, err := v.purgeStart(ctx, organizationID)
	if err != nil || again == nil || (start != nil && again.EventID == start.EventID) {
		return res, last, err
	}
	return v.walkFrom(ctx, organizationID, shard, from, fromStart, again)
}

// purgeStart is where organizationID's chain starts since its oldest events were
// purged, nil when none were (or for a platform chain).
func (v *Verifier) purgeStart(ctx context.Context, organizationID *uuid.UUID) (*checkpoint, error) {
	if organizationID == nil {
		return nil, nil
	}
	row, err := v.q.GetAuditPurgeCheckpoint(ctx, *organizationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &checkpoint{EventID: row.EventID, CreatedAt: row.EventCreatedAt, RowHash: strings.TrimSpace(row.RowHash), KeyID: strutil.Deref(row.KeyID), MAC: row.Mac}, nil
}

// signPurgeCheckpoint signs organizationID's purge checkpoint again with the current
// key when another signed it, so retiring that key leaves it checkable.
func (v *Verifier) signPurgeCheckpoint(ctx context.Context, organizationID uuid.UUID) error {
	start, err := v.purgeStart(ctx, &organizationID)
	if err != nil || start == nil || v.key == nil {
		return err
	}
	keyID, mac := signCheckpoint(v.key, purgeCheckpointKind, &organizationID, 0, start)
	if *keyID == start.KeyID || !signedCheckpoint(v.key, purgeCheckpointKind, &organizationID, 0, start) {
		return nil
	}
	return v.q.SignAuditPurgeCheckpoint(ctx, dbgen.SignAuditPurgeCheckpointParams{OrganizationID: organizationID, EventID: start.EventID, KeyID: keyID, Mac: mac})
}

// notAfter reports whether a is at or before b in chain order (created_at,
// then id, as Postgres orders uuids).
func notAfter(a, b *checkpoint) bool {
	if !a.CreatedAt.Equal(b.CreatedAt) {
		return a.CreatedAt.Before(b.CreatedAt)
	}
	return bytes.Compare(a.EventID[:], b.EventID[:]) <= 0
}

// walkFrom is walk starting at start, a purge checkpoint (nil: the seed): the
// first row must link to it, and a from at or before it was purged with it.
func (v *Verifier) walkFrom(ctx context.Context, organizationID *uuid.UUID, shard int16, from *checkpoint, fromStart bool, start *checkpoint) (VerifyResult, *checkpoint, error) {
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
	page := dbgen.ListAuditEventsForVerifyParams{OrganizationID: organizationID, ChainShard: shard, PageSize: verifyPageSize}
	if start != nil {
		if !signedCheckpoint(v.key, purgeCheckpointKind, organizationID, 0, start) {
			return broken(start.EventID, chainCheckpointUnsigned, "the chain's purge checkpoint isn't signed by this server")
		}
		expectedPrev = start.RowHash
		page.AfterCreatedAt, page.AfterID = start.CreatedAt, start.EventID
		if from != nil && notAfter(from, start) {
			from = nil
		}
	}
	if from != nil && !signedCheckpoint(v.key, chainCheckpointKind, organizationID, shard, from) {
		return broken(from.EventID, chainCheckpointUnsigned, "the last verified row's checkpoint isn't signed by this server")
	}
	if from != nil {
		row, err := v.q.GetAuditEventForVerify(ctx, dbgen.GetAuditEventForVerifyParams{ID: from.EventID, OrganizationID: page.OrganizationID, ChainShard: shard})
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
			if organizationID == nil && last == nil {
				return VerifyResult{
					OK: false, ReasonCode: chainShardMissing,
					BrokenReason: fmt.Sprintf("platform chain %d has no row", shard),
				}, nil, nil
			}
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
		OrganizationID: row.OrganizationID,
		ActorUserID:    row.ActorUserID,
		ActorType:      row.ActorType,
		Action:         row.Action,
		ResourceType:   row.ResourceType,
		ResourceID:     row.ResourceID,
		IP:             ip,
		UserAgent:      row.UserAgent, // already COALESCE'd to ""
		RequestID:      row.RequestID, // already COALESCE'd to ""
	}, row.ChainShard, row.ID, row.CreatedAt, metaJSON, trimmed(row.PrevHash))
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

// ChainVerification is an organization's chain as the scheduled verification
// last left it, without walking it again.
type ChainVerification struct {
	Verified       bool       `json:"verified"`         // the scheduled verification has reached the chain
	Intact         bool       `json:"intact"`           // no break found; false also before a first verification
	LastVerifiedAt *time.Time `json:"last_verified_at"` // when the chain was last verified up to LastEventID
	BrokenAt       *time.Time `json:"broken_at"`        // when a break was found; it stays until resolved
	LastEventID    *uuid.UUID `json:"last_verified_event_id"`
	LastRunAt      *time.Time `json:"last_run_at"`    // when the latest scheduled run finished
	LastRunScope   string     `json:"last_run_scope"` // "all" or "incremental"
}

// LastVerification returns how the scheduled verification last left organizationID's
// chain: when it verified it, up to which event, and whether it found a break.
func (v *Verifier) LastVerification(ctx context.Context, organizationID uuid.UUID) (*ChainVerification, error) {
	out := &ChainVerification{}
	run, err := v.q.GetLatestVerificationRun(ctx)
	switch {
	case err == nil:
		out.LastRunAt, out.LastRunScope = &run.FinishedAt, run.Scope
	case !errors.Is(err, pgx.ErrNoRows):
		return nil, err
	}
	row, err := v.q.GetOrganizationChainCheckpoint(ctx, organizationID)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	out.Verified, out.Intact, out.LastEventID, out.LastVerifiedAt = true, row.BrokenAt == nil, &row.EventID, &row.VerifiedAt
	out.BrokenAt = row.BrokenAt
	return out, nil
}

package world

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
)

// chainSeed is the prev_hash of a chain's first row (audit.chainSeed).
const chainSeed = "0000000000000000000000000000000000000000000000000000000000000000"

// Audit writes the audit row e at t, unhashed. Rechain hashes every chain once
// the story is written, so rows may be written in any order. A nil e.TenantID
// puts the row on the platform chain; an empty ActorType means "user". The row
// is marked scored, so the anomaly worker leaves seeded history alone.
func (w *World) Audit(t time.Time, e audit.Event) uuid.UUID {
	if e.ActorType == "" {
		e.ActorType = "user"
	}
	meta, err := json.Marshal(e.Metadata)
	Must(err, "encode audit metadata")
	if string(meta) == "null" {
		meta = []byte("{}")
	}
	id := uuid.New()
	w.Exec("audit "+e.Action, `
		INSERT INTO audit.events (id, tenant_id, actor_user_id, actor_type, action, resource_type, resource_id,
		                          ip, user_agent, request_id, metadata, created_at, scored_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, '')::inet, NULLIF($9, ''), NULLIF($10, ''), $11, $12, $12)`,
		id, e.TenantID, e.ActorUserID, e.ActorType, e.Action, e.ResourceType, e.ResourceID,
		e.IP, e.UserAgent, e.RequestID, meta, t.UTC().Truncate(time.Microsecond))
	return id
}

// canonicalRow is audit's hashed serialisation (audit.canonicalRow): the same
// fields in the same order. Verify proves the two still agree.
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

// Rechain rehashes every audit chain in time order, after At moved rows back
// and Audit wrote history out of order.
func (w *World) Rechain() {
	rows, err := w.Admin.Query(w.Ctx, `SELECT DISTINCT tenant_id FROM audit.events`)
	Must(err, "list audit chains")
	var chains []pgtype.UUID
	for rows.Next() {
		var t pgtype.UUID
		Must(rows.Scan(&t), "scan audit chain")
		chains = append(chains, t)
	}
	rows.Close()
	Must(rows.Err(), "list audit chains")
	for _, t := range chains {
		w.rechain(t)
	}
}

func (w *World) rechain(tenant pgtype.UUID) {
	rows, err := w.Admin.Query(w.Ctx, `
		SELECT id, COALESCE(tenant_id::text, ''), COALESCE(actor_user_id::text, ''), actor_type, action,
		       resource_type, COALESCE(resource_id::text, ''), COALESCE(host(ip), ''),
		       COALESCE(user_agent, ''), COALESCE(request_id, ''), metadata, created_at
		FROM audit.events
		WHERE tenant_id IS NOT DISTINCT FROM $1
		ORDER BY created_at, id`, tenant)
	Must(err, "read audit chain")
	type link struct {
		id         uuid.UUID
		prev, hash string
	}
	var links []link
	prev := chainSeed
	for rows.Next() {
		var (
			id      uuid.UUID
			r       canonicalRow
			meta    []byte
			created time.Time
		)
		Must(rows.Scan(&id, &r.TenantID, &r.ActorUserID, &r.ActorType, &r.Action, &r.ResourceType, &r.ResourceID,
			&r.IP, &r.UserAgent, &r.RequestID, &meta, &created), "scan audit row")
		var m map[string]any
		Must(json.Unmarshal(meta, &m), "decode audit metadata")
		if m == nil {
			m = map[string]any{}
		}
		norm, err := json.Marshal(m)
		Must(err, "encode audit metadata")
		r.ID, r.Metadata, r.CreatedAt, r.PrevHash = id.String(), norm, created.UTC().Format(time.RFC3339Nano), prev
		b, err := json.Marshal(r)
		Must(err, "encode audit row")
		sum := sha256.Sum256(b)
		hash := hex.EncodeToString(sum[:])
		links = append(links, link{id, prev, hash})
		prev = hash
	}
	rows.Close()
	Must(rows.Err(), "read audit chain")

	batch := &pgx.Batch{}
	for _, l := range links {
		batch.Queue(`UPDATE audit.events SET prev_hash = $2, row_hash = $3 WHERE id = $1`, l.id, l.prev, l.hash)
	}
	Must(w.Admin.SendBatch(w.Ctx, batch).Close(), "rehash audit chain")
}

// VerifyChains checks every chain with the API's own verifier, so the console's
// "verify" shows intact chains.
func (w *World) VerifyChains() int {
	rows, err := w.Admin.Query(w.Ctx, `SELECT DISTINCT tenant_id FROM audit.events`)
	Must(err, "list audit chains")
	var chains []pgtype.UUID
	for rows.Next() {
		var t pgtype.UUID
		Must(rows.Scan(&t), "scan audit chain")
		chains = append(chains, t)
	}
	rows.Close()
	verifier := audit.NewVerifier(w.Pool)
	total := 0
	for _, t := range chains {
		var tid *uuid.UUID
		if t.Valid {
			id := uuid.UUID(t.Bytes)
			tid = &id
		}
		res, err := verifier.Verify(w.Ctx, tid)
		Must(err, "verify audit chain")
		if !res.OK {
			label := "platform"
			if tid != nil {
				label = tid.String()
			}
			Must(errString("audit chain "+label+" broken: "+res.BrokenReason+" "+strings.TrimSpace(res.ReasonCode)), "verify audit chain")
		}
		total += res.RowsChecked
	}
	return total
}

type errString string

func (e errString) Error() string { return string(e) }

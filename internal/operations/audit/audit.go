// Package audit records mutations to audit.events inside the caller's
// transaction, so each row commits with the change it describes. Each row's
// SHA-256 hash chains to the previous row of its chain, its tenant's or one of
// the PlatformChainShards platform chains: deleting, editing or reordering a
// row breaks the chain, which Verifier detects.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/audit/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// chainSeed is the prev_hash of the first row of a chain.
const chainSeed = "0000000000000000000000000000000000000000000000000000000000000000"

// PlatformChainShards is how many platform chains there are, numbered from 0,
// so writers of events with no tenant don't all queue on one chain's lock.
// Changing it leaves rows outside the range, which verification reports.
const PlatformChainShards = 16

// platformShard is the platform chain tx's events go on: its database
// connection's, so a transaction only ever takes one platform chain's lock
// (two taken in opposite orders by two transactions would deadlock), and
// concurrent transactions spread across the chains. Tests replace it.
var platformShard = func(tx pgx.Tx) int16 {
	return int16(tx.Conn().PgConn().PID() % PlatformChainShards) // #nosec G115 -- below PlatformChainShards
}

// Event is an audit row to record. A nil TenantID puts it on a platform
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

// ActorOf returns who made r, for its audit events: its principal (a user
// unless the principal names another actor type) or, with none, the system,
// with r's client address, user agent and request ID.
func ActorOf(r *http.Request) Actor {
	a := Actor{Type: "system", IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r)}
	if p := httpx.PrincipalFromCtx(r.Context()); p != nil {
		a.UserID, a.Type = p.UserID, "user"
		if p.ActorType != "" {
			a.Type = p.ActorType
		}
	}
	return a
}

// Identity returns the actor's user, if any, and type: an Event's
// ActorUserID and ActorType.
func (a Actor) Identity() (*uuid.UUID, string) { return a.UserID, a.Type }

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

// Changes returns the fields of after whose value differs from before, each as
// {"from": old, "to": new}: what an update changed, for its audit metadata.
func Changes(before, after map[string]any) map[string]any {
	out := map[string]any{}
	for field, to := range after {
		if from := before[field]; !reflect.DeepEqual(from, to) {
			out[field] = map[string]any{"from": from, "to": to}
		}
	}
	return out
}

// canonicalRow is the serialisation each row's hash covers; its field order is
// fixed by this declaration. Changing it breaks every existing chain, so add a
// chain-version column first. ChainShard is left out at 0, so a row of an
// organisation's chain or of platform chain 0 hashes as it always has.
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
	ChainShard   int16           `json:"chain_shard,omitempty"`
}

func canonicalize(e Event, shard int16, id uuid.UUID, createdAt time.Time, metaJSON []byte, prevHash string) ([]byte, error) {
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
		ChainShard:   shard,
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

// clock is this instance's time, which an audit row is stamped with unless
// its chain's tip is later. A test sets it to stand for another instance.
var clock = time.Now

// labelQueries read the name of a role, group or ABAC policy by its id in
// the event's tenant.
var labelQueries = map[string]string{
	"role":        `SELECT name FROM rbac.roles WHERE id = $1 AND tenant_id = $2`,
	"group":       `SELECT name FROM tenant.groups WHERE id = $1 AND tenant_id = $2`,
	"abac_policy": `SELECT name FROM auth.abac_policies WHERE id = $1 AND tenant_id = $2`,
}

// labelled is e's metadata with the names of the roles, groups and ABAC
// policies the event is about, as they are now: target_name for its resource,
// and role_name or group_name for a role_id or group_id the metadata gives. A
// target already gone keeps the name the caller gave, as metadata "name".
// People are left to their ids: the chain can't be changed, so a name in it
// would outlive the person's erasure.
func labelled(ctx context.Context, tx pgx.Tx, e Event) (map[string]any, error) {
	meta := make(map[string]any, len(e.Metadata)+2)
	for k, v := range e.Metadata {
		meta[k] = v
	}
	if _, named := labelQueries[e.ResourceType]; named && meta["target_name"] == nil && e.ResourceID != nil {
		name, err := label(ctx, tx, e.ResourceType, *e.ResourceID, e.TenantID)
		if err != nil {
			return nil, err
		}
		if given, ok := meta["name"].(string); ok && name == "" {
			name = given
		}
		if name != "" {
			meta["target_name"] = name
		}
	}
	for _, kind := range []string{"role", "group"} {
		id, ok := idOf(meta[kind+"_id"])
		if _, named := meta[kind+"_name"]; !ok || named {
			continue
		}
		name, err := label(ctx, tx, kind, id, e.TenantID)
		if err != nil {
			return nil, err
		}
		if name != "" {
			meta[kind+"_name"] = name
		}
	}
	return meta, nil
}

// label is the name of the kind of thing id is, or "" for a kind without one
// or an id not found.
func label(ctx context.Context, tx pgx.Tx, kind string, id uuid.UUID, tenantID *uuid.UUID) (string, error) {
	q, ok := labelQueries[kind]
	if !ok {
		return "", nil
	}
	var name string
	err := tx.QueryRow(ctx, q, id, pgUUIDNullable(tenantID)).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return name, err
}

// idOf reads an id from metadata, as a UUID or its string.
func idOf(v any) (uuid.UUID, bool) {
	switch id := v.(type) {
	case uuid.UUID:
		return id, id != uuid.Nil
	case *uuid.UUID:
		if id != nil {
			return *id, *id != uuid.Nil
		}
	case string:
		if parsed, err := uuid.Parse(id); err == nil {
			return parsed, true
		}
	}
	return uuid.Nil, false
}

// Record writes one audit row in tx, as the next link of its chain, with the
// names of what it is about (see labelled): its tenant's chain, or with no
// tenant the platform chain of tx's connection. A per-chain advisory lock
// serialises concurrent writers until tx ends.
func Record(ctx context.Context, tx pgx.Tx, e Event) error {
	if e.ActorType == "" {
		e.ActorType = "user"
	}
	labels, err := labelled(ctx, tx, e)
	if err != nil {
		return err
	}
	// Where the request came from, approximately, when the proxy says.
	if _, given := labels["geo"]; !given {
		geo := map[string]any{}
		if c := httpx.GeoCountry(ctx); c != "" {
			geo["country"] = c
		}
		if c := httpx.GeoCity(ctx); c != "" {
			geo["city"] = c
		}
		if len(geo) > 0 {
			labels["geo"] = geo
		}
	}
	e.Metadata = labels
	var shard int16
	if e.TenantID == nil {
		shard = platformShard(tx)
	}
	return appendEvent(ctx, tx, e, shard)
}

// lockChain takes the advisory lock of a chain, held until tx ends: a
// tenant's, or with no tenant platform chain shard. Chain 0's key is the one
// the single platform chain had.
func lockChain(ctx context.Context, tx pgx.Tx, tenantID *uuid.UUID, shard int16) error {
	key := "audit:platform"
	switch {
	case tenantID != nil:
		key = "audit:" + tenantID.String()
	case shard != 0:
		key += ":" + strconv.Itoa(int(shard))
	}
	// Raw SQL: pg_advisory_xact_lock returns void, which sqlc cannot model.
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, key)
	return err
}

// appendEvent writes e in tx as the next link of its tenant's chain, or with no
// tenant of platform chain shard.
func appendEvent(ctx context.Context, tx pgx.Tx, e Event, shard int16) error {
	meta, err := json.Marshal(e.Metadata)
	if err != nil {
		return err
	}
	if len(meta) == 0 || string(meta) == "null" {
		meta = []byte("{}")
	}
	if err := lockChain(ctx, tx, e.TenantID, shard); err != nil {
		return err
	}

	q := dbgen.New(tx)

	prevHash := chainSeed
	createdAt := clock().UTC().Truncate(time.Microsecond)
	tip, err := q.GetAuditChainTip(ctx, dbgen.GetAuditChainTipParams{TenantID: pgUUIDNullable(e.TenantID), ChainShard: shard})
	switch {
	case err == nil:
		prevHash = strings.TrimSpace(*tip.RowHash)
		// The chain is ordered by created_at, and each instance has its own
		// clock: a row stamped no later than the tip would sort before it and
		// fork the chain, so it goes just after.
		if !createdAt.After(tip.CreatedAt) {
			createdAt = tip.CreatedAt.Add(time.Microsecond)
		}
	case errors.Is(err, pgx.ErrNoRows):
		// First row in chain; keep the seed.
	default:
		return err
	}

	id := uuid.New()
	canonical, err := canonicalize(e, shard, id, createdAt, meta, prevHash)
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
		ChainShard:   shard,
	})
}

// OpenPlatformChains starts each platform chain that has no row yet with an
// audit.chain_opened event, so every chain always has a tip and verification
// can tell one whose rows were removed from one never written to.
func OpenPlatformChains(ctx context.Context, pool *pgxpool.Pool) error {
	for shard := range int16(PlatformChainShards) {
		if err := openPlatformChain(ctx, pool, shard); err != nil {
			return err
		}
	}
	return nil
}

func openPlatformChain(ctx context.Context, pool *pgxpool.Pool, shard int16) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := lockChain(ctx, tx, nil, shard); err != nil {
		return err
	}
	_, err = dbgen.New(tx).GetAuditChainTip(ctx, dbgen.GetAuditChainTipParams{ChainShard: shard})
	if err == nil {
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	opened := Event{ActorType: "system", Action: "audit.chain_opened", ResourceType: "audit_chain",
		Metadata: map[string]any{"chain_shard": shard}}
	if err := appendEvent(ctx, tx, opened, shard); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

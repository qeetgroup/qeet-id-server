package audit

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Reader reads a tenant's audit log.
type Reader struct {
	pool *pgxpool.Pool
}

// NewReader returns a Reader over pool.
func NewReader(pool *pgxpool.Pool) *Reader {
	return &Reader{pool: pool}
}

// Row is one audit event as List returns it.
type Row struct {
	ID           uuid.UUID  `json:"id"`
	TenantID     *uuid.UUID `json:"tenant_id"`
	ActorUserID  *uuid.UUID `json:"actor_user_id"`
	ActorType    string     `json:"actor_type"`
	Action       string     `json:"action"`
	ResourceType string     `json:"resource_type"`
	ResourceID   *uuid.UUID `json:"resource_id"`
	IP           *string    `json:"ip"`
	UserAgent    *string    `json:"user_agent"`
	RequestID    *string    `json:"request_id"`
	CreatedAt    time.Time  `json:"created_at"`
}

// ListFilter narrows List's results; zero-value fields do not filter. Search is
// a websearch_to_tsquery full-text query ("quoted phrases", -exclusions, OR).
type ListFilter struct {
	Action       string
	ResourceType string
	ActorUserID  uuid.UUID
	Search       string
}

// List returns up to limit of the tenant's audit rows (50 if limit is not in
// 1..200), newest first, and a cursor for the next page, or "" on the last
// page.
func (rd *Reader) List(ctx context.Context, tenantID uuid.UUID, limit int, cursor string, filter ListFilter) ([]Row, string, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	q := `
		SELECT id, tenant_id, actor_user_id, actor_type, action, resource_type, resource_id,
		       host(ip), user_agent, request_id, created_at
		FROM audit.events
		WHERE tenant_id = $1
	`
	args := []any{tenantID}
	if filter.Action != "" {
		args = append(args, filter.Action)
		q += ` AND action = $` + strconv.Itoa(len(args))
	}
	if filter.ResourceType != "" {
		args = append(args, filter.ResourceType)
		q += ` AND resource_type = $` + strconv.Itoa(len(args))
	}
	if filter.ActorUserID != uuid.Nil {
		args = append(args, filter.ActorUserID)
		q += ` AND actor_user_id = $` + strconv.Itoa(len(args))
	}
	if filter.Search != "" {
		args = append(args, filter.Search)
		q += ` AND search_vector @@ websearch_to_tsquery('simple', $` + strconv.Itoa(len(args)) + `)`
	}
	if cursor != "" {
		cid, err := uuid.Parse(cursor)
		if err != nil {
			return nil, "", errs.ErrAuditCursorInvalid
		}
		args = append(args, cid)
		q += ` AND (created_at, id) < (SELECT created_at, id FROM audit.events WHERE id = $` + strconv.Itoa(len(args)) + `)`
	}
	args = append(args, limit+1)
	q += ` ORDER BY created_at DESC, id DESC LIMIT $` + strconv.Itoa(len(args))

	resRows, err := rd.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, "", err
	}
	defer resRows.Close()
	// Empty, not nil, so an empty page encodes as [] rather than null.
	out := []Row{}
	for resRows.Next() {
		var r Row
		if err := resRows.Scan(&r.ID, &r.TenantID, &r.ActorUserID, &r.ActorType, &r.Action,
			&r.ResourceType, &r.ResourceID, &r.IP, &r.UserAgent, &r.RequestID, &r.CreatedAt); err != nil {
			return nil, "", err
		}
		out = append(out, r)
	}
	// Without this, a truncated read would return a short page that looks
	// complete.
	if err := resRows.Err(); err != nil {
		return nil, "", err
	}
	var next string
	if len(out) > limit {
		next = out[limit].ID.String()
		out = out[:limit]
	}
	return out, next, nil
}

// Handler serves the audit log endpoints.
type Handler struct {
	Reader   *Reader
	Verifier *Verifier
}

// Mount registers the authenticated audit routes.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/audit", h.list)
	r.Get("/tenants/{tenantID}/audit/verify", h.verify)
}

// MountPublic registers GET /audit/verify, an unauthenticated check of the
// platform audit chain, so anyone can confirm it is intact. Tenant chains are
// verified only behind auth, in Mount.
func (h *Handler) MountPublic(r chi.Router) {
	r.Get("/audit/verify", h.verifyPublic)
}

// publicVerifyResult is verifyPublic's deliberately minimal result: whether the
// platform chain is intact, with no tenant data or row identifiers.
type publicVerifyResult struct {
	ChainValid  bool `json:"chain_valid"`
	RowsChecked int  `json:"rows_checked"`
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrAuditTenantInvalid)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	var filter ListFilter
	filter.Action = r.URL.Query().Get("action")
	filter.ResourceType = r.URL.Query().Get("resource_type")
	if raw := r.URL.Query().Get("actor_user_id"); raw != "" {
		actorID, err := uuid.Parse(raw)
		if err != nil {
			httpx.WriteError(w, r, errs.ErrAuditActorIDInvalid)
			return
		}
		filter.ActorUserID = actorID
	}
	filter.Search = r.URL.Query().Get("q")
	out, next, err := h.Reader.List(r.Context(), tid, limit, r.URL.Query().Get("cursor"), filter)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"items":       out,
		"next_cursor": next,
	})
}

func (h *Handler) verify(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrAuditTenantInvalid)
		return
	}
	res, err := h.Verifier.Verify(r.Context(), &tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// verifyPublic verifies the platform audit chain (rows with a NULL tenant_id)
// and returns only whether it is intact and how many rows were checked.
func (h *Handler) verifyPublic(w http.ResponseWriter, r *http.Request) {
	res, err := h.Verifier.Verify(r.Context(), nil)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, publicVerifyResult{
		ChainValid:  res.OK,
		RowsChecked: res.RowsChecked,
	})
}

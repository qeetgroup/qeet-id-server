package audit

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qeetgroup/qeet-identity/internal/platform/errs"
	"github.com/qeetgroup/qeet-identity/internal/platform/httpx"
)

type Reader struct {
	pool *pgxpool.Pool
}

func NewReader(pool *pgxpool.Pool) *Reader {
	return &Reader{pool: pool}
}

type Row struct {
	ID            uuid.UUID  `json:"id"`
	TenantID      *uuid.UUID `json:"tenant_id"`
	ActorUserID   *uuid.UUID `json:"actor_user_id"`
	ActorType     string     `json:"actor_type"`
	Action        string     `json:"action"`
	ResourceType  string     `json:"resource_type"`
	ResourceID    *uuid.UUID `json:"resource_id"`
	IP            *string    `json:"ip"`
	UserAgent     *string    `json:"user_agent"`
	RequestID     *string    `json:"request_id"`
	CreatedAt     time.Time  `json:"created_at"`
}

func (rd *Reader) List(ctx context.Context, tenantID uuid.UUID, limit int, cursor string) ([]Row, string, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var (
		rows interface{ Scan(...any) error }
		_    = rows
	)
	q := `
		SELECT id, tenant_id, actor_user_id, actor_type, action, resource_type, resource_id,
		       host(ip), user_agent, request_id, created_at
		FROM audit.events
		WHERE tenant_id = $1
	`
	args := []any{tenantID}
	if cursor != "" {
		cid, err := uuid.Parse(cursor)
		if err != nil {
			return nil, "", errs.ErrBadRequest.WithDetail("invalid cursor")
		}
		q += ` AND (created_at, id) < (SELECT created_at, id FROM audit.events WHERE id = $2)`
		args = append(args, cid)
	}
	q += ` ORDER BY created_at DESC, id DESC LIMIT $` + strconv.Itoa(len(args)+1)
	args = append(args, limit+1)

	resRows, err := rd.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, "", err
	}
	defer resRows.Close()
	var out []Row
	for resRows.Next() {
		var r Row
		if err := resRows.Scan(&r.ID, &r.TenantID, &r.ActorUserID, &r.ActorType, &r.Action,
			&r.ResourceType, &r.ResourceID, &r.IP, &r.UserAgent, &r.RequestID, &r.CreatedAt); err != nil {
			return nil, "", err
		}
		out = append(out, r)
	}
	var next string
	if len(out) > limit {
		next = out[limit].ID.String()
		out = out[:limit]
	}
	return out, next, nil
}

type Handler struct {
	Reader   *Reader
	Verifier *Verifier
}

func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/audit", h.list)
	r.Get("/tenants/{tenantID}/audit/verify", h.verify)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tid, err := uuid.Parse(chi.URLParam(r, "tenantID"))
	if err != nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	out, next, err := h.Reader.List(r.Context(), tid, limit, r.URL.Query().Get("cursor"))
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
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid tenantID"))
		return
	}
	res, err := h.Verifier.Verify(r.Context(), &tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

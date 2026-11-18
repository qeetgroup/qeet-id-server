package activity

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/activity/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Related-events window bounds around the anchor event.
const (
	relatedDefaultWindow = 5 * time.Minute
	relatedMinWindow     = 1 * time.Minute
	relatedMaxWindow     = 1 * time.Hour
	relatedRowLimit      = int32(20)
)

// activityRelatedResponse is the wire shape for GET /v1/activity/{id}/related.
type activityRelatedResponse struct {
	Event   ActivityEvent      `json:"event"`
	Related activityRelatedSet `json:"related"`
}

type activityRelatedSet struct {
	ByRequestID []ActivityEvent `json:"by_request_id"`
	ByActor     []ActivityEvent `json:"by_actor"`
}

// related serves GET /v1/activity/{id}/related: the anchor event, the events
// sharing its request_id, and the same actor's events within the time window.
// An unknown or other-organization id is a 404; no event appears in both lists.
// event serves GET /organizations/{organizationID}/activity/{id}: one of the
// organization's events, with its metadata, actor and browser. Another
// organization's id answers 404, like an unknown one.
func (h *Handler) event(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid event id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	row, err := dbgen.New(h.pool).GetActivityEventByID(r.Context(), dbgen.GetActivityEventByIDParams{
		OrganizationID: &organizationID,
		ID:             id,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		httpx.WriteError(w, r, errs.ErrNotFound)
		return
	}
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, mapAuditRow(toAuditRow(row)))
}

func (h *Handler) related(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	id, err := httpx.PathUUID(r, "id", errs.ErrBadRequest.WithDetail("invalid event id"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	q := dbgen.New(h.pool)
	ctx := r.Context()

	anchorRow, err := q.GetActivityEventByID(ctx, dbgen.GetActivityEventByIDParams{
		OrganizationID: &organizationID,
		ID:             id,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			httpx.WriteError(w, r, errs.ErrNotFound)
			return
		}
		httpx.WriteError(w, r, err)
		return
	}
	anchor := mapAuditRow(toAuditRow(anchorRow))

	window := relatedDefaultWindow
	if raw := r.URL.Query().Get("window"); raw != "" {
		if secs, errW := strconv.ParseInt(raw, 10, 64); errW == nil && secs > 0 {
			window = time.Duration(secs) * time.Second
		}
	}
	if window < relatedMinWindow {
		window = relatedMinWindow
	}
	if window > relatedMaxWindow {
		window = relatedMaxWindow
	}

	seen := map[uuid.UUID]bool{id: true}

	byRequest := []ActivityEvent{}
	if anchorRow.RequestID != nil && *anchorRow.RequestID != "" {
		rows, errR := q.ListRelatedByRequestID(ctx, dbgen.ListRelatedByRequestIDParams{
			OrganizationID: &organizationID,
			RequestID:      anchorRow.RequestID,
			ExcludeID:      id,
			RowLimit:       relatedRowLimit,
		})
		if errR != nil {
			httpx.WriteError(w, r, errR)
			return
		}
		for _, row := range rows {
			ev := mapAuditRow(toAuditRow(row))
			seen[ev.ID] = true
			byRequest = append(byRequest, ev)
		}
	}

	byActor := []ActivityEvent{}
	if anchorRow.ActorUserID != nil {
		rows, errA := q.ListRelatedByActor(ctx, dbgen.ListRelatedByActorParams{
			OrganizationID: &organizationID,
			ActorID:        anchorRow.ActorUserID,
			FromTs:         anchor.At.Add(-window),
			ToTs:           anchor.At.Add(window),
			ExcludeID:      id,
			RowLimit:       relatedRowLimit,
		})
		if errA != nil {
			httpx.WriteError(w, r, errA)
			return
		}
		for _, row := range rows {
			ev := mapAuditRow(toAuditRow(row))
			if seen[ev.ID] {
				continue // already surfaced under by_request_id
			}
			seen[ev.ID] = true
			byActor = append(byActor, ev)
		}
	}

	httpx.WriteJSON(w, http.StatusOK, activityRelatedResponse{
		Event: anchor,
		Related: activityRelatedSet{
			ByRequestID: byRequest,
			ByActor:     byActor,
		},
	})
}

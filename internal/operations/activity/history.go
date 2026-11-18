package activity

import (
	"context"
	"net/http"
	"net/netip"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/activity/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
	"github.com/qeetgroup/qeet-id-server/internal/platform/strutil"
)

// history serves GET /v1/activity: one cursor-paginated page of events from
// the audit log.
func (h *Handler) history(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.RequireOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	f, err := parseListFilter(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	after, err := paging.ParseCursor(r.URL.Query())
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	events, next, err := h.listHistory(r.Context(), organizationID, f, after, paging.Limit(r.URL.Query(), 50, 200))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if events == nil {
		events = []ActivityEvent{}
	}
	total, err := dbgen.New(h.pool).CountActivityHistory(r.Context(), historyCountParams(organizationID, f))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}

	resp := map[string]any{"events": events, "total": min(total, maxCountedEvents), "total_capped": total > maxCountedEvents}
	if next != "" {
		resp["next_cursor"] = next
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// maxCountedEvents is how far the history's total counts; past it the total
// says it is capped.
const maxCountedEvents = 10000

// historyCountParams are f's filters for CountActivityHistory, counting one
// past maxCountedEvents.
func historyCountParams(organizationID uuid.UUID, f ListFilter) dbgen.CountActivityHistoryParams {
	p := historyParams(organizationID, f)
	return dbgen.CountActivityHistoryParams{
		OrganizationID: p.OrganizationID, Actions: p.Actions, ActorID: p.ActorID, Subject: p.Subject,
		FromTs: p.FromTs, ToTs: p.ToTs, Q: p.Q, QLike: p.QLike, ResourceTypes: p.ResourceTypes, ResourceID: p.ResourceID,
		Ip: p.Ip, Categories: p.Categories, Severities: p.Severities, MinSeverity: p.MinSeverity,
		CountCap: maxCountedEvents + 1,
	}
}

// historyParams are f's filters for ListActivityHistory, with no cursor or
// limit. A nil filter passes NULL, which the query treats as "no filter on this
// dimension".
func historyParams(organizationID uuid.UUID, f ListFilter) dbgen.ListActivityHistoryParams {
	params := dbgen.ListActivityHistoryParams{
		OrganizationID: &organizationID,
		Actions:        f.Types, // nil slice → NULL → no filter
		ResourceTypes:  f.ResourceTypes,
		Categories:     f.Categories,
		Severities:     f.Severities,
		Ip:             f.IP,
	}
	if f.MinSeverity != "" {
		params.MinSeverity = &f.MinSeverity
	}
	if f.ActorID != uuid.Nil {
		params.ActorID = &f.ActorID
	}
	if f.Subject != nil {
		params.Subject = f.Subject
	}
	if f.ResourceID != nil {
		params.ResourceID = f.ResourceID
	}
	if f.From != nil {
		params.FromTs = f.From
	}
	if f.To != nil {
		params.ToTs = f.To
	}
	if f.Search != "" {
		like := postgres.EscapeLike(f.Search)
		params.Q, params.QLike = &f.Search, &like
	}
	return params
}

// listHistory returns a page of up to limit events (50 when limit is not in
// 1..200) and the next page's cursor, or "" on the last page. Every filter is
// applied in the query, so a page is full unless it is the last.
func (h *Handler) listHistory(ctx context.Context, organizationID uuid.UUID, f ListFilter, after paging.Cursor, limit int) ([]ActivityEvent, string, error) {
	limit = paging.Clamp(limit, 50, 200)
	params := historyParams(organizationID, f)
	params.RowLimit = int32(limit + 1) // #nosec G115 -- at most 201
	params.CursorTs, params.CursorID = after.Before()
	dbRows, err := dbgen.New(h.pool).ListActivityHistory(ctx, params)
	if err != nil {
		return nil, "", err
	}
	out := make([]ActivityEvent, 0, len(dbRows))
	for _, row := range dbRows {
		out = append(out, mapAuditRow(toAuditRow(row)))
	}
	out, next := paging.Next(out, limit, func(e ActivityEvent) (time.Time, uuid.UUID) { return e.At, e.ID })
	return out, next, nil
}

// parseListFilter builds the ListFilter shared by history and summary from the
// query string. Values that do not parse (actor, subject, from, to) are
// ignored; an unknown severity or category, or a malformed resource_id or ip,
// is refused with ErrBadRequest.
func parseListFilter(r *http.Request) (ListFilter, error) {
	query := r.URL.Query()
	f := ListFilter{
		Types:         strutil.SplitList(query.Get("types")),
		Severities:    strutil.SplitList(query.Get("severity")),
		MinSeverity:   query.Get("min_severity"),
		Categories:    strutil.SplitList(query.Get("category")),
		Search:        query.Get("q"),
		ResourceTypes: strutil.SplitList(query.Get("resource_type")),
	}
	for _, s := range append(slices.Clone(f.Severities), f.MinSeverity) {
		if s != "" && !slices.Contains(severities, s) {
			return ListFilter{}, errs.ErrBadRequest.WithDetail("unknown severity " + s)
		}
	}
	for _, c := range f.Categories {
		if !slices.Contains(categories, c) {
			return ListFilter{}, errs.ErrBadRequest.WithDetail("unknown category " + c)
		}
	}
	if raw := query.Get("resource_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			return ListFilter{}, errs.ErrBadRequest.WithDetail("invalid resource_id")
		}
		f.ResourceID = &id
	}
	if raw := query.Get("ip"); raw != "" {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			return ListFilter{}, errs.ErrBadRequest.WithDetail("invalid ip")
		}
		f.IP = &addr
	}
	// A filter that doesn't parse is refused, as resource_id and ip are: dropping it would answer
	// unfiltered events as if they matched.
	if raw := r.URL.Query().Get("actor"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			return ListFilter{}, errs.ErrBadRequest.WithDetail("invalid actor")
		}
		f.ActorID = id
	}
	if raw := r.URL.Query().Get("subject"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			return ListFilter{}, errs.ErrBadRequest.WithDetail("invalid subject")
		}
		f.Subject = &id
	}
	for name, at := range map[string]**time.Time{"from": &f.From, "to": &f.To} {
		if raw := r.URL.Query().Get(name); raw != "" {
			t, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				return ListFilter{}, errs.ErrBadRequest.WithDetail(name + " must be an RFC 3339 time")
			}
			*at = &t
		}
	}
	return f, nil
}

// The severities and categories activity gives an action.
var (
	severities = []string{SeverityInfo, SeveritySuccess, SeverityWarning, SeverityError, SeverityCritical}
	categories = []string{CategoryAuthentication, CategoryAuthorization, CategorySecurity, CategoryDirectory, CategoryDeveloper, CategorySystem}
)

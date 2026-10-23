package tenant

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/identity/tenant/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// EligibleOrganization is an organisation a person may switch to.
type EligibleOrganization struct {
	ID         uuid.UUID  `json:"id"`
	Name       string     `json:"name"`
	Slug       string     `json:"slug"`
	Plan       string     `json:"plan"`
	Region     string     `json:"region"`
	LogoURL    string     `json:"logo_url"`
	Domain     string     `json:"domain"`
	Roles      []string   `json:"roles"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

// OrganizationSelectionPage is one page of eligible organisations.
type OrganizationSelectionPage struct {
	Items      []EligibleOrganization `json:"items"`
	NextCursor string                 `json:"next_cursor"`
}

// EligibleOrganizations returns one page of the organisations the user may
// switch to from the current session.
func (r *Repository) EligibleOrganizations(ctx context.Context, userID, currentSessionID uuid.UUID, limit int, cursor string) (OrganizationSelectionPage, error) {
	page := OrganizationSelectionPage{Items: []EligibleOrganization{}}
	if limit < 1 || limit > 200 {
		return page, errs.ErrBadRequest.WithDetail("limit must be between 1 and 200")
	}
	after := uuid.Nil
	if cursor != "" {
		var err error
		after, err = uuid.Parse(cursor)
		if err != nil {
			return page, errs.ErrBadRequest.WithDetail("invalid organization cursor")
		}
	}
	rows, err := r.q.ListEligibleOrganizations(ctx, dbgen.ListEligibleOrganizationsParams{
		UserID: userID, CurrentSessionID: currentSessionID, AfterID: after, RowLimit: int32(limit + 1),
	})
	if err != nil {
		return page, err
	}
	if len(rows) > limit {
		page.NextCursor = rows[limit-1].ID.String()
		rows = rows[:limit]
	}
	for _, row := range rows {
		organization := EligibleOrganization{
			ID: row.ID, Name: row.Name, Slug: row.Slug, Plan: row.Plan, Region: row.Region,
			LogoURL: row.LogoUrl, Domain: row.Domain, Roles: row.Roles,
		}
		if !row.LastUsedAt.IsZero() {
			lastUsed := row.LastUsedAt
			organization.LastUsedAt = &lastUsed
		}
		page.Items = append(page.Items, organization)
	}
	return page, nil
}

func (h *Handler) eligibleOrganizations(w http.ResponseWriter, r *http.Request) {
	principal := httpx.PrincipalFromCtx(r.Context())
	if principal == nil || principal.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		var err error
		limit, err = strconv.Atoi(raw)
		if err != nil {
			httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid limit"))
			return
		}
	}
	currentSession := uuid.Nil
	if principal.SessionID != nil {
		currentSession = *principal.SessionID
	}
	// The picker lists every organisation the person belongs to, not only the
	// one they're signed in to.
	page, err := h.Repo.EligibleOrganizations(postgres.AcrossTenants(r.Context()), *principal.UserID, currentSession, limit, r.URL.Query().Get("cursor"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, page)
}

package organization

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/identity/organization/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// EligibleOrganization is an organization a person may switch to.
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

// eligibleLimit is the page size of the organization picker, by default and
// at most: a person belongs to few organizations, so one page usually shows all.
const eligibleLimit = 200

// EligibleOrganizations returns one page of the organizations the user may
// switch to from the current session, in id order after the cursor (an
// organization id, "" for the first page), and the next page's cursor.
func (r *Repository) EligibleOrganizations(ctx context.Context, userID, currentSessionID uuid.UUID, limit int, cursor string) (paging.Result[EligibleOrganization], error) {
	limit = paging.Clamp(limit, eligibleLimit, eligibleLimit)
	after := uuid.Nil
	if cursor != "" {
		var err error
		after, err = uuid.Parse(cursor)
		if err != nil {
			return paging.Result[EligibleOrganization]{}, errs.ErrBadRequest.WithDetail("invalid organization cursor")
		}
	}
	rows, err := r.q.ListEligibleOrganizations(ctx, dbgen.ListEligibleOrganizationsParams{
		UserID: userID, CurrentSessionID: currentSessionID, AfterID: after, RowLimit: int32(limit + 1), // #nosec G115 -- clamped to at most eligibleLimit
	})
	if err != nil {
		return paging.Result[EligibleOrganization]{}, err
	}
	var next string
	if len(rows) > limit {
		next = rows[limit-1].ID.String()
		rows = rows[:limit]
	}
	items := make([]EligibleOrganization, 0, len(rows))
	for _, row := range rows {
		roles := row.Roles
		if roles == nil {
			roles = []string{} // an organization's own account may hold no role there
		}
		organization := EligibleOrganization{
			ID: row.ID, Name: row.Name, Slug: row.Slug, Plan: row.Plan, Region: row.Region,
			LogoURL: row.LogoUrl, Domain: row.Domain, Roles: roles,
		}
		if !row.LastUsedAt.IsZero() {
			lastUsed := row.LastUsedAt
			organization.LastUsedAt = &lastUsed
		}
		items = append(items, organization)
	}
	return paging.Page(items, next), nil
}

func (h *Handler) eligibleOrganizations(w http.ResponseWriter, r *http.Request) {
	principal := httpx.PrincipalFromCtx(r.Context())
	if principal == nil || principal.UserID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized)
		return
	}
	limit := paging.Limit(r.URL.Query(), eligibleLimit, eligibleLimit)
	currentSession := uuid.Nil
	if principal.SessionID != nil {
		currentSession = *principal.SessionID
	}
	// The picker lists every organization the person belongs to, not only the
	// one they're signed in to.
	page, err := h.Repo.EligibleOrganizations(postgres.AcrossOrganizations(r.Context()), *principal.UserID, currentSession, limit, r.URL.Query().Get("cursor"))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, page)
}

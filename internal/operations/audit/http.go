package audit

import (
	"net/http"
	"net/netip"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
	"github.com/qeetgroup/qeet-id-server/internal/platform/strutil"
)

// Handler serves the audit log endpoints.
type Handler struct {
	Reader   *Reader
	Verifier *Verifier
}

// Mount registers the authenticated audit routes.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/organizations/{organizationID}/audit", h.list)
	r.Get("/organizations/{organizationID}/audit/verify", h.verify)
	r.Get("/organizations/{organizationID}/audit/verification", h.lastVerification)
}

// MountPublic registers GET /audit/verify, an unauthenticated check of the
// platform audit chains, so anyone can confirm they are intact. Organization chains are
// verified only behind auth, in Mount.
func (h *Handler) MountPublic(r chi.Router) {
	r.Get("/audit/verify", h.verifyPublic)
}

// publicVerifyResult is verifyPublic's deliberately minimal result: whether the
// platform chains are intact, with no organization data or row identifiers.
type publicVerifyResult struct {
	ChainValid  bool `json:"chain_valid"`
	RowsChecked int  `json:"rows_checked"`
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	query := r.URL.Query()
	filter := ListFilter{
		Actions:       strutil.SplitList(query.Get("action")),
		ResourceTypes: strutil.SplitList(query.Get("resource_type")),
		Search:        query.Get("q"),
	}
	if raw := query.Get("actor_user_id"); raw != "" {
		actorID, err := uuid.Parse(raw)
		if err != nil {
			httpx.WriteError(w, r, ErrActorIDInvalid)
			return
		}
		filter.ActorUserID = actorID
	}
	if raw := query.Get("resource_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid resource_id"))
			return
		}
		filter.ResourceID = &id
	}
	if raw := query.Get("ip"); raw != "" {
		addr, err := netip.ParseAddr(raw)
		if err != nil {
			httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid ip"))
			return
		}
		filter.IP = &addr
	}
	for name, bound := range map[string]**time.Time{"from": &filter.From, "to": &filter.To} {
		if raw := query.Get(name); raw != "" {
			at, err := time.Parse(time.RFC3339, raw)
			if err != nil {
				httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("invalid "+name))
				return
			}
			*bound = &at
		}
	}
	out, next, total, err := h.Reader.List(r.Context(), tid, paging.Limit(query, 50, 200), query.Get("cursor"), filter)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, listPage{
		Result:      paging.Page(out, next),
		Total:       min(total, MaxCounted),
		TotalCapped: total > MaxCounted,
	})
}

// listPage is a page of the audit log, with how many rows match: Total, up to
// MaxCounted, and TotalCapped when more do.
type listPage struct {
	paging.Result[Row]
	Total       int  `json:"total"`
	TotalCapped bool `json:"total_capped"`
}

func (h *Handler) verify(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	res, err := h.Verifier.Verify(r.Context(), &tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// lastVerification serves GET /organizations/{organizationID}/audit/verification: how the
// scheduled verification last left the organization's chain, read, not walked.
func (h *Handler) lastVerification(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	res, err := h.Verifier.LastVerification(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// verifyPublic verifies the platform audit chains (rows with a NULL organization_id)
// and returns only whether they are intact and how many rows were checked.
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

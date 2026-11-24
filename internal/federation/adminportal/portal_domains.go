package adminportal

import (
	"net/http"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

func (h *Handler) domainList(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilityDomainVerification)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out, err := h.Domains.List(r.Context(), l.OrganizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

// domainAdd claims a domain for the organization and answers with the DNS record to
// publish, as the admin API does.
func (h *Handler) domainAdd(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilityDomainVerification)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		Domain string `json:"domain"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	d, err := h.Domains.Add(r.Context(), l.OrganizationID, in.Domain, portalActor(l, r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, d)
}

// domainVerify checks the DNS record of the organization's domain, as the admin API
// does: a domain another organization verified stays theirs.
func (h *Handler) domainVerify(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilityDomainVerification)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrIDInvalid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	d, err := h.Domains.Verify(r.Context(), id, l.OrganizationID, portalActor(l, r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, d)
}

// domainUpdate turns single sign-on on or off for one of the organization's verified domains, so
// its people are sent to the identity provider the link is setting up (the guided setup's last
// step). It needs both domain verification and SAML in the link, and touches no other setting.
func (h *Handler) domainUpdate(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilityDomainVerification)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if !l.Has(CapabilitySAML) {
		httpx.WriteError(w, r, ErrCapabilityNotGranted)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrIDInvalid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in struct {
		SSOEnabled *bool `json:"sso_enabled"`
	}
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.SSOEnabled == nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("sso_enabled is required"))
		return
	}
	d, err := h.Domains.UpdateSettings(r.Context(), id, l.OrganizationID, in.SSOEnabled, nil, portalActor(l, r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, d)
}

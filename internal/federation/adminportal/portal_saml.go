package adminportal

import (
	"net/http"
	"strings"

	"github.com/qeetgroup/qeet-id-server/internal/federation/identitylink"
	"github.com/qeetgroup/qeet-id-server/internal/federation/saml"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// portalConnection is a SAML connection as the portal shows it: with the
// addresses the IT admin enters at their IdP.
type portalConnection struct {
	saml.Connection
	saml.SPAddresses
}

func (h *Handler) withAddresses(r *http.Request, c *saml.Connection) portalConnection {
	return portalConnection{Connection: *c, SPAddresses: saml.Addresses(h.origin(r), c.ID)}
}

func (h *Handler) samlList(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilitySAML)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	conns, err := h.SAML.List(r.Context(), l.OrganizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out := make([]portalConnection, len(conns))
	for i := range conns {
		out[i] = h.withAddresses(r, &conns[i])
	}
	httpx.WriteJSON(w, http.StatusOK, paging.List(out))
}

func (h *Handler) samlCreate(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilitySAML)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in saml.CreateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.IdpEntityID = strings.TrimSpace(in.IdpEntityID)
	in.IdpSSOURL = strings.TrimSpace(in.IdpSSOURL)
	// A name alone makes a draft, whose addresses go to the IdP before its details come back (the
	// guided setup's order); any detail given brings the rest with it, as on the console.
	if in.Name == "" || (!in.AwaitsIdP() && (in.IdpEntityID == "" || in.IdpSSOURL == "" || strings.TrimSpace(in.IdpCertificate) == "")) {
		httpx.WriteError(w, r, ErrSAMLFieldsRequired)
		return
	}
	ctx := r.Context()
	if err := h.SAML.RequireSSO(ctx, l.OrganizationID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	conn, err := h.SAML.Create(ctx, l.OrganizationID, in, portalActor(l, r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, h.withAddresses(r, conn))
}

func (h *Handler) samlGet(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilitySAML)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrIDInvalid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	conn, err := h.SAML.Get(r.Context(), id, l.OrganizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.withAddresses(r, conn))
}

func (h *Handler) samlUpdate(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilitySAML)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrIDInvalid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in saml.UpdateInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.Status != nil && *in.Status != "draft" && *in.Status != "active" && *in.Status != "disabled" {
		httpx.WriteError(w, r, ErrSAMLStatusInvalid)
		return
	}
	ctx := r.Context()
	// A portal session is no person who could outrank anyone, so it changes
	// what a connection trusts only while no administrator is linked to it.
	current, err := h.SAML.Get(ctx, id, l.OrganizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.ChangesTrust(current) {
		if err := identitylink.CheckTrustChange(ctx, h.SAML.Pool(), nil, nil, l.OrganizationID, id, ""); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}
	conn, err := h.SAML.Update(ctx, id, l.OrganizationID, in, portalActor(l, r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.withAddresses(r, conn))
}

func (h *Handler) samlTest(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilitySAML)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrIDInvalid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	res, err := h.SAML.TestConnection(r.Context(), id, l.OrganizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// samlTestSignInBegin starts a test sign-in through a connection in this
// browser: it answers with the IdP address to send the browser to, and the
// IdP's answer returns the browser to the portal page to read the result.
func (h *Handler) samlTestSignInBegin(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilitySAML)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrIDInvalid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	test, err := h.SAMLSignIn.BeginTestSignIn(w, r, l.OrganizationID, id, h.Service.PortalURL(), portalActor(l, r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, test)
}

func (h *Handler) samlTestSignInGet(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilitySAML)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrIDInvalid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	testID, err := httpx.PathUUID(r, "testID", ErrIDInvalid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	test, err := h.SAML.TestSignIn(r.Context(), testID, id, l.OrganizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, test)
}

func (h *Handler) samlDelete(w http.ResponseWriter, r *http.Request) {
	l, err := h.resolve(r, CapabilitySAML)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrIDInvalid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.SAML.Delete(r.Context(), id, l.OrganizationID, portalActor(l, r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

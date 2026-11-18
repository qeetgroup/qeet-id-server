package authpolicy

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Handler serves the authentication policy HTTP API.
type Handler struct {
	Service *Service
}

// Mount registers the authentication policy routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/organizations/{organizationID}/auth-policy", h.get)
	r.Get("/organizations/{organizationID}/auth-policy/usage", h.usage)
	r.Put("/organizations/{organizationID}/auth-policy", h.update)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	p, err := h.Service.Get(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

// usage serves GET /organizations/{organizationID}/auth-policy/usage.
func (h *Handler) usage(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	u, err := h.Service.Usage(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
}

func (h *Handler) update(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in Policy
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	p, err := h.Service.Update(r.Context(), organizationID, in, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

// policyUpdate is the body of PUT /organizations/{id}/policy. Address rules are the
// only address control: empty ip_allowlist and ip_denylist are accepted, but
// entries are refused, so nobody believes a list protects them.
type policyUpdate struct {
	SecurityPolicy
	IPAllowlist []string `json:"ip_allowlist"`
	IPDenylist  []string `json:"ip_denylist"`
}

func (u policyUpdate) retiredFields() []errs.FieldError {
	var bad []errs.FieldError
	for name, list := range map[string][]string{"ip_allowlist": u.IPAllowlist, "ip_denylist": u.IPDenylist} {
		if len(list) > 0 {
			bad = append(bad, errs.FieldError{Field: name, Code: "retired",
				Message: "The security policy no longer holds IP lists. Add address rules instead (Security → Address rules)."})
		}
	}
	return bad
}

// SecurityPolicyHandler serves the security policy HTTP API.
type SecurityPolicyHandler struct {
	Repo *SecurityPolicies
}

// Mount registers the security policy routes on r.
func (h *SecurityPolicyHandler) Mount(r chi.Router) {
	r.Get("/organizations/{organizationID}/policy", h.get)
	r.Put("/organizations/{organizationID}/policy", h.put)
	r.Patch("/organizations/{organizationID}/policy", h.patch)
}

func (h *SecurityPolicyHandler) get(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	p, err := h.Repo.Get(r.Context(), tid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

func (h *SecurityPolicyHandler) put(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var body policyUpdate
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if bad := body.retiredFields(); len(bad) > 0 {
		httpx.WriteError(w, r, errs.ErrValidationFailed.WithFields(bad))
		return
	}
	p, err := h.Repo.Replace(r.Context(), tid, body.SecurityPolicy, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

// patch serves PATCH /organizations/{organizationID}/policy: it changes only the fields
// sent, over the stored policy, under the policy's lock, so saving one rule
// keeps another saved meanwhile. A null clears a nullable field.
func (h *SecurityPolicyHandler) patch(w http.ResponseWriter, r *http.Request) {
	tid, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	p, err := h.Repo.Patch(r.Context(), tid, func(current *SecurityPolicy) error {
		// Decoding over the stored policy changes only the fields the body names.
		body := policyUpdate{SecurityPolicy: *current}
		if err := httpx.DecodeJSON(r, &body); err != nil {
			return err
		}
		if bad := body.retiredFields(); len(bad) > 0 {
			return errs.ErrValidationFailed.WithFields(bad)
		}
		*current = body.SecurityPolicy
		return nil
	}, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, p)
}

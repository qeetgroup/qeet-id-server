package social

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/identitylink"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// Handler serves the social endpoints. CookieSecure marks the SSO and binding
// cookies Secure. LoginBaseURL is the hosted login's origin, where browser
// failures go with a generic error code. PublicBaseURL is this API's public
// origin, or "" to build callback URLs from the request's Host.
type Handler struct {
	Service       *Service
	CookieSecure  bool
	LoginBaseURL  string
	PublicBaseURL string
	// ActOnCheck lets a change of where an OpenID Connect provider finds its
	// keys and claims through only for a caller who outranks every
	// administrator linked to it (rbac CheckActOn). Without it the change is
	// refused while one is linked.
	ActOnCheck identitylink.ActOn
}

// Mount registers the social sign-in routes on r.
func (h *Handler) Mount(r chi.Router) {
	r.Post("/social/providers", h.upsertProvider)
	r.Patch("/social/providers/{provider}", h.updateProvider)
	r.Delete("/social/providers/{provider}", h.deleteProvider)
	r.Get("/organizations/{organizationID}/social/providers", h.listProviders)
	r.Get("/users/{userID}/social/identities", h.listIdentities)
	r.Delete("/social/identities/{id}", h.unlink)
	// Self-service (organization-independent): manage the social logins on my own
	// account, so a user who signed up via Google can see/unlink it pre-org.
	r.Get("/me/social/identities", h.listMyIdentities)
	r.Delete("/me/social/identities/{id}", h.unlinkMine)
	// Authenticated "connect this provider to my account" — returns the provider
	// authorize URL for the browser to navigate to. The callback links the
	// identity to the caller (never creates/switches accounts).
	r.Post("/social/{provider}/link/start", h.linkStart)
	r.Post("/social/link/complete", h.linkComplete)
}

// MountPublic mounts the browser-facing OAuth ceremony, which carries no JWT.
func (h *Handler) MountPublic(r chi.Router) {
	r.Get("/social/{provider}/start", h.start)
	r.Get("/social/{provider}/callback", h.callback)
	r.Post("/social/{provider}/callback", h.callback) // Apple response_mode=form_post
	r.Post("/social/exchange", h.exchange)
	// Which platform (organization-less) providers are configured — lets the console
	// enable only the social buttons that will actually work.
	r.Get("/social/platform/providers", h.platformProviders)
}

// redirectSocialError sends a failed browser-facing ceremony back to the hosted
// login with a generic error code, never the detail, keeping the request's
// return_to so the person can retry. Without LoginBaseURL it writes the error
// as JSON.
func (h *Handler) redirectSocialError(w http.ResponseWriter, r *http.Request, err error) {
	if h.LoginBaseURL == "" {
		// No hosted login app configured — fall back to the JSON error.
		httpx.WriteError(w, r, err)
		return
	}
	q := url.Values{"error": {"social"}}
	// A suspended or deleted account is told so, as at password sign-in, and
	// one that can't be adopted yet is told to verify its address.
	switch {
	case errors.Is(err, errs.ErrAuthAccountInactive):
		q.Set("error", "account_inactive")
	case errors.Is(err, ErrAccountUnverified):
		q.Set("error", "account_unverified")
	}
	if rt := r.URL.Query().Get("return_to"); rt != "" {
		q.Set("return_to", rt)
	}
	http.Redirect(w, r, h.LoginBaseURL+"/sign-in?"+q.Encode(), http.StatusFound)
}

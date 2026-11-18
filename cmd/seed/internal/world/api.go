package world

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// API is the server's own handlers, called in process as a signed-in person,
// so validation, audit records and side effects are those of a console
// request. The router's permission checks are not applied: the seed chooses
// actors who hold the permission.
type API struct {
	w      *World
	router chi.Router
}

// mounter is a handler that registers its routes.
type mounter interface{ Mount(chi.Router) }

func newAPI(w *World) *API {
	r := chi.NewRouter()
	r.Use(chimw.RequestID, httpx.ClientIPContext)
	d := w.Deps
	for _, h := range []mounter{d.Organization, d.User, d.Branding, d.EmailTemplate, d.Policy, d.AuthPolicy, d.Retention, d.OIDC, d.SAML,
		d.LDAP, d.OIDCSSO, d.AdminPortal, d.SSOGroups, d.DomainVerify, d.Directory, d.SCIM, d.Principal, d.Webhook,
		d.Secret, d.RateLimits, d.IPAllow, d.AuditAnomaly} {
		h.Mount(r)
	}
	d.SCIM.MountPublic(r)
	return &API{w: w, router: r}
}

// Do sends method path with body (JSON) in o as actor, fails the seed unless
// it succeeds, and decodes the answer into out when out is not nil. A nil o
// is a request outside any organization.
func (a *API) Do(o *Org, actor *Person, method, path string, body, out any) {
	id := actor.ID
	p := &httpx.Principal{UserID: &id, ActorType: "user"}
	what := method + " " + path
	if o != nil {
		organization := o.ID
		p.OrganizationID, what = &organization, what+" in "+o.Spec.Slug
	}
	req := a.request(method, path, body, "application/json")
	req.RemoteAddr = actor.Device.IP + ":52114"
	req.Header.Set("User-Agent", actor.Device.UserAgent)
	a.send(req.WithContext(httpx.WithPrincipal(a.w.Ctx, p)), out, what)
}

// SCIM sends a SCIM request as an identity provider holding token.
func (a *API) SCIM(token, userAgent, method, path string, body, out any) {
	req := a.request(method, "/scim/v2"+path, body, "application/scim+json")
	req.RemoteAddr = "198.51.100.235:44310"
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", userAgent)
	a.send(req.WithContext(a.w.Ctx), out, "SCIM "+method+" "+path)
}

func (a *API) request(method, path string, body any, contentType string) *http.Request {
	var in io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		Must(err, "encode "+method+" "+path)
		in = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, in)
	req.Header.Set("Content-Type", contentType)
	return req
}

func (a *API) send(req *http.Request, out any, what string) {
	rec := httptest.NewRecorder()
	a.router.ServeHTTP(rec, req)
	if rec.Code >= http.StatusMultipleChoices {
		Must(fmt.Errorf("%d %s", rec.Code, rec.Body.String()), what)
	}
	if out != nil {
		Must(json.Unmarshal(rec.Body.Bytes(), out), "decode "+what)
	}
}

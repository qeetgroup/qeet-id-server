package accounts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// api is the API's own handlers, called in process as a signed-in
// administrator, so validation, audit rows and side effects are the ones a
// console request produces. Permission checks are the router's and are not
// applied: the seed chooses actors who hold the permission.
type api struct {
	w      *world.World
	router chi.Router
}

func newAPI(w *world.World) *api {
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	d := w.Deps
	d.User.Mount(r)
	d.Branding.Mount(r)
	d.EmailTemplate.Mount(r)
	d.Policy.Mount(r)
	d.AuthPolicy.Mount(r)
	d.Retention.Mount(r)
	return &api{w: w, router: r}
}

// do sends a request in o as actor and fails the seed unless it succeeds. A
// nil actor is the platform itself; actorType then names it ("system", "scim",
// "ldap"). It returns the response body.
func (a *api) do(o *world.Org, actor *world.Person, actorType, method, path string, body any) []byte {
	var in io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		world.Must(err, "encode "+method+" "+path)
		in = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, in)
	req.Header.Set("Content-Type", "application/json")
	tenant := o.ID
	p := &httpx.Principal{TenantID: &tenant, ActorType: actorType}
	if actor != nil {
		id := actor.ID
		p.UserID, p.ActorType = &id, "user"
		req.RemoteAddr = actor.Device.IP + ":52114"
		req.Header.Set("User-Agent", actor.Device.UserAgent)
	} else {
		req.RemoteAddr = "10.0.0.1:443"
	}
	req = req.WithContext(httpx.WithPrincipal(a.w.Ctx, p))
	rec := httptest.NewRecorder()
	a.router.ServeHTTP(rec, req)
	if rec.Code >= http.StatusMultipleChoices {
		world.Must(fmt.Errorf("%d %s", rec.Code, rec.Body.String()), method+" "+path+" in "+o.Spec.Slug)
	}
	return rec.Body.Bytes()
}

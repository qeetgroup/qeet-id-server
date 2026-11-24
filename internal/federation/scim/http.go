package scim

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

// Handler serves the SCIM admin endpoints and the /scim/v2 protocol.
// PublicBaseURL is this API's public origin, or "" to build resource locations
// from the request's Host.
type Handler struct {
	Service       *Service
	PublicBaseURL string
}

// Mount registers the admin endpoints under the authenticated /v1 group.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/organizations/{organizationID}/scim", h.config)
	r.Get("/organizations/{organizationID}/scim/users", h.adminListUsers)
	r.Get("/organizations/{organizationID}/scim/groups", h.adminListGroups)
	r.Post("/organizations/{organizationID}/scim/token", h.rotate)
	r.Delete("/organizations/{organizationID}/scim/token", h.revoke)
	r.Get("/organizations/{organizationID}/scim/tokens", h.listTokens)
	r.Post("/organizations/{organizationID}/scim/tokens", h.createToken)
	r.Post("/organizations/{organizationID}/scim/tokens/{id}/rotate", h.rotateToken)
	r.Delete("/organizations/{organizationID}/scim/tokens/{id}", h.revokeToken)
}

// MountPublic registers the SCIM 2.0 protocol surface at the root, guarded
// by the per-organization bearer token rather than the user-JWT middleware.
func (h *Handler) MountPublic(r chi.Router) {
	r.Route("/scim/v2", func(r chi.Router) {
		r.Use(h.scimAuth)
		r.Get("/ServiceProviderConfig", h.serviceProviderConfig)
		r.Get("/ResourceTypes", h.resourceTypes)
		r.Get("/Schemas", h.schemas)
		r.Get("/Users", h.listUsers)
		r.Post("/Users", h.createUser)
		r.Get("/Users/{id}", h.getUser)
		r.Put("/Users/{id}", h.replaceUser)
		r.Patch("/Users/{id}", h.patchUser)
		r.Delete("/Users/{id}", h.deleteUser)
		r.Get("/Groups", h.listGroups)
		r.Post("/Groups", h.createGroup)
		r.Get("/Groups/{id}", h.getGroup)
		r.Put("/Groups/{id}", h.replaceGroup)
		r.Patch("/Groups/{id}", h.patchGroup)
		r.Delete("/Groups/{id}", h.deleteGroup)
	})
}

type ctxKey int

const organizationCtxKey ctxKey = iota

func (h *Handler) scimAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr := r.Header.Get("Authorization")
		if !strings.HasPrefix(hdr, "Bearer ") {
			writeSCIMErr(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		raw := strings.TrimSpace(strings.TrimPrefix(hdr, "Bearer "))
		tid, err := h.Service.resolveToken(r.Context(), raw)
		if err != nil {
			writeSCIMErr(w, http.StatusUnauthorized, "invalid SCIM token")
			return
		}
		// The plan is checked on every request, not only when the token was
		// issued, so a token from a plan that has since lapsed provisions nothing.
		allowed, err := h.Service.planIncludesSCIM(r.Context(), tid)
		if err != nil {
			slog.Error("scim: plan check", "err", err, "organization_id", tid)
			writeSCIMErr(w, http.StatusInternalServerError, "the organization's plan could not be checked")
			return
		}
		if !allowed {
			writeSCIMErr(w, http.StatusForbidden, "the organization's plan does not include SCIM provisioning")
			return
		}
		ctx := context.WithValue(r.Context(), organizationCtxKey, tid)
		h.observeMutations(next).ServeHTTP(w, r.WithContext(ctx))
	})
}

func organizationFromCtx(ctx context.Context) (uuid.UUID, bool) {
	tid, ok := ctx.Value(organizationCtxKey).(uuid.UUID)
	return tid, ok
}

func writeSCIM(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", scimContentType)
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Warn("scim: encode response", "err", err, "status", status)
	}
}

func writeSCIMErr(w http.ResponseWriter, status int, detail string) {
	writeSCIM(w, status, map[string]any{
		"schemas": []string{schemaError},
		"status":  strconv.Itoa(status),
		"detail":  detail,
	})
}

func writeSCIMTypedErr(w http.ResponseWriter, status int, scimType, detail string) {
	noteReason(w, scimType)
	writeSCIM(w, status, map[string]any{
		"schemas":  []string{schemaError},
		"status":   strconv.Itoa(status),
		"scimType": scimType,
		"detail":   detail,
	})
}

// BaseURL returns the SCIM 2.0 base URL an IdP provisions to, on origin, the
// API's public origin.
func BaseURL(origin string) string { return origin + "/scim/v2" }

// location returns the absolute URL of the SCIM endpoint at suffix, a path
// under /scim/v2.
func (h *Handler) location(r *http.Request, suffix string) string {
	return BaseURL(httpx.PublicOrigin(r, h.PublicBaseURL)) + suffix
}

var equalityFilterPattern = regexp.MustCompile(`(?i)^([A-Za-z][A-Za-z0-9._-]*)\s+eq\s+("(?:[^"\\]|\\.)*")$`)

// parseEqualityFilter accepts exactly one quoted-string equality expression
// on the expected attribute. Empty input means no filter; every other
// unsupported/malformed expression is an RFC 7644 invalidFilter error.
func parseEqualityFilter(filter, attribute string) (string, error) {
	f := strings.TrimSpace(filter)
	if f == "" {
		return "", nil
	}
	matches := equalityFilterPattern.FindStringSubmatch(f)
	if len(matches) != 3 || !strings.EqualFold(matches[1], attribute) {
		return "", errors.New("unsupported or malformed SCIM filter")
	}
	value, err := strconv.Unquote(matches[2])
	if err != nil || value == "" {
		return "", errors.New("unsupported or malformed SCIM filter")
	}
	return value, nil
}

// listWindow reads a SCIM list request's startIndex (1-based, at least 1) and
// count (defaultPageCount when absent or below 1, at most maxPageCount).
func listWindow(r *http.Request) (start, count int) {
	q := r.URL.Query()
	start, _ = strconv.Atoi(q.Get("startIndex"))
	count, _ = strconv.Atoi(q.Get("count"))
	return max(start, 1), paging.Clamp(count, defaultPageCount, maxPageCount)
}

// scimTarget pulls the organization from context and the {id} path param,
// writing a SCIM error and returning ok=false on failure.
func (h *Handler) scimTarget(w http.ResponseWriter, r *http.Request) (uuid.UUID, uuid.UUID, bool) {
	tid, ok := organizationFromCtx(r.Context())
	if !ok {
		writeSCIMErr(w, http.StatusUnauthorized, "no organization")
		return uuid.Nil, uuid.Nil, false
	}
	id, err := httpx.PathUUID(r, "id", errs.ErrBadRequest)
	if err != nil {
		writeSCIMErr(w, http.StatusBadRequest, "invalid id")
		return uuid.Nil, uuid.Nil, false
	}
	return tid, id, true
}

// decodeSCIMBody decodes a request body capped at httpx.MaxJSONBodyBytes,
// writing a SCIM error and returning false on failure. SCIM can't use
// httpx.DecodeJSON because it needs SCIM-shaped errors.
func decodeSCIMBody(w http.ResponseWriter, r *http.Request, out any) bool {
	if r.ContentLength > httpx.MaxJSONBodyBytes {
		writeSCIMTypedErr(w, http.StatusRequestEntityTooLarge, "tooLarge", "Request body is too large.")
		return false
	}
	limited := http.MaxBytesReader(w, r.Body, httpx.MaxJSONBodyBytes)
	if err := json.NewDecoder(limited).Decode(out); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeSCIMTypedErr(w, http.StatusRequestEntityTooLarge, "tooLarge", "Request body is too large.")
			return false
		}
		writeSCIMErr(w, http.StatusBadRequest, "invalid JSON")
		return false
	}
	return true
}

// scimRefusal is a refused SCIM request: the status, scimType ("" for none)
// and detail of its SCIM error.
type scimRefusal struct {
	status           int
	scimType, detail string
}

func (e *scimRefusal) Error() string { return e.detail }

// refusal returns the scimRefusal of status, scimType and detail.
func refusal(status int, scimType, detail string) error {
	return &scimRefusal{status: status, scimType: scimType, detail: detail}
}

// writeRefusal writes err's SCIM error, or a 500 for an error that isn't a
// scimRefusal.
func writeRefusal(w http.ResponseWriter, err error) {
	var ref *scimRefusal
	switch {
	case !errors.As(err, &ref):
		writeSCIMErr(w, http.StatusInternalServerError, "internal error")
	case ref.scimType != "":
		writeSCIMTypedErr(w, ref.status, ref.scimType, ref.detail)
	default:
		writeSCIMErr(w, ref.status, ref.detail)
	}
}

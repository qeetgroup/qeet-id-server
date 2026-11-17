// Package scim implements SCIM 2.0 (RFC 7643/7644) provisioning, so IdPs such
// as Okta and Entra ID can push and deprovision users and groups. The protocol
// is served at /scim/v2 behind a per-organization bearer token managed under /v1.
// Provisioned users are ordinary organization users tagged provisioned_via='scim'.
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
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	auth "github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/identitylink"
	"github.com/qeetgroup/qeet-id-server/internal/federation/scim/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres/pgxerr"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/paging"
)

const (
	tokenPrefix      = "qf_scim_" // #nosec G101 -- token prefix, not a secret
	provisionedScim  = "scim"
	schemaUser       = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaListResp   = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	schemaError      = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimContentType  = "application/scim+json"
	defaultPageCount = 100
	maxPageCount     = 200
)

// Service manages SCIM tokens and provisioned users and groups. A nil signals
// announces no ended sessions; a nil gate leaves token rotation and SCIM
// requests ungated, and nil seats leaves group membership uncapped.
type Service struct {
	signals  *sessionsignal.Signaller
	pool     *pgxpool.Pool
	q        *dbgen.Queries
	users    *user.Repository
	observer OperationObserver
	mapper   ProfileMapper
	gate     PlanGate
	seats    SeatGuard
}

// SeatGuard keeps the people holding a role in an organization within its plan's
// seats; joining a group that carries a role takes one. Satisfied by
// *invite.Service.
type SeatGuard interface {
	// SeatLimit returns the organization's seat cap, negative for none; it reads on
	// the pool, so it is asked before the transaction.
	SeatLimit(ctx context.Context, organizationID uuid.UUID) (int, error)
	// WithinSeats runs change in tx and refuses it when it gives someone a
	// first role beyond limit.
	WithinSeats(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, limit int, change func() error) error
}

// SetSeatGuard wires the seat limit on group membership (nil disables it).
func (s *Service) SetSeatGuard(g SeatGuard) { s.seats = g }

// seatLimit returns the organization's seat cap, or -1 without a seat guard.
func (s *Service) seatLimit(ctx context.Context, organizationID uuid.UUID) (int, error) {
	if s.seats == nil {
		return -1, nil
	}
	return s.seats.SeatLimit(ctx, organizationID)
}

// withinSeats runs change in tx through the seat guard, if there is one.
func (s *Service) withinSeats(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, limit int, change func() error) error {
	if s.seats == nil {
		return change()
	}
	return s.seats.WithinSeats(ctx, tx, organizationID, limit, change)
}

// SetSessionSignals sets where the sessions ended by a SCIM suspension are
// announced.
func (s *Service) SetSessionSignals(sig *sessionsignal.Signaller) { s.signals = sig }

// NewService returns the SCIM service.
func NewService(pool *pgxpool.Pool, users *user.Repository) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), users: users}
}

// PlanGate reports whether a plan-gated boolean feature is included in the
// organization's plan. Satisfied by *entitlements.Service.
type PlanGate interface {
	FeatureAllowed(ctx context.Context, organizationID uuid.UUID, feature string) (bool, error)
}

// SetPlanGate wires the plan-feature gate (nil allows all features).
func (s *Service) SetPlanGate(g PlanGate) { s.gate = g }

// planIncludesSCIM reports whether the organization's plan includes SCIM; with no
// gate set, every plan does.
func (s *Service) planIncludesSCIM(ctx context.Context, organizationID uuid.UUID) (bool, error) {
	if s.gate == nil {
		return true, nil
	}
	return s.gate.FeatureAllowed(ctx, organizationID, "scim")
}

// Pool returns the connection pool, for handlers that run their own transaction.
func (s *Service) Pool() *pgxpool.Pool { return s.pool }

// userRow is the SCIM read side (includes external_id, which user.User omits).
type userRow struct {
	ID          uuid.UUID
	Email       string
	DisplayName *string
	Status      string
	ExternalID  *string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

const userRowCols = `id, email, display_name, status, external_id, created_at, updated_at`

func (s *Service) getProvisioned(ctx context.Context, organizationID, id uuid.UUID) (*userRow, error) {
	r, err := s.q.GetProvisionedUser(ctx, dbgen.GetProvisionedUserParams{
		ID:             id,
		OrganizationID: pgtype.UUID{Bytes: organizationID, Valid: true},
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &userRow{
		ID:          r.ID,
		Email:       r.Email,
		DisplayName: r.DisplayName,
		Status:      r.Status,
		ExternalID:  r.ExternalID,
		CreatedAt:   r.CreatedAt,
		UpdatedAt:   r.UpdatedAt,
	}, nil
}

// listProvisioned lists the organization's directory-provisioned users. A
// userName lookup finds any account at home there, whoever created it, so an
// identity provider can match and link the people who are already members.
func (s *Service) listProvisioned(ctx context.Context, organizationID uuid.UUID, emailFilter string, start, count int) ([]userRow, int, error) {
	args := []any{organizationID}
	where := `organization_id = $1 AND deleted_at IS NULL`
	if emailFilter != "" {
		args = append(args, emailFilter)
		where += ` AND LOWER(email) = LOWER($2)`
	} else {
		args = append(args, provisionedScim)
		where += ` AND provisioned_via = $2`
	}

	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM account.users WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	args = append(args, count, start-1) // SCIM startIndex is 1-based
	rows, err := s.pool.Query(ctx, `
		SELECT `+userRowCols+` FROM account.users WHERE `+where+`
		ORDER BY created_at DESC, id DESC
		LIMIT $`+strconv.Itoa(len(args)-1)+` OFFSET $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []userRow
	for rows.Next() {
		var u userRow
		if err := rows.Scan(&u.ID, &u.Email, &u.DisplayName, &u.Status, &u.ExternalID, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, u)
	}
	return out, total, rows.Err()
}

func (s *Service) tagProvisionedTx(ctx context.Context, tx pgx.Tx, id uuid.UUID, externalID string) error {
	var ext *string
	if externalID != "" {
		ext = &externalID
	}
	return s.q.WithTx(tx).TagProvisionedUser(ctx, dbgen.TagProvisionedUserParams{
		ExternalID: ext,
		ID:         id,
	})
}

// Handler serves the SCIM admin endpoints and the /scim/v2 protocol.
// PublicBaseURL is this API's public origin, or "" to build resource locations
// from the request's Host.
type Handler struct {
	Service       *Service
	PublicBaseURL string
}

// Mount registers the admin endpoints under the authenticated /v1 group.
func (h *Handler) Mount(r chi.Router) {
	r.Get("/tenants/{tenantID}/scim", h.config)
	r.Get("/tenants/{tenantID}/scim/users", h.adminListUsers)
	r.Get("/tenants/{tenantID}/scim/groups", h.adminListGroups)
	r.Post("/tenants/{tenantID}/scim/token", h.rotate)
	r.Delete("/tenants/{tenantID}/scim/token", h.revoke)
	r.Get("/tenants/{tenantID}/scim/tokens", h.listTokens)
	r.Post("/tenants/{tenantID}/scim/tokens", h.createToken)
	r.Post("/tenants/{tenantID}/scim/tokens/{id}/rotate", h.rotateToken)
	r.Delete("/tenants/{tenantID}/scim/tokens/{id}", h.revokeToken)
}

// adminUser is the plain (non-SCIM-envelope) shape the admin console renders.
type adminUser struct {
	ID          uuid.UUID `json:"id"`
	Email       string    `json:"email"`
	DisplayName *string   `json:"display_name"`
	Status      string    `json:"status"`
	ExternalID  *string   `json:"external_id"`
	CreatedAt   time.Time `json:"created_at"`
}

// adminPage reads a console list's limit (1..200, default 50) and cursor.
func adminPage(r *http.Request) (int, time.Time, uuid.UUID, error) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > maxPageCount {
		limit = 50
	}
	before, beforeID := time.Now().Add(time.Hour), uuid.Max
	if cursor := r.URL.Query().Get("cursor"); cursor != "" {
		var err error
		if before, beforeID, err = paging.DecodeTimeUUID(cursor); err != nil {
			return 0, time.Time{}, uuid.Nil, errs.ErrBadRequest.WithDetail("invalid cursor")
		}
	}
	return limit, before, beforeID, nil
}

// adminListUsers returns a page of this organization's SCIM-provisioned users for the
// admin UI, newest first, with how many there are.
func (h *Handler) adminListUsers(w http.ResponseWriter, r *http.Request) {
	organizationID, err := requirePathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	limit, before, beforeID, err := adminPage(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	var total int
	if err := h.Service.pool.QueryRow(ctx, `SELECT count(*) FROM account.users WHERE organization_id = $1 AND deleted_at IS NULL AND provisioned_via = $2`,
		organizationID, provisionedScim).Scan(&total); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	rows, err := h.Service.pool.Query(ctx, `
		SELECT id, email, display_name, status, external_id, created_at FROM account.users
		WHERE organization_id = $1 AND deleted_at IS NULL AND provisioned_via = $2 AND (created_at, id) < ($3, $4)
		ORDER BY created_at DESC, id DESC LIMIT $5`, organizationID, provisionedScim, before, beforeID, limit+1)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer rows.Close()
	items := make([]adminUser, 0, limit+1)
	for rows.Next() {
		var u adminUser
		if err := rows.Scan(&u.ID, &u.Email, &u.DisplayName, &u.Status, &u.ExternalID, &u.CreatedAt); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		items = append(items, u)
	}
	if err := rows.Err(); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out := map[string]any{"total": total}
	if len(items) > limit {
		items = items[:limit]
		out["next_cursor"] = paging.EncodeTimeUUID(items[limit-1].CreatedAt, items[limit-1].ID)
	}
	out["items"] = items
	httpx.WriteJSON(w, http.StatusOK, out)
}

// adminGroup is a group SCIM made, as the console lists it.
type adminGroup struct {
	ID         uuid.UUID `json:"id"`
	Name       string    `json:"name"`
	ExternalID *string   `json:"external_id"`
	Members    int       `json:"members"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// adminListGroups returns a page of the groups this organization's SCIM made, newest
// first, each with its count of live members, and how many there are.
func (h *Handler) adminListGroups(w http.ResponseWriter, r *http.Request) {
	organizationID, err := requirePathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	limit, before, beforeID, err := adminPage(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	var total int
	if err := h.Service.pool.QueryRow(ctx, `SELECT count(*) FROM organization.groups WHERE organization_id = $1 AND provisioned_via = 'scim'`,
		organizationID).Scan(&total); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	rows, err := h.Service.pool.Query(ctx, `
		SELECT g.id, g.name, g.external_id, g.created_at, g.updated_at,
		       (SELECT count(*) FROM organization.group_members gm JOIN account.users u ON u.id = gm.user_id
		        WHERE gm.group_id = g.id AND gm.organization_id = g.organization_id AND u.deleted_at IS NULL)::int
		FROM organization.groups g
		WHERE g.organization_id = $1 AND g.provisioned_via = 'scim' AND (g.created_at, g.id) < ($2, $3)
		ORDER BY g.created_at DESC, g.id DESC LIMIT $4`, organizationID, before, beforeID, limit+1)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer rows.Close()
	items := make([]adminGroup, 0, limit+1)
	for rows.Next() {
		var g adminGroup
		if err := rows.Scan(&g.ID, &g.Name, &g.ExternalID, &g.CreatedAt, &g.UpdatedAt, &g.Members); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
		items = append(items, g)
	}
	if err := rows.Err(); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	out := map[string]any{"total": total}
	if len(items) > limit {
		items = items[:limit]
		out["next_cursor"] = paging.EncodeTimeUUID(items[limit-1].CreatedAt, items[limit-1].ID)
	}
	out["items"] = items
	httpx.WriteJSON(w, http.StatusOK, out)
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

// --- admin handlers ---

func requirePathOrganization(r *http.Request) (uuid.UUID, error) {
	return httpx.PathOrganizationOr(r, errs.ErrSCIMOrganizationIDInvalid, errs.ErrSCIMOrganizationMismatch)
}

func (h *Handler) config(w http.ResponseWriter, r *http.Request) {
	organizationID, err := requirePathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	cfg, err := h.Service.Config(r.Context(), organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, cfg)
}

func (h *Handler) rotate(w http.ResponseWriter, r *http.Request) {
	organizationID, err := requirePathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	issued, full, err := h.Service.replaceAll(ctx, tx, organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := audit.ActorOf(r).Identity()
	tid := organizationID
	if err := audit.Record(ctx, tx, audit.Event{
		OrganizationID: &tid,
		ActorUserID:    actorID,
		ActorType:      actorType,
		Action:         "scim.token_rotated",
		ResourceType:   "scim_token",
		ResourceID:     &issued.ID,
		IP:             httpx.ClientIP(r),
		UserAgent:      r.UserAgent(),
		RequestID:      httpx.RequestID(r),
		Metadata:       map[string]any{"name": issued.Name, "replaced": "all"},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	cfg, err := h.Service.Config(ctx, organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"token": full, "config": cfg})
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	organizationID, err := requirePathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	tx, err := h.Service.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	if err := h.Service.Revoke(ctx, tx, organizationID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := audit.ActorOf(r).Identity()
	tid := organizationID
	if err := audit.Record(ctx, tx, audit.Event{
		OrganizationID: &tid,
		ActorUserID:    actorID,
		ActorType:      actorType,
		Action:         "scim.token_revoked",
		ResourceType:   "scim_token",
		IP:             httpx.ClientIP(r),
		UserAgent:      r.UserAgent(),
		RequestID:      httpx.RequestID(r),
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- SCIM protocol auth + helpers ---

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
			slog.Error("scim: plan check", "err", err, "tenant_id", tid)
			writeSCIMErr(w, http.StatusInternalServerError, "the organisation's plan could not be checked")
			return
		}
		if !allowed {
			writeSCIMErr(w, http.StatusForbidden, "the organisation's plan does not include SCIM provisioning")
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

// toResource renders a user row as a SCIM core User.
func (h *Handler) toResource(r *http.Request, u *userRow) map[string]any {
	display := ""
	if u.DisplayName != nil {
		display = *u.DisplayName
	}
	res := map[string]any{
		"schemas":  []string{schemaUser},
		"id":       u.ID.String(),
		"userName": u.Email,
		"active":   u.Status == "active",
		"emails":   []map[string]any{{"value": u.Email, "primary": true, "type": "work"}},
		"meta": map[string]any{
			"resourceType": "User",
			"created":      u.CreatedAt.UTC().Format(time.RFC3339),
			"lastModified": u.UpdatedAt.UTC().Format(time.RFC3339),
			"location":     h.location(r, "/Users/"+u.ID.String()),
		},
	}
	if display != "" {
		res["displayName"] = display
		res["name"] = map[string]any{"formatted": display}
	}
	if u.ExternalID != nil && *u.ExternalID != "" {
		res["externalId"] = *u.ExternalID
	}
	return res
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

func parseUserNameFilter(filter string) (string, error) {
	return parseEqualityFilter(filter, "userName")
}

// --- SCIM /Users handlers ---

func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request) {
	tid, ok := organizationFromCtx(r.Context())
	if !ok {
		writeSCIMErr(w, http.StatusUnauthorized, "no tenant")
		return
	}
	start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
	if start < 1 {
		start = 1
	}
	count, err := strconv.Atoi(r.URL.Query().Get("count"))
	if err != nil || count <= 0 {
		count = defaultPageCount
	}
	if count > maxPageCount {
		count = maxPageCount
	}
	email, err := parseUserNameFilter(r.URL.Query().Get("filter"))
	if err != nil {
		writeSCIMTypedErr(w, http.StatusBadRequest, "invalidFilter", "Only userName eq \"value\" is supported.")
		return
	}

	rows, total, err := h.Service.listProvisioned(r.Context(), tid, email, start, count)
	if err != nil {
		writeSCIMErr(w, http.StatusInternalServerError, "list failed")
		return
	}
	resources := make([]map[string]any, 0, len(rows))
	for i := range rows {
		resources = append(resources, h.toResource(r, &rows[i]))
	}
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":      []string{schemaListResp},
		"totalResults": total,
		"startIndex":   start,
		"itemsPerPage": len(resources),
		"Resources":    resources,
	})
}

type scimUserPayload struct {
	Source      map[string]any `json:"-"`
	UserName    string         `json:"userName"`
	DisplayName string         `json:"displayName"`
	ExternalID  string         `json:"externalId"`
	Active      *bool          `json:"active"`
	Name        *scimName      `json:"name"`
	Emails      []scimEmail    `json:"emails"`
}

type scimName struct {
	Formatted  string `json:"formatted"`
	GivenName  string `json:"givenName"`
	FamilyName string `json:"familyName"`
}

type scimEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary"`
}

func (p scimUserPayload) email() string {
	if p.UserName != "" {
		return strings.TrimSpace(p.UserName)
	}
	for _, e := range p.Emails {
		if e.Primary && e.Value != "" {
			return strings.TrimSpace(e.Value)
		}
	}
	if len(p.Emails) > 0 {
		return strings.TrimSpace(p.Emails[0].Value)
	}
	return ""
}

func (p scimUserPayload) display() string {
	if p.DisplayName != "" {
		return p.DisplayName
	}
	if p.Name != nil {
		if p.Name.Formatted != "" {
			return p.Name.Formatted
		}
		full := strings.TrimSpace(p.Name.GivenName + " " + p.Name.FamilyName)
		if full != "" {
			return full
		}
	}
	return ""
}

func (h *Handler) createUser(w http.ResponseWriter, r *http.Request) {
	tid, ok := organizationFromCtx(r.Context())
	if !ok {
		writeSCIMErr(w, http.StatusUnauthorized, "no tenant")
		return
	}
	var p scimUserPayload
	if !decodeSCIMBody(w, r, &p) {
		return
	}
	profile, err := h.Service.profile(r.Context(), tid, p.Source, false)
	if err != nil {
		writeSCIMTypedErr(w, http.StatusBadRequest, "invalidValue", "Directory mapping validation failed")
		return
	}
	email := p.email()
	if mapped, ok := profile["email"].(string); ok {
		email = mapped
	}
	display := p.display()
	if mapped, ok := profile["display_name"].(string); ok {
		display = mapped
	}
	if email == "" {
		writeSCIMErr(w, http.StatusBadRequest, "userName (email) is required")
		return
	}
	ctx := r.Context()
	// Someone already at home in the organization (invited, or signed in with
	// single sign-on) is adopted rather than refused as a duplicate.
	if existing, err := h.Service.q.HomeUserByEmail(ctx, dbgen.HomeUserByEmailParams{OrganizationID: tid, Email: email}); err == nil {
		c := userChange{profile: profile, tag: &p.ExternalID, adopted: true}
		if display != "" {
			c.in.DisplayName = &display
		}
		if st := statusFromActive(p.Active); st != "" {
			c.in.Status = &st
		}
		if !h.applyUserChange(w, r, tid, existing, c, "user.updated") {
			return
		}
		row, err := h.Service.getProvisioned(ctx, tid, existing)
		if err != nil {
			writeSCIMErr(w, http.StatusNotFound, "user not found")
			return
		}
		writeSCIM(w, http.StatusCreated, h.toResource(r, row))
		return
	} else if !errors.Is(err, pgx.ErrNoRows) {
		writeSCIMErr(w, http.StatusInternalServerError, "create failed")
		return
	}
	if err := domainverify.CheckNewAccount(ctx, h.Service.users.Pool(), tid, email); err != nil {
		if errors.Is(err, errs.ErrUserDomainManaged) {
			writeSCIMErr(w, http.StatusConflict, "userName is on a domain another organization manages")
			return
		}
		writeSCIMErr(w, http.StatusInternalServerError, "create failed")
		return
	}
	tx, err := h.Service.users.Pool().Begin(ctx)
	if err != nil {
		writeSCIMErr(w, http.StatusInternalServerError, "create failed")
		return
	}
	defer tx.Rollback(ctx)
	u, err := h.Service.users.CreateWithCredentialTx(ctx, tx, user.CreateInput{
		OrganizationID: tid,
		Email:          email,
		DisplayName:    display,
	}, "")
	if err != nil {
		if errors.Is(err, errs.ErrAuthEmailExists) || errors.Is(err, errs.ErrConflict) {
			writeSCIMErr(w, http.StatusConflict, "userName already exists")
			return
		}
		writeSCIMErr(w, http.StatusBadRequest, "create failed")
		return
	}
	if err := h.Service.tagProvisionedTx(ctx, tx, u.ID, p.ExternalID); err != nil {
		writeSCIMErr(w, http.StatusInternalServerError, "tagging failed")
		return
	}
	if h.Service.mapper != nil {
		if err := h.Service.mapper.StoreProfile(ctx, tx, tid, u.ID, "scim:"+tid.String(), profile); err != nil {
			writeSCIMErr(w, http.StatusInternalServerError, "Profile mapping could not be saved")
			return
		}
	}
	// An IdP can create a user already deactivated.
	active := true
	if p.Active != nil && !*p.Active {
		active = false
		suspended := "suspended"
		if _, err := h.Service.users.UpdateTx(ctx, tx, u.ID, user.UpdateInput{Status: &suspended}); err != nil {
			writeSCIMErr(w, http.StatusInternalServerError, "create failed")
			return
		}
		if _, err := tx.Exec(ctx, `UPDATE account.users SET suspension_source='scim',suspension_reason='provider' WHERE organization_id=$1 AND id=$2`, tid, u.ID); err != nil {
			writeSCIMErr(w, http.StatusInternalServerError, "create failed")
			return
		}
	}
	if err := recordUserEvidence(ctx, tx, r, tid, u.ID, "user.created",
		map[string]any{"email": u.Email, "active": active}); err != nil {
		writeSCIMErr(w, http.StatusInternalServerError, "create failed")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		writeSCIMErr(w, http.StatusInternalServerError, "create failed")
		return
	}
	row, err := h.Service.getProvisioned(ctx, tid, u.ID)
	if err != nil {
		writeSCIMErr(w, http.StatusInternalServerError, "reload failed")
		return
	}
	writeSCIM(w, http.StatusCreated, h.toResource(r, row))
}

func (h *Handler) getUser(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := h.scimTarget(w, r)
	if !ok {
		return
	}
	row, err := h.Service.getProvisioned(r.Context(), tid, id)
	if err != nil {
		writeSCIMErr(w, http.StatusNotFound, "user not found")
		return
	}
	writeSCIM(w, http.StatusOK, h.toResource(r, row))
}

func (h *Handler) replaceUser(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := h.scimTarget(w, r)
	if !ok {
		return
	}
	var p scimUserPayload
	if !decodeSCIMBody(w, r, &p) {
		return
	}
	profile, err := h.Service.profile(r.Context(), tid, p.Source, false)
	if err != nil {
		writeSCIMTypedErr(w, http.StatusBadRequest, "invalidValue", "Directory mapping validation failed")
		return
	}
	c := userChange{profile: profile, email: p.email()}
	if d := p.display(); d != "" {
		c.in.DisplayName = &d
	}
	status := statusFromActive(p.Active)
	if status != "" {
		c.in.Status = &status
	}
	ext := p.ExternalID // PUT is a full replace: externalId is authoritative
	c.tag = &ext
	if !h.applyUserChange(w, r, tid, id, c, "user.updated") {
		return
	}
	row, err := h.Service.getProvisioned(r.Context(), tid, id)
	if err != nil {
		writeSCIMErr(w, http.StatusNotFound, "user not found")
		return
	}
	writeSCIM(w, http.StatusOK, h.toResource(r, row))
}

type patchBody struct {
	Schemas    []string `json:"schemas"`
	Operations []struct {
		Op    string          `json:"op"`
		Path  string          `json:"path"`
		Value json.RawMessage `json:"value"`
	} `json:"Operations"`
}

// patchUser supports the deprovisioning flow IdPs lean on: replacing the
// `active` attribute (path-scoped or via a value object) and displayName.
func (h *Handler) patchUser(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := h.scimTarget(w, r)
	if !ok {
		return
	}
	var body patchBody
	if !decodeSCIMBody(w, r, &body) {
		return
	}
	profile, err := h.Service.profile(r.Context(), tid, patchProfileSource(body), true)
	if err != nil {
		writeSCIMTypedErr(w, http.StatusBadRequest, "invalidValue", "Directory mapping validation failed")
		return
	}
	c := parseUserPatch(body)
	c.profile = profile
	if !h.applyUserChange(w, r, tid, id, c, "user.updated") {
		return
	}
	row, err := h.Service.getProvisioned(r.Context(), tid, id)
	if err != nil {
		writeSCIMErr(w, http.StatusNotFound, "user not found")
		return
	}
	writeSCIM(w, http.StatusOK, h.toResource(r, row))
}

func (h *Handler) deleteUser(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := h.scimTarget(w, r)
	if !ok {
		return
	}
	// Confirm the user belongs to this organization before soft-deleting.
	if _, err := h.Service.getProvisioned(r.Context(), tid, id); err != nil {
		writeSCIMErr(w, http.StatusNotFound, "user not found")
		return
	}
	if err := h.deprovision(r, tid, id); err != nil {
		if errors.Is(err, errOwnerUnchangeable) {
			writeSCIMErr(w, http.StatusForbidden, ownerUnchangeable)
			return
		}
		writeSCIMErr(w, http.StatusNotFound, "user not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// scimTarget pulls the organization from context and the {id} path param,
// writing a SCIM error and returning ok=false on failure.
func (h *Handler) scimTarget(w http.ResponseWriter, r *http.Request) (uuid.UUID, uuid.UUID, bool) {
	tid, ok := organizationFromCtx(r.Context())
	if !ok {
		writeSCIMErr(w, http.StatusUnauthorized, "no tenant")
		return uuid.Nil, uuid.Nil, false
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeSCIMErr(w, http.StatusBadRequest, "invalid id")
		return uuid.Nil, uuid.Nil, false
	}
	return tid, id, true
}

// parseUserPatch resolves a PatchOp body into a userChange: active (a
// boolean, or the string Entra sends), displayName, name parts, userName or
// the primary email, and externalId, by path or in a path-less value object.
// Other attributes are left to the directory mapping.
func parseUserPatch(body patchBody) userChange {
	var c userChange
	var given, family, formatted *string
	set := func(path string, raw json.RawMessage) {
		switch strings.ToLower(path) {
		case "active":
			if b, ok := scimBool(raw); ok {
				st := statusFromActive(&b)
				c.in.Status = &st
			}
		case "displayname":
			if v, ok := scimString(raw); ok {
				c.in.DisplayName = &v
			}
		case "username", `emails[primary eq true].value`, `emails[type eq "work"].value`:
			if v, ok := scimString(raw); ok && v != "" {
				c.email = v
			}
		case "emails":
			var emails []scimEmail
			if json.Unmarshal(raw, &emails) == nil {
				if v := (scimUserPayload{Emails: emails}).email(); v != "" {
					c.email = v
				}
			}
		case "externalid":
			if v, ok := scimString(raw); ok {
				c.tag = &v
			}
		case "name":
			var n scimName
			if json.Unmarshal(raw, &n) == nil {
				given, family, formatted = &n.GivenName, &n.FamilyName, &n.Formatted
			}
		case "name.givenname":
			if v, ok := scimString(raw); ok {
				given = &v
			}
		case "name.familyname":
			if v, ok := scimString(raw); ok {
				family = &v
			}
		case "name.formatted":
			if v, ok := scimString(raw); ok {
				formatted = &v
			}
		}
	}
	for _, op := range body.Operations {
		if !strings.EqualFold(op.Op, "replace") && !strings.EqualFold(op.Op, "add") {
			continue
		}
		path := strings.Trim(op.Path, `"`)
		if path != "" {
			set(path, op.Value)
			continue
		}
		var obj map[string]json.RawMessage
		if json.Unmarshal(op.Value, &obj) != nil {
			continue
		}
		for key, raw := range obj {
			set(key, raw)
		}
	}
	if c.in.DisplayName == nil {
		switch {
		case formatted != nil && *formatted != "":
			c.in.DisplayName = formatted
		case given != nil && family != nil:
			if full := strings.TrimSpace(*given + " " + *family); full != "" {
				c.in.DisplayName = &full
			}
		}
	}
	return c
}

// scimBool reads a SCIM boolean, which Entra sends as the string "True" or
// "False".
func scimBool(raw json.RawMessage) (bool, bool) {
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b, true
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if v, err := strconv.ParseBool(strings.TrimSpace(s)); err == nil {
			return v, true
		}
	}
	return false, false
}

// scimString reads a SCIM string attribute.
func scimString(raw json.RawMessage) (string, bool) {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return strings.TrimSpace(s), true
}

// statusFromActive maps the SCIM active flag to a user status. nil → "" so
// callers can leave the status untouched.
func statusFromActive(active *bool) string {
	if active == nil {
		return ""
	}
	if *active {
		return "active"
	}
	return "suspended"
}

// --- SCIM discovery ---

func (h *Handler) serviceProviderConfig(w http.ResponseWriter, r *http.Request) {
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":          []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri": h.location(r, ""),
		"patch":            map[string]any{"supported": true},
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": maxPageCount},
		"changePassword":   map[string]any{"supported": false},
		"sort":             map[string]any{"supported": false},
		"etag":             map[string]any{"supported": false},
		"authenticationSchemes": []map[string]any{{
			"type":        "oauthbearertoken",
			"name":        "OAuth Bearer Token",
			"description": "Authentication via the tenant SCIM bearer token.",
			"primary":     true,
		}},
		"meta": map[string]any{"resourceType": "ServiceProviderConfig", "location": h.location(r, "/ServiceProviderConfig")},
	})
}

func (h *Handler) resourceTypes(w http.ResponseWriter, r *http.Request) {
	userType := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
		"id":          "User",
		"name":        "User",
		"endpoint":    "/Users",
		"description": "User Account",
		"schema":      schemaUser,
		"meta":        map[string]any{"resourceType": "ResourceType", "location": h.location(r, "/ResourceTypes/User")},
	}
	groupType := map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
		"id":          "Group",
		"name":        "Group",
		"endpoint":    "/Groups",
		"description": "Group",
		"schema":      schemaGroup,
		"meta":        map[string]any{"resourceType": "ResourceType", "location": h.location(r, "/ResourceTypes/Group")},
	}
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":      []string{schemaListResp},
		"totalResults": 2,
		"startIndex":   1,
		"itemsPerPage": 2,
		"Resources":    []map[string]any{userType, groupType},
	})
}

func (h *Handler) schemas(w http.ResponseWriter, r *http.Request) {
	userSchema := map[string]any{
		"id":          schemaUser,
		"name":        "User",
		"description": "User Account",
		"attributes": []map[string]any{
			{"name": "userName", "type": "string", "required": true, "uniqueness": "server", "mutability": "readWrite"},
			{"name": "displayName", "type": "string", "required": false, "mutability": "readWrite"},
			{"name": "active", "type": "boolean", "required": false, "mutability": "readWrite"},
			{"name": "externalId", "type": "string", "required": false, "mutability": "readWrite"},
		},
		"meta": map[string]any{"resourceType": "Schema", "location": h.location(r, "/Schemas/"+schemaUser)},
	}
	groupSchema := map[string]any{
		"id":          schemaGroup,
		"name":        "Group",
		"description": "Group",
		"attributes": []map[string]any{
			{"name": "displayName", "type": "string", "required": true, "uniqueness": "none", "mutability": "readWrite"},
			{"name": "externalId", "type": "string", "required": false, "mutability": "readWrite"},
			{
				"name":        "members",
				"type":        "complex",
				"multiValued": true,
				"required":    false,
				"mutability":  "readWrite",
				"subAttributes": []map[string]any{
					{"name": "value", "type": "string", "mutability": "immutable"},
					{"name": "display", "type": "string", "mutability": "readOnly"},
					{"name": "$ref", "type": "reference", "mutability": "immutable"},
				},
			},
		},
		"meta": map[string]any{"resourceType": "Schema", "location": h.location(r, "/Schemas/"+schemaGroup)},
	}
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":      []string{schemaListResp},
		"totalResults": 2,
		"startIndex":   1,
		"itemsPerPage": 2,
		"Resources":    []map[string]any{userSchema, groupSchema},
	})
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

// recordUserEvidence writes the audit row and outbox event for a SCIM user
// change inside the caller's transaction. The actor is the organization's SCIM
// credential, recorded as actor type "scim".
func recordUserEvidence(ctx context.Context, tx pgx.Tx, r *http.Request, organizationID, userID uuid.UUID, action string, metadata map[string]any) error {
	organization := organizationID
	target := userID
	if err := audit.Record(ctx, tx, audit.Event{
		OrganizationID: &organization,
		ActorType:      "scim",
		Action:         action,
		ResourceType:   "user",
		ResourceID:     &target,
		IP:             httpx.ClientIP(r),
		UserAgent:      r.UserAgent(),
		RequestID:      httpx.RequestID(r),
		Metadata:       metadata,
	}); err != nil {
		return err
	}
	payload := map[string]any{"user_id": userID, "tenant_id": organizationID, "source": "scim"}
	for k, v := range metadata {
		payload[k] = v
	}
	return outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: userID,
		Topic:       "user.events",
		EventType:   action,
		Payload:     payload,
	})
}

// userChange is a SCIM change to a user: the update, the directory's mapped
// profile (nil: none), an external ID tagging the account as provisioned (nil:
// keep the tag), a new address ("": keep it), and whether a create adopted the
// existing account.
type userChange struct {
	in      user.UpdateInput
	profile map[string]any
	tag     *string
	email   string
	adopted bool
}

// applyUserChange runs a SCIM-driven user change and its evidence in one
// transaction, so a provisioning change is never durable without a record of
// it. A new address must be on a domain the organization manages; it counts as
// verified, as the organization's directory vouches for it, and links sent to
// the old one stop working.
func (h *Handler) applyUserChange(w http.ResponseWriter, r *http.Request, organizationID, userID uuid.UUID, c userChange, action string) bool {
	ctx := r.Context()
	in := c.in
	// UpdateTx matches on the user ID alone, so without this check one organization's
	// SCIM token could suspend or rename a user in any organization.
	current, err := h.Service.getProvisioned(ctx, organizationID, userID)
	if err != nil {
		writeSCIMErr(w, http.StatusNotFound, "user not found")
		return false
	}
	if strings.EqualFold(c.email, current.Email) {
		c.email = ""
	}
	if c.email != "" {
		manager, managed, err := domainverify.ManagerOf(postgres.AcrossOrganizations(ctx), h.Service.users.Pool(), c.email)
		if err != nil {
			writeSCIMErr(w, http.StatusInternalServerError, "update failed")
			return false
		}
		if !managed || manager != organizationID {
			writeSCIMTypedErr(w, http.StatusBadRequest, "invalidValue", "userName must be on a domain the organization has verified")
			return false
		}
	}
	tx, err := h.Service.users.Pool().Begin(ctx)
	if err != nil {
		writeSCIMErr(w, http.StatusInternalServerError, "update failed")
		return false
	}
	defer tx.Rollback(ctx)
	state, err := h.Service.q.WithTx(tx).ProvisionedUserState(ctx, dbgen.ProvisionedUserStateParams{OrganizationID: organizationID, ID: userID})
	if err != nil {
		writeSCIMErr(w, http.StatusNotFound, "user not found")
		return false
	}
	if state.Owner {
		writeSCIMErr(w, http.StatusForbidden, ownerUnchangeable)
		return false
	}
	// Nor does it move an administrator to another address, where their
	// password reset would then go, as single sign-on doesn't (ssosync).
	if c.email != "" {
		admin, err := identitylink.Administers(ctx, tx, userID, organizationID)
		if err != nil {
			writeSCIMErr(w, http.StatusInternalServerError, "update failed")
			return false
		}
		if admin {
			writeSCIMErr(w, http.StatusForbidden, administratorAddressUnchangeable)
			return false
		}
	}
	// The directory lifts only a suspension it set: one an administrator, a
	// policy or another directory set stands, and the rest of the change
	// applies.
	if in.Status != nil && *in.Status == "active" && state.Status == "suspended" && state.SuspensionSource != "scim" {
		in.Status = nil
	}
	if _, err := h.Service.users.UpdateTx(ctx, tx, userID, in); err != nil {
		writeSCIMErr(w, http.StatusNotFound, "user not found")
		return false
	}
	// Tagging an account as the directory's, or giving it a new address, vouches
	// for it from now on. One nobody vouched for yet (its holder never proved
	// the address, nor did the directory provision it) keeps nothing whoever
	// registered the address first set up, whichever request does it.
	if c.adopted || c.tag != nil || c.email != "" {
		if err := h.forgetUnvouched(ctx, tx, r, organizationID, userID); err != nil {
			writeSCIMErr(w, http.StatusInternalServerError, "update failed")
			return false
		}
	}
	if c.tag != nil {
		if err := h.Service.tagProvisionedTx(ctx, tx, userID, *c.tag); err != nil {
			writeSCIMErr(w, http.StatusInternalServerError, "update failed")
			return false
		}
	}
	if c.email != "" {
		if err := auth.ExpireRecoveryLinks(ctx, tx, userID); err != nil {
			writeSCIMErr(w, http.StatusInternalServerError, "update failed")
			return false
		}
		if _, err := tx.Exec(ctx, `
			UPDATE account.users SET email = $3, email_verified_at = NOW(), updated_at = NOW()
			WHERE id = $1 AND organization_id = $2`, userID, organizationID, c.email); err != nil {
			if pgxerr.IsUnique(err) {
				writeSCIMTypedErr(w, http.StatusConflict, "uniqueness", "userName already exists")
				return false
			}
			writeSCIMErr(w, http.StatusInternalServerError, "update failed")
			return false
		}
	}
	if in.Status != nil && *in.Status == "suspended" {
		if _, err := tx.Exec(ctx, `UPDATE account.users SET suspension_source='scim',suspension_reason='provider' WHERE organization_id=$1 AND id=$2 AND suspension_source='unknown'`, organizationID, userID); err != nil {
			writeSCIMErr(w, http.StatusInternalServerError, "update failed")
			return false
		}
		// Every way in ends, as an administrator's suspension ends them, so a
		// later reactivation revives none.
		if _, err := auth.EndSignIns(ctx, tx, h.Service.signals, userID, sessionsignal.ReasonDeprovisioned); err != nil {
			writeSCIMErr(w, http.StatusInternalServerError, "update failed")
			return false
		}
	}
	if h.Service.mapper != nil && c.profile != nil {
		if err := h.Service.mapper.StoreProfile(ctx, tx, organizationID, userID, "scim:"+organizationID.String(), c.profile); err != nil {
			writeSCIMErr(w, http.StatusInternalServerError, "Profile mapping could not be saved")
			return false
		}
	}
	metadata := map[string]any{}
	if in.Status != nil {
		metadata["status"] = *in.Status
	}
	if in.DisplayName != nil {
		metadata["display_name_changed"] = true
	}
	if c.email != "" {
		metadata["email_changed"] = true
	}
	if c.adopted {
		metadata["adopted"] = true
	}
	if err := recordUserEvidence(ctx, tx, r, organizationID, userID, action, metadata); err != nil {
		writeSCIMErr(w, http.StatusInternalServerError, "update failed")
		return false
	}
	if err := tx.Commit(ctx); err != nil {
		writeSCIMErr(w, http.StatusInternalServerError, "update failed")
		return false
	}
	return true
}

// forgetUnvouched removes, inside tx, every credential and sign-in of an
// account the directory is about to vouch for when nothing vouched for its
// address yet, and records the removal in organizationID's trail.
func (h *Handler) forgetUnvouched(ctx context.Context, tx pgx.Tx, r *http.Request, organizationID, userID uuid.UUID) error {
	vouched, err := identitylink.AddressVerified(ctx, tx, userID)
	if err != nil || vouched {
		return err
	}
	removed, err := auth.ForgetCredentials(ctx, tx, userID, false)
	if err != nil {
		return err
	}
	if _, err := auth.EndSignIns(ctx, tx, h.Service.signals, userID, sessionsignal.ReasonAdminRevokedAll); err != nil {
		return err
	}
	// Audited only, as the other first proofs are: no event leaves for webhooks.
	return audit.Record(ctx, tx, audit.Event{
		OrganizationID: &organizationID, ActorType: "scim", Action: "auth.credentials_removed", ResourceType: "user",
		ResourceID: &userID, IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r),
		Metadata: map[string]any{"proof": "scim_adoption", "removed": removed},
	})
}

// ownerUnchangeable is the refusal of a directory change to an account that
// owns the organization: owners are changed only by people, in the console.
const ownerUnchangeable = "This account owns the organization, so the directory can't change it."

// administratorAddressUnchangeable is the refusal of a directory change to the
// address of an account that administers the organization.
const administratorAddressUnchangeable = "This account administers the organization, so the directory can't change its address. Change it in the console."

// errOwnerUnchangeable refuses deprovisioning an owner.
var errOwnerUnchangeable = errors.New("scim: the account owns the organization")

// deprovision soft-deletes a SCIM-managed user, ending every way they sign
// in, and records it and what they leave behind (OffboardTx) in the same
// transaction. An owner is refused with
// errOwnerUnchangeable.
func (h *Handler) deprovision(r *http.Request, organizationID, userID uuid.UUID) error {
	ctx := r.Context()
	tx, err := h.Service.users.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	state, err := h.Service.q.WithTx(tx).ProvisionedUserState(ctx, dbgen.ProvisionedUserStateParams{OrganizationID: organizationID, ID: userID})
	if err != nil {
		return err
	}
	if state.Owner {
		return errOwnerUnchangeable
	}
	if err := h.Service.users.SoftDeleteTx(ctx, tx, userID); err != nil {
		return err
	}
	if _, err := auth.EndSignIns(ctx, tx, h.Service.signals, userID, sessionsignal.ReasonDeprovisioned); err != nil {
		return err
	}
	if err := recordUserEvidence(ctx, tx, r, organizationID, userID, "user.deleted", nil); err != nil {
		return err
	}
	directory := audit.Actor{Type: "scim", IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r)}
	if err := h.Service.users.OffboardTx(ctx, tx, organizationID, userID, directory); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

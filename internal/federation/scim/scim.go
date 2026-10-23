// Package scim implements SCIM 2.0 (RFC 7643/7644) provisioning, so IdPs such
// as Okta and Entra ID can push and deprovision users and groups. The protocol
// is served at /scim/v2 behind a per-tenant bearer token managed under /v1.
// Provisioned users are ordinary tenant users tagged provisioned_via='scim'.
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

	"github.com/qeetgroup/qeet-id-server/internal/federation/scim/dbgen"
	user "github.com/qeetgroup/qeet-id-server/internal/identity/users"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/codes"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
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
// announces no ended sessions; a nil gate leaves token rotation ungated.
type Service struct {
	signals  *sessionsignal.Signaller
	pool     *pgxpool.Pool
	q        *dbgen.Queries
	users    *user.Repository
	observer OperationObserver
	mapper   ProfileMapper
	gate     PlanGate
}

// SetSessionSignals sets where the sessions ended by a SCIM suspension are
// announced.
func (s *Service) SetSessionSignals(sig *sessionsignal.Signaller) { s.signals = sig }

// NewService returns the SCIM service.
func NewService(pool *pgxpool.Pool, users *user.Repository) *Service {
	return &Service{pool: pool, q: dbgen.New(pool), users: users}
}

// PlanGate reports whether a plan-gated boolean feature is included in the
// tenant's plan. Satisfied by *entitlements.Service.
type PlanGate interface {
	FeatureAllowed(ctx context.Context, tenantID uuid.UUID, feature string) (bool, error)
}

// SetPlanGate wires the plan-feature gate (nil allows all features).
func (s *Service) SetPlanGate(g PlanGate) { s.gate = g }

// Pool returns the connection pool, for handlers that run their own transaction.
func (s *Service) Pool() *pgxpool.Pool { return s.pool }

// ConfigView is the admin-facing status of a tenant's SCIM endpoint. The
// token itself is never returned here — only on rotation.
type ConfigView struct {
	TokenSet         bool       `json:"token_set"`
	TokenPrefix      string     `json:"token_prefix,omitempty"`
	CreatedAt        *time.Time `json:"created_at"`
	LastUsedAt       *time.Time `json:"last_used_at"`
	ProvisionedCount int        `json:"provisioned_count"`
}

// Config returns the tenant's SCIM settings, without its token.
func (s *Service) Config(ctx context.Context, tenantID uuid.UUID) (*ConfigView, error) {
	v := &ConfigView{}
	tok, err := s.q.GetScimTokenConfig(ctx, tenantID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if err == nil {
		v.TokenSet = true
		v.TokenPrefix = tok.TokenPrefix
		v.CreatedAt = &tok.CreatedAt
		if tok.LastUsedAt.Valid {
			t := tok.LastUsedAt.Time
			v.LastUsedAt = &t
		}
	}
	pgTID := pgtype.UUID{Bytes: tenantID, Valid: true}
	count, err := s.q.CountProvisionedUsers(ctx, pgTID)
	if err != nil {
		return nil, err
	}
	v.ProvisionedCount = int(count)
	return v, nil
}

// Rotate generates a new bearer token (replacing any existing one) and
// returns the full plaintext exactly once. Stored as SHA-256 + a short
// display prefix.
func (s *Service) Rotate(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) (full string, err error) {
	// Plan gate: SCIM directory sync is an Enterprise feature, not on Free/lower.
	if s.gate != nil {
		ok, gerr := s.gate.FeatureAllowed(ctx, tenantID, "scim")
		if gerr != nil {
			return "", gerr
		}
		if !ok {
			return "", errs.ErrUpgradeRequired.WithMetadata(map[string]any{"feature": "scim"})
		}
	}
	raw, _, err := codes.URLToken()
	if err != nil {
		return "", err
	}
	full = tokenPrefix + raw
	hash := codes.Hash(full)
	display := tokenPrefix + raw[:6]
	if err := s.q.WithTx(tx).UpsertScimToken(ctx, dbgen.UpsertScimTokenParams{
		TenantID:    tenantID,
		TokenHash:   hash,
		TokenPrefix: display,
	}); err != nil {
		return "", err
	}
	return full, nil
}

// Revoke deletes the tenant's SCIM token, which ends provisioning.
func (s *Service) Revoke(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) error {
	n, err := s.q.WithTx(tx).DeleteScimToken(ctx, tenantID)
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

// resolveToken maps a presented bearer token to its tenant and records use.
func (s *Service) resolveToken(ctx context.Context, raw string) (uuid.UUID, error) {
	hash := codes.Hash(raw)
	tid, err := s.q.GetScimTokenTenant(ctx, hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, errs.ErrUnauthorized
	}
	if err != nil {
		return uuid.Nil, err
	}
	// Best-effort last-used stamp; never block the request on it.
	_ = s.q.TouchScimTokenUsed(ctx, tid)
	return tid, nil
}

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

func (s *Service) getProvisioned(ctx context.Context, tenantID, id uuid.UUID) (*userRow, error) {
	r, err := s.q.GetProvisionedUser(ctx, dbgen.GetProvisionedUserParams{
		ID:       id,
		TenantID: pgtype.UUID{Bytes: tenantID, Valid: true},
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

func (s *Service) listProvisioned(ctx context.Context, tenantID uuid.UUID, emailFilter string, start, count int) ([]userRow, int, error) {
	args := []any{tenantID, provisionedScim}
	where := `tenant_id = $1 AND provisioned_via = $2 AND deleted_at IS NULL`
	if emailFilter != "" {
		args = append(args, emailFilter)
		where += ` AND LOWER(email) = LOWER($3)`
	}

	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM "user".users WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	args = append(args, count, start-1) // SCIM startIndex is 1-based
	rows, err := s.pool.Query(ctx, `
		SELECT `+userRowCols+` FROM "user".users WHERE `+where+`
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
	r.Post("/tenants/{tenantID}/scim/token", h.rotate)
	r.Delete("/tenants/{tenantID}/scim/token", h.revoke)
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

// adminListUsers returns this tenant's SCIM-provisioned users for the admin UI.
func (h *Handler) adminListUsers(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	rows, _, err := h.Service.listProvisioned(r.Context(), tenantID, "", 1, maxPageCount)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	items := make([]adminUser, 0, len(rows))
	for i := range rows {
		items = append(items, adminUser{
			ID:          rows[i].ID,
			Email:       rows[i].Email,
			DisplayName: rows[i].DisplayName,
			Status:      rows[i].Status,
			ExternalID:  rows[i].ExternalID,
			CreatedAt:   rows[i].CreatedAt,
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

// MountPublic registers the SCIM 2.0 protocol surface at the root, guarded
// by the per-tenant bearer token rather than the user-JWT middleware.
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

func requirePathTenant(r *http.Request) (uuid.UUID, error) {
	return httpx.PathTenantOr(r, errs.ErrSCIMTenantIDInvalid, errs.ErrSCIMTenantMismatch)
}

func (h *Handler) config(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	cfg, err := h.Service.Config(r.Context(), tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, cfg)
}

func (h *Handler) rotate(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
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
	full, err := h.Service.Rotate(ctx, tx, tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := audit.ActorOf(r).Identity()
	tid := tenantID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "scim.token_rotated",
		ResourceType: "scim_token",
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	cfg, err := h.Service.Config(ctx, tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"token": full, "config": cfg})
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requirePathTenant(r)
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
	if err := h.Service.Revoke(ctx, tx, tenantID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	actorID, actorType := audit.ActorOf(r).Identity()
	tid := tenantID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &tid,
		ActorUserID:  actorID,
		ActorType:    actorType,
		Action:       "scim.token_revoked",
		ResourceType: "scim_token",
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
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

const tenantCtxKey ctxKey = iota

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
		ctx := context.WithValue(r.Context(), tenantCtxKey, tid)
		h.observeMutations(next).ServeHTTP(w, r.WithContext(ctx))
	})
}

func tenantFromCtx(ctx context.Context) (uuid.UUID, bool) {
	tid, ok := ctx.Value(tenantCtxKey).(uuid.UUID)
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
	writeSCIM(w, status, map[string]any{
		"schemas":  []string{schemaError},
		"status":   strconv.Itoa(status),
		"scimType": scimType,
		"detail":   detail,
	})
}

// location returns the absolute URL of the SCIM endpoint at suffix, a path
// under /scim/v2.
func (h *Handler) location(r *http.Request, suffix string) string {
	return httpx.PublicOrigin(r, h.PublicBaseURL) + "/scim/v2" + suffix
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
	tid, ok := tenantFromCtx(r.Context())
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
	tid, ok := tenantFromCtx(r.Context())
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
	tx, err := h.Service.users.Pool().Begin(ctx)
	if err != nil {
		writeSCIMErr(w, http.StatusInternalServerError, "create failed")
		return
	}
	defer tx.Rollback(ctx)
	u, err := h.Service.users.CreateWithCredentialTx(ctx, tx, user.CreateInput{
		TenantID:    tid,
		Email:       email,
		DisplayName: display,
	}, "")
	if err != nil {
		if errors.Is(err, errs.ErrConflict) {
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
		if _, err := tx.Exec(ctx, `UPDATE "user".users SET suspension_source='scim',suspension_reason='provider' WHERE tenant_id=$1 AND id=$2`, tid, u.ID); err != nil {
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
	in := user.UpdateInput{}
	if d := p.display(); d != "" {
		in.DisplayName = &d
	}
	status := statusFromActive(p.Active)
	if status != "" {
		in.Status = &status
	}
	if !h.applyUserUpdate(w, r, tid, id, in, "user.updated", profile) {
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
	in := user.UpdateInput{}
	for _, op := range body.Operations {
		if !strings.EqualFold(op.Op, "replace") && !strings.EqualFold(op.Op, "add") {
			continue
		}
		switch strings.ToLower(strings.Trim(op.Path, `"`)) {
		case "active":
			var b bool
			if json.Unmarshal(op.Value, &b) == nil {
				st := statusFromActive(&b)
				in.Status = &st
			}
		case "displayname":
			var dn string
			if json.Unmarshal(op.Value, &dn) == nil {
				in.DisplayName = &dn
			}
		case "":
			// Path-less replace: value is an object of attributes.
			var obj map[string]json.RawMessage
			if json.Unmarshal(op.Value, &obj) != nil {
				continue
			}
			if raw, exists := obj["active"]; exists {
				var b bool
				if json.Unmarshal(raw, &b) == nil {
					st := statusFromActive(&b)
					in.Status = &st
				}
			}
			if raw, exists := obj["displayName"]; exists {
				var dn string
				if json.Unmarshal(raw, &dn) == nil {
					in.DisplayName = &dn
				}
			}
		}
	}
	if !h.applyUserUpdate(w, r, tid, id, in, "user.updated", profile) {
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
	// Confirm the user belongs to this tenant before soft-deleting.
	if _, err := h.Service.getProvisioned(r.Context(), tid, id); err != nil {
		writeSCIMErr(w, http.StatusNotFound, "user not found")
		return
	}
	if err := h.deprovision(r, tid, id); err != nil {
		writeSCIMErr(w, http.StatusNotFound, "user not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// scimTarget pulls the tenant from context and the {id} path param,
// writing a SCIM error and returning ok=false on failure.
func (h *Handler) scimTarget(w http.ResponseWriter, r *http.Request) (uuid.UUID, uuid.UUID, bool) {
	tid, ok := tenantFromCtx(r.Context())
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
// change inside the caller's transaction. The actor is the tenant's SCIM
// credential, recorded as actor type "scim".
func recordUserEvidence(ctx context.Context, tx pgx.Tx, r *http.Request, tenantID, userID uuid.UUID, action string, metadata map[string]any) error {
	tenant := tenantID
	target := userID
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &tenant,
		ActorType:    "scim",
		Action:       action,
		ResourceType: "user",
		ResourceID:   &target,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata:     metadata,
	}); err != nil {
		return err
	}
	payload := map[string]any{"user_id": userID, "tenant_id": tenantID, "source": "scim"}
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

// applyUserUpdate runs a SCIM-driven user update and its evidence in one
// transaction, so a provisioning change is never durable without a record of it.
func (h *Handler) applyUserUpdate(w http.ResponseWriter, r *http.Request, tenantID, userID uuid.UUID, in user.UpdateInput, action string, profiles ...map[string]any) bool {
	ctx := r.Context()
	// UpdateTx matches on the user ID alone, so without this check one tenant's
	// SCIM token could suspend or rename a user in any tenant.
	if _, err := h.Service.getProvisioned(ctx, tenantID, userID); err != nil {
		writeSCIMErr(w, http.StatusNotFound, "user not found")
		return false
	}
	tx, err := h.Service.users.Pool().Begin(ctx)
	if err != nil {
		writeSCIMErr(w, http.StatusInternalServerError, "update failed")
		return false
	}
	defer tx.Rollback(ctx)
	if _, err := h.Service.users.UpdateTx(ctx, tx, userID, in); err != nil {
		writeSCIMErr(w, http.StatusNotFound, "user not found")
		return false
	}
	if in.Status != nil && *in.Status == "suspended" {
		if _, err := tx.Exec(ctx, `UPDATE "user".users SET suspension_source='scim',suspension_reason='provider' WHERE tenant_id=$1 AND id=$2 AND suspension_source='unknown'`, tenantID, userID); err != nil {
			writeSCIMErr(w, http.StatusInternalServerError, "update failed")
			return false
		}
		ended, err := sessionsignal.EndUserSessions(ctx, tx, userID)
		if err != nil {
			writeSCIMErr(w, http.StatusInternalServerError, "update failed")
			return false
		}
		h.Service.signals.Revoked(ctx, tx, sessionsignal.ReasonDeprovisioned, ended...)
	}
	if h.Service.mapper != nil && len(profiles) > 0 {
		if err := h.Service.mapper.StoreProfile(ctx, tx, tenantID, userID, "scim:"+tenantID.String(), profiles[0]); err != nil {
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
	if err := recordUserEvidence(ctx, tx, r, tenantID, userID, action, metadata); err != nil {
		writeSCIMErr(w, http.StatusInternalServerError, "update failed")
		return false
	}
	if err := tx.Commit(ctx); err != nil {
		writeSCIMErr(w, http.StatusInternalServerError, "update failed")
		return false
	}
	return true
}

// deprovision soft-deletes a SCIM-managed user and records it in the same
// transaction.
func (h *Handler) deprovision(r *http.Request, tenantID, userID uuid.UUID) error {
	ctx := r.Context()
	tx, err := h.Service.users.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := h.Service.users.SoftDeleteTx(ctx, tx, userID); err != nil {
		return err
	}
	if err := recordUserEvidence(ctx, tx, r, tenantID, userID, "user.deleted", nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

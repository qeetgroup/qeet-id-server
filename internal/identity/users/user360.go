package user

// User 360 — admin read surfaces for the console's per-user "identity
// investigation" workspace. These endpoints answer, for a single user: how do
// they authenticate (security posture), where are they signed in (sessions),
// and what can they access (roles / groups / org / apps / policies).
//
// Every handler goes through scopedID, so it parses {id} AND enforces that the
// target user belongs to the caller's own tenant (ErrNotFound on any
// cross-tenant probe). The route→permission gating lives in bootstrap's
// permissionMap: the reads require user.read, the session revoke-all is a
// user.write mutation.

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/identity/users/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// SecuritySummary is a user's authentication posture, as shown in the console's
// "Security posture" tiles and Security tab.
type SecuritySummary struct {
	// MFARequired reflects the users.mfa_required flag (policy), independent of
	// whether the user has actually enrolled a factor.
	MFARequired bool `json:"mfa_required"`
	// MFAEnabled is derived: the user has at least one usable second factor
	// (confirmed TOTP, a verified email/SMS OTP factor, or a push device).
	MFAEnabled             bool       `json:"mfa_enabled"`
	TOTPEnabled            bool       `json:"totp_enabled"`
	OTPFactors             int        `json:"otp_factors"`
	PushDevices            int        `json:"push_devices"`
	Passkeys               int        `json:"passkeys"`
	PasskeyLastUsedAt      *time.Time `json:"passkey_last_used_at"`
	RecoveryCodesRemaining int        `json:"recovery_codes_remaining"`
	PasswordSet            bool       `json:"password_set"`
	PasswordChangedAt      *time.Time `json:"password_changed_at"`
	ActiveSessions         int        `json:"active_sessions"`
	// DistinctDevices is a User-Agent-based approximation (there is no true
	// device identifier on sessions today).
	DistinctDevices int `json:"distinct_devices"`
}

// SessionInfo is one live session for a user. Device/OS/geo are intentionally
// absent — the sessions model stores only ip + raw user_agent; the console
// parses the UA client-side.
type SessionInfo struct {
	ID         uuid.UUID `json:"id"`
	IP         *string   `json:"ip"`
	UserAgent  *string   `json:"user_agent"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
}

// RoleInfo / GroupInfo / OrganizationInfo are the access primitives surfaced in
// the Access tab.
type RoleInfo struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
}

type GroupInfo struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
}

type OrganizationInfo struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
	Slug string    `json:"slug"`
}

// AccessSummary answers "what can this user access?" within the caller's tenant.
// Organizations map 1:1 to tenants in Qeet ID (a user belongs to exactly one),
// so Organization is a single object rather than a list. Roles are direct
// assignments; effective permissions (which also fold in group-inherited roles)
// are served by the existing RBAC endpoint.
type AccessSummary struct {
	Organization      *OrganizationInfo `json:"organization"`
	Roles             []RoleInfo        `json:"roles"`
	Groups            []GroupInfo       `json:"groups"`
	ApplicationsCount int               `json:"applications_count"`
	PoliciesCount     int               `json:"policies_count"`
	// Permission breakdown: PermissionsTotal is the distinct effective set;
	// PermissionsDirect comes from directly-assigned roles; PermissionsInherited
	// (= total − direct) is what the user gains only through group membership.
	PermissionsDirect    int `json:"permissions_direct"`
	PermissionsInherited int `json:"permissions_inherited"`
	PermissionsTotal     int `json:"permissions_total"`
}

// UserStats is the tenant-wide member summary shown in the Users KPI cards.
type UserStats struct {
	Total      int `json:"total"`
	Active     int `json:"active"`
	Suspended  int `json:"suspended"`
	Invited    int `json:"invited"`
	MFAEnabled int `json:"mfa_enabled"`
	MFAMissing int `json:"mfa_missing"`
	// NewLast30d is members created in the last 30 days — the Total-users card's
	// "vs last 30 days" delta baseline.
	NewLast30d int `json:"new_last_30d"`
}

// UserTrends holds 30-day daily series (oldest → newest) for the KPI sparklines.
type UserTrends struct {
	Total      []int `json:"total"`
	MFAEnabled []int `json:"mfa_enabled"`
}

// ── Repository ────────────────────────────────────────────────────────────────

// Stats returns the tenant-wide member counts for the Users summary.
func (r *Repository) Stats(ctx context.Context, tenantID uuid.UUID) (*UserStats, error) {
	row, err := r.q.GetUserStats(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return &UserStats{
		Total:      int(row.TotalUsers),
		Active:     int(row.ActiveUsers),
		Suspended:  int(row.SuspendedUsers),
		Invited:    int(row.InvitedUsers),
		MFAEnabled: int(row.MfaEnabled),
		MFAMissing: int(row.MfaMissing),
		NewLast30d: int(row.NewLast30d),
	}, nil
}

// Trends returns the 30-day daily total/MFA-enabled series for the KPI cards.
func (r *Repository) Trends(ctx context.Context, tenantID uuid.UUID) (*UserTrends, error) {
	rows, err := r.q.GetUserTrends(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := &UserTrends{Total: make([]int, 0, len(rows)), MFAEnabled: make([]int, 0, len(rows))}
	for _, row := range rows {
		out.Total = append(out.Total, int(row.Total))
		out.MFAEnabled = append(out.MFAEnabled, int(row.Mfa))
	}
	return out, nil
}

// SecuritySummary aggregates a user's authentication posture. The two nullable
// timestamps come from dedicated queries whose ErrNoRows cleanly means "never".
func (r *Repository) SecuritySummary(ctx context.Context, id uuid.UUID) (*SecuritySummary, error) {
	row, err := r.q.GetUserSecuritySummary(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	s := &SecuritySummary{
		MFARequired:            row.MfaRequired,
		TOTPEnabled:            row.TotpEnabled,
		OTPFactors:             int(row.OtpFactors),
		PushDevices:            int(row.PushDevices),
		Passkeys:               int(row.Passkeys),
		RecoveryCodesRemaining: int(row.RecoveryCodesRemaining),
		PasswordSet:            row.PasswordSet,
		ActiveSessions:         int(row.ActiveSessions),
		DistinctDevices:        int(row.DistinctDevices),
	}
	s.MFAEnabled = s.TOTPEnabled || s.OTPFactors > 0 || s.PushDevices > 0

	changed, perr := r.q.GetUserPasswordChangedAt(ctx, id)
	if perr == nil {
		t := changed
		s.PasswordChangedAt = &t
	} else if !errors.Is(perr, pgx.ErrNoRows) {
		return nil, perr
	}

	lastUsed, lerr := r.q.GetUserPasskeyLastUsed(ctx, id)
	if lerr == nil {
		s.PasskeyLastUsedAt = pgtypeToTimePtr(lastUsed)
	} else if !errors.Is(lerr, pgx.ErrNoRows) {
		return nil, lerr
	}
	return s, nil
}

// ListUserSessions returns a user's live (non-revoked) sessions.
func (r *Repository) ListUserSessions(ctx context.Context, id uuid.UUID) ([]SessionInfo, error) {
	rows, err := r.q.ListUserActiveSessions(ctx, id)
	if err != nil {
		return nil, err
	}
	out := make([]SessionInfo, 0, len(rows))
	for _, row := range rows {
		si := SessionInfo{
			ID:         row.ID,
			UserAgent:  row.UserAgent,
			CreatedAt:  row.CreatedAt,
			LastSeenAt: row.LastSeenAt,
		}
		if row.Ip != "" {
			ip := row.Ip
			si.IP = &ip
		}
		out = append(out, si)
	}
	return out, nil
}

// RevokeAllUserSessions revokes every live session for a user; returns the count.
func (r *Repository) RevokeAllUserSessions(ctx context.Context, id uuid.UUID) (int64, error) {
	return r.q.RevokeAllUserSessions(ctx, id)
}

func (r *Repository) UserRolesInTenant(ctx context.Context, id, tenantID uuid.UUID) ([]RoleInfo, error) {
	rows, err := r.q.ListUserRolesInTenant(ctx, dbgen.ListUserRolesInTenantParams{UserID: id, TenantID: tenantID})
	if err != nil {
		return nil, err
	}
	out := make([]RoleInfo, 0, len(rows))
	for _, row := range rows {
		out = append(out, RoleInfo{ID: row.ID, Name: row.Name, Description: row.Description})
	}
	return out, nil
}

func (r *Repository) UserGroupsInTenant(ctx context.Context, id, tenantID uuid.UUID) ([]GroupInfo, error) {
	rows, err := r.q.ListUserGroupsInTenant(ctx, dbgen.ListUserGroupsInTenantParams{UserID: id, TenantID: tenantID})
	if err != nil {
		return nil, err
	}
	out := make([]GroupInfo, 0, len(rows))
	for _, row := range rows {
		out = append(out, GroupInfo{ID: row.ID, Name: row.Name, Description: row.Description})
	}
	return out, nil
}

func (r *Repository) UserOrganization(ctx context.Context, id uuid.UUID) (*OrganizationInfo, error) {
	row, err := r.q.GetUserOrganization(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &OrganizationInfo{ID: row.ID, Name: row.Name, Slug: row.Slug}, nil
}

// AccessSummary composes the per-user access view for the caller's tenant.
func (r *Repository) AccessSummary(ctx context.Context, id, tenantID uuid.UUID) (*AccessSummary, error) {
	org, err := r.UserOrganization(ctx, id)
	if err != nil {
		return nil, err
	}
	roles, err := r.UserRolesInTenant(ctx, id, tenantID)
	if err != nil {
		return nil, err
	}
	groups, err := r.UserGroupsInTenant(ctx, id, tenantID)
	if err != nil {
		return nil, err
	}
	apps, err := r.q.CountUserApplications(ctx, dbgen.CountUserApplicationsParams{UserID: id, TenantID: tenantID})
	if err != nil {
		return nil, err
	}
	policies, err := r.q.CountTenantEnabledPolicies(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	direct, err := r.q.CountUserDirectPermissions(ctx, dbgen.CountUserDirectPermissionsParams{UserID: id, TenantID: tenantID})
	if err != nil {
		return nil, err
	}
	effective, err := r.q.CountUserEffectivePermissions(ctx, dbgen.CountUserEffectivePermissionsParams{UserID: id, TenantID: tenantID})
	if err != nil {
		return nil, err
	}
	inherited := int(effective) - int(direct)
	if inherited < 0 {
		inherited = 0 // direct ⊆ effective, so this is defensive only
	}
	return &AccessSummary{
		Organization:         org,
		Roles:                roles,
		Groups:               groups,
		ApplicationsCount:    int(apps),
		PoliciesCount:        int(policies),
		PermissionsDirect:    int(direct),
		PermissionsInherited: inherited,
		PermissionsTotal:     int(effective),
	}, nil
}

// SetMfaRequired flips the users.mfa_required policy flag. ErrNotFound when the
// user does not exist (or is soft-deleted).
func (r *Repository) SetMfaRequired(ctx context.Context, id uuid.UUID, required bool) error {
	n, err := r.q.SetUserMfaRequired(ctx, dbgen.SetUserMfaRequiredParams{ID: id, MfaRequired: required})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	return nil
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// getUserStats → GET /v1/users/stats (user.read). Tenant-wide member counts for
// the Users admin summary strip; scoped to the caller's own tenant principal.
func (h *Handler) getUserStats(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.TenantID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized.WithDetail("tenant scope required"))
		return
	}
	stats, err := h.Repo.Stats(r.Context(), *p.TenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, stats)
}

// getUserTrends → GET /v1/users/trends (user.read). 30-day KPI-sparkline series.
func (h *Handler) getUserTrends(w http.ResponseWriter, r *http.Request) {
	p := httpx.PrincipalFromCtx(r.Context())
	if p == nil || p.TenantID == nil {
		httpx.WriteError(w, r, errs.ErrUnauthorized.WithDetail("tenant scope required"))
		return
	}
	trends, err := h.Repo.Trends(r.Context(), *p.TenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, trends)
}

// getSecurity → GET /v1/users/{id}/security (user.read).
func (h *Handler) getSecurity(w http.ResponseWriter, r *http.Request) {
	id, _, err := h.scopedID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	sum, err := h.Repo.SecuritySummary(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sum)
}

// getSessions → GET /v1/users/{id}/sessions (user.read).
func (h *Handler) getSessions(w http.ResponseWriter, r *http.Request) {
	id, _, err := h.scopedID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	items, err := h.Repo.ListUserSessions(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

// revokeAllSessions → POST /v1/users/{id}/sessions/revoke-all (user.write).
// Admin force sign-out: invalidates every live session for the user.
func (h *Handler) revokeAllSessions(w http.ResponseWriter, r *http.Request) {
	id, _, err := h.scopedID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	n, err := h.Repo.RevokeAllUserSessions(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.auditUserAction(r, "session.admin_revoked_all", id)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"revoked": n})
}

// getAccess → GET /v1/users/{id}/access (user.read).
func (h *Handler) getAccess(w http.ResponseWriter, r *http.Request) {
	id, tenantID, err := h.scopedID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	sum, err := h.Repo.AccessSummary(r.Context(), id, tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sum)
}

type setMfaRequiredInput struct {
	// Pointer so a missing field is distinguishable from an explicit false.
	Required *bool `json:"required"`
}

// setMfaRequired → PUT /v1/users/{id}/mfa-required (user.write). Toggles the
// per-user MFA-required policy flag; audited.
func (h *Handler) setMfaRequired(w http.ResponseWriter, r *http.Request) {
	id, _, err := h.scopedID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in setMfaRequiredInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.Required == nil {
		httpx.WriteError(w, r, errs.ErrBadRequest.WithDetail("required is required"))
		return
	}
	if err := h.Repo.SetMfaRequired(r.Context(), id, *in.Required); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	h.auditUserAction(r, "user.mfa_required_set", id)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"mfa_required": *in.Required})
}

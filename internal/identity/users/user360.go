package user

// User 360: the console's per-user investigation views (security posture,
// sessions, access). Reads resolve {id} with memberID and actions with
// scopedID, so a user outside the caller's tenant is ErrNotFound.

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/identity/users/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// SecuritySummary is a user's authentication posture for the console. MFARequired
// is the account's policy flag; MFAEnabled reports a usable second factor
// (confirmed TOTP, a verified OTP factor or a push device). DistinctDevices is
// estimated from session User-Agents.
type SecuritySummary struct {
	MFARequired            bool       `json:"mfa_required"`
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
	DistinctDevices        int        `json:"distinct_devices"`
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

// RoleInfo is a role shown in the console's Access tab.
type RoleInfo struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
}

// GroupInfo is a group shown in the console's Access tab.
type GroupInfo struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
}

// OrganizationInfo is the organization shown in the console's Access tab.
type OrganizationInfo struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
	Slug string    `json:"slug"`
}

// AccessSummary is what a user can access in the caller's tenant. Organization
// is that tenant and Roles are direct assignments; the Permissions counts split
// the effective set into direct and group-inherited.
type AccessSummary struct {
	Organization         *OrganizationInfo `json:"organization"`
	Roles                []RoleInfo        `json:"roles"`
	Groups               []GroupInfo       `json:"groups"`
	ApplicationsCount    int               `json:"applications_count"`
	PoliciesCount        int               `json:"policies_count"`
	PermissionsDirect    int               `json:"permissions_direct"`
	PermissionsInherited int               `json:"permissions_inherited"`
	PermissionsTotal     int               `json:"permissions_total"`
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

// SecuritySummary aggregates a user's authentication posture, counting the
// sessions ListUserSessions lists for tenantID. The two nullable timestamps come
// from dedicated queries whose ErrNoRows cleanly means "never".
func (r *Repository) SecuritySummary(ctx context.Context, id, tenantID uuid.UUID) (*SecuritySummary, error) {
	row, err := r.q.GetUserSecuritySummary(ctx, dbgen.GetUserSecuritySummaryParams{ID: id, TenantID: tenantID})
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

// ListUserSessions returns a user's live sessions in tenantID, and, when it is
// their home tenant, those in no tenant.
func (r *Repository) ListUserSessions(ctx context.Context, id, tenantID uuid.UUID) ([]SessionInfo, error) {
	rows, err := r.q.ListUserActiveSessions(ctx, dbgen.ListUserActiveSessionsParams{UserID: id, TenantID: tenantID})
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

// UserRolesInTenant returns the user's roles in the tenant.
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

// UserGroupsInTenant returns the user's groups in the tenant.
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

// accessOrganization is the organization an access view describes: the one the
// admin is viewing the user from.
func (r *Repository) accessOrganization(ctx context.Context, tenantID uuid.UUID) (*OrganizationInfo, error) {
	row, err := r.q.GetAccessOrganization(ctx, tenantID)
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
	org, err := r.accessOrganization(ctx, tenantID)
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

// getUserStats handles GET /v1/users/stats: member counts for the caller's tenant.
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

// getUserTrends handles GET /v1/users/trends: 30-day daily series for the
// caller's tenant.
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

// getSecurity handles GET /v1/users/{id}/security: the user's SecuritySummary
// as the caller's tenant sees it.
func (h *Handler) getSecurity(w http.ResponseWriter, r *http.Request) {
	id, tenantID, err := h.memberID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	sum, err := h.Repo.SecuritySummary(r.Context(), id, tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sum)
}

// getSessions handles GET /v1/users/{id}/sessions: the user's live sessions
// in the caller's tenant.
func (h *Handler) getSessions(w http.ResponseWriter, r *http.Request) {
	id, tenantID, err := h.memberID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	items, err := h.Repo.ListUserSessions(r.Context(), id, tenantID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

// revokeAllSessions handles POST /v1/users/{id}/sessions/revoke-all: in one
// transaction it ends every way the user is signed in and records it, then
// reports {"revoked": total} with a count per kind. Access tokens already
// issued stay valid until they expire.
func (h *Handler) revokeAllSessions(w http.ResponseWriter, r *http.Request) {
	id, tenantID, err := h.scopedID(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if h.SignIns == nil {
		httpx.WriteError(w, r, errs.ErrNotImplemented)
		return
	}
	ctx := r.Context()
	tx, err := h.Repo.Pool().Begin(ctx)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	defer tx.Rollback(ctx)
	ended, err := h.SignIns.EndAllSignIns(ctx, tx, id, sessionsignal.ReasonAdminRevokedAll)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var actorID *uuid.UUID
	if p := httpx.PrincipalFromCtx(ctx); p != nil {
		actorID = p.UserID
	}
	if err := audit.Record(ctx, tx, audit.Event{
		TenantID:     &tenantID,
		ActorUserID:  actorID,
		Action:       "session.admin_revoked_all",
		ResourceType: "user",
		ResourceID:   &id,
		IP:           httpx.ClientIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    httpx.RequestID(r),
		Metadata: map[string]any{
			"revoked_sessions":             ended.Sessions,
			"revoked_login_sessions":       ended.LoginSessions,
			"revoked_app_grants":           ended.AppGrants,
			"revoked_trusted_devices":      ended.TrustedDevices,
			"ended_pending_authorizations": ended.PendingAuthorizations,
		},
	}); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"revoked":                ended.Total(),
		"sessions":               ended.Sessions,
		"hosted_login_sessions":  ended.LoginSessions,
		"app_grants":             ended.AppGrants,
		"trusted_devices":        ended.TrustedDevices,
		"pending_authorizations": ended.PendingAuthorizations,
	})
}

// getAccess handles GET /v1/users/{id}/access: the user's AccessSummary.
func (h *Handler) getAccess(w http.ResponseWriter, r *http.Request) {
	id, tenantID, err := h.memberID(r)
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

// setMfaRequired handles PUT /v1/users/{id}/mfa-required: it sets the user's
// MFA-required flag and audits the change.
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

package gdpr

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/operations/gdpr/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/messaging/notifier"
	"github.com/qeetgroup/qeet-id-server/internal/platform/strutil"
)

type exportIdentity struct {
	Provider string    `json:"provider"`
	Subject  string    `json:"subject"`
	Email    *string   `json:"email,omitempty"`
	LinkedAt time.Time `json:"linked_at"`
}

type exportOTPFactor struct {
	Channel     string     `json:"channel"`
	Destination string     `json:"destination"` // masked
	VerifiedAt  *time.Time `json:"verified_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

type exportConsent struct {
	ClientID   string    `json:"client_id"`
	ClientName string    `json:"client_name"`
	Scopes     []string  `json:"scopes"`
	GrantedAt  time.Time `json:"granted_at"`
}

type exportGrant struct {
	ClientID   string    `json:"client_id"`
	ClientName string    `json:"client_name"`
	Scopes     []string  `json:"scopes"`
	IssuedAt   time.Time `json:"issued_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type exportGroup struct {
	Name         string    `json:"name"`
	Organization string    `json:"organization"`
	AddedAt      time.Time `json:"added_at"`
}

type exportSignIn struct {
	At           time.Time `json:"at"`
	Succeeded    bool      `json:"succeeded"`
	Method       string    `json:"method,omitempty"`
	IP           string    `json:"ip,omitempty"`
	UserAgent    string    `json:"user_agent,omitempty"`
	Organization string    `json:"organization,omitempty"`
}

// exportSections adds to out the sections both exports share: linked
// accounts, email and SMS factors (their destinations masked), application
// consents and live grants, group memberships and the latest sign-ins. With
// organizationID set they cover that organization's part only.
func exportSections(ctx context.Context, q *dbgen.Queries, userID uuid.UUID, organizationID *uuid.UUID, out map[string]any) error {
	organization := organizationID

	idRows, err := q.ListUserIdentitiesForExport(ctx, dbgen.ListUserIdentitiesForExportParams{UserID: userID, OrganizationID: organization})
	if err != nil {
		return err
	}
	identities := make([]exportIdentity, 0, len(idRows))
	for _, r := range idRows {
		identities = append(identities, exportIdentity{Provider: r.Provider, Subject: r.Subject, Email: r.Email, LinkedAt: r.LinkedAt})
	}

	factorRows, err := q.ListUserOTPFactorsForExport(ctx, userID)
	if err != nil {
		return err
	}
	factors := make([]exportOTPFactor, 0, len(factorRows))
	for _, r := range factorRows {
		factors = append(factors, exportOTPFactor{
			Channel: r.Channel, Destination: notifier.MaskDestination(r.Channel, r.Destination),
			VerifiedAt: r.VerifiedAt, CreatedAt: r.CreatedAt,
		})
	}

	consentRows, err := q.ListUserConsentsForExport(ctx, dbgen.ListUserConsentsForExportParams{UserID: userID, OrganizationID: organization})
	if err != nil {
		return err
	}
	consents := make([]exportConsent, 0, len(consentRows))
	for _, r := range consentRows {
		consents = append(consents, exportConsent{ClientID: r.ClientID, ClientName: r.ClientName, Scopes: r.Scopes, GrantedAt: r.GrantedAt})
	}

	grantRows, err := q.ListUserGrantsForExport(ctx, dbgen.ListUserGrantsForExportParams{UserID: userID, OrganizationID: organization})
	if err != nil {
		return err
	}
	grants := make([]exportGrant, 0, len(grantRows))
	for _, r := range grantRows {
		grants = append(grants, exportGrant{ClientID: r.ClientID, ClientName: r.ClientName, Scopes: r.Scopes,
			IssuedAt: r.IssuedAt, ExpiresAt: r.ExpiresAt})
	}

	groupRows, err := q.ListUserGroupsForExport(ctx, dbgen.ListUserGroupsForExportParams{UserID: userID, OrganizationID: organization})
	if err != nil {
		return err
	}
	groups := make([]exportGroup, 0, len(groupRows))
	for _, r := range groupRows {
		groups = append(groups, exportGroup{Name: r.Name, Organization: r.Organization, AddedAt: r.AddedAt})
	}

	signInRows, err := q.ListUserSignInsForExport(ctx, dbgen.ListUserSignInsForExportParams{UserID: userID, OrganizationID: organization})
	if err != nil {
		return err
	}
	signIns := make([]exportSignIn, 0, len(signInRows))
	for _, r := range signInRows {
		signIns = append(signIns, exportSignIn{At: r.CreatedAt, Succeeded: r.Succeeded, Method: r.Method,
			IP: r.Ip, UserAgent: r.UserAgent, Organization: r.Organization})
	}

	out["identities"] = identities
	out["otp_factors"] = factors
	out["app_consents"] = consents
	out["app_grants"] = grants
	out["groups"] = groups
	out["sign_ins"] = signIns
	return nil
}

// metadataOf decodes a user's metadata column; an unreadable value exports as
// empty.
func metadataOf(raw []byte) map[string]any {
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

type exportProfile struct {
	Email           string         `json:"email"`
	Phone           *string        `json:"phone,omitempty"`
	DisplayName     *string        `json:"display_name,omitempty"`
	AvatarURL       *string        `json:"avatar_url,omitempty"`
	Metadata        map[string]any `json:"metadata"`
	Status          string         `json:"status"`
	EmailVerifiedAt *time.Time     `json:"email_verified_at,omitempty"`
	PhoneVerifiedAt *time.Time     `json:"phone_verified_at,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
}

type exportSession struct {
	ID         uuid.UUID  `json:"id"`
	IP         *string    `json:"ip,omitempty"`
	UserAgent  *string    `json:"user_agent,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt time.Time  `json:"last_seen_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

type exportPasskey struct {
	ID         uuid.UUID  `json:"id"`
	Name       *string    `json:"name,omitempty"`
	Transports []string   `json:"transports,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

type exportRole struct {
	RoleName  string    `json:"role_name"`
	GrantedAt time.Time `json:"granted_at"`
}

// collectUserData assembles one user's portable data in an organization: profile,
// sessions, passkeys, MFA status, roles and the sections of exportSections.
// Credentials (password hashes, TOTP secrets, recovery codes) are excluded.
func (s *Service) collectUserData(ctx context.Context, organizationID, userID uuid.UUID) (map[string]any, error) {
	// account.users.organization_id is nullable, so it takes a pointer.
	profileRow, err := s.q.GetUserProfileForExport(ctx, dbgen.GetUserProfileForExportParams{
		UserID:         userID,
		OrganizationID: &organizationID,
	})
	if err != nil {
		return nil, err
	}
	profile := exportProfile{
		Email:           profileRow.Email,
		Phone:           profileRow.Phone,
		DisplayName:     profileRow.DisplayName,
		AvatarURL:       profileRow.AvatarUrl,
		Metadata:        metadataOf(profileRow.Metadata),
		Status:          profileRow.Status,
		EmailVerifiedAt: profileRow.EmailVerifiedAt,
		PhoneVerifiedAt: profileRow.PhoneVerifiedAt,
		CreatedAt:       profileRow.CreatedAt,
	}

	// auth.sessions.organization_id is nullable, so it takes a pointer.
	sessRows, err := s.q.ListUserSessionsForExport(ctx, dbgen.ListUserSessionsForExportParams{
		UserID:         userID,
		OrganizationID: &organizationID,
	})
	if err != nil {
		return nil, err
	}
	sessions := make([]exportSession, 0, len(sessRows))
	for _, r := range sessRows {
		// ip is COALESCE(host(ip), '') → interface{}; nil *string when empty.
		var ipPtr *string
		if ip, ok := r.Ip.(string); ok && ip != "" {
			ipPtr = &ip
		}
		sessions = append(sessions, exportSession{
			ID:         r.ID,
			IP:         ipPtr,
			UserAgent:  r.UserAgent,
			CreatedAt:  r.CreatedAt,
			LastSeenAt: r.LastSeenAt,
			RevokedAt:  r.RevokedAt,
		})
	}

	pkRows, err := s.q.ListUserPasskeysForExport(ctx, userID)
	if err != nil {
		return nil, err
	}
	passkeys := make([]exportPasskey, 0, len(pkRows))
	for _, r := range pkRows {
		passkeys = append(passkeys, exportPasskey{
			ID:         r.ID,
			Name:       r.Name,
			Transports: r.Transports,
			CreatedAt:  r.CreatedAt,
			LastUsedAt: r.LastUsedAt,
		})
	}

	roleRows, err := s.q.ListUserRolesForExport(ctx, dbgen.ListUserRolesForExportParams{
		UserID:         userID,
		OrganizationID: organizationID,
	})
	if err != nil {
		return nil, err
	}
	roles := make([]exportRole, 0, len(roleRows))
	for _, r := range roleRows {
		roles = append(roles, exportRole{RoleName: r.RoleName, GrantedAt: r.GrantedAt})
	}

	// ErrNoRows means no TOTP factor, so mfaEnabled stays false.
	mfaEnabled, err := s.q.GetUserMFAStatus(ctx, userID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	out := map[string]any{
		"profile":          profile,
		"sessions":         sessions,
		"passkeys":         passkeys,
		"roles":            roles,
		"mfa_totp_enabled": mfaEnabled,
		"generated_at":     time.Now().UTC(),
	}
	if err := exportSections(ctx, s.q, userID, &organizationID, out); err != nil {
		return nil, err
	}
	return out, nil
}

type exportSelfRole struct {
	RoleName     string    `json:"role_name"`
	Organization string    `json:"organization"`
	GrantedAt    time.Time `json:"granted_at"`
}

// ExportSelf assembles the current user's portable data across all their
// organizations, with no organization scope: a self-service user may have no organization.
// Credentials are excluded.
func (s *Service) ExportSelf(ctx context.Context, userID uuid.UUID) (map[string]any, error) {
	profileRow, err := s.q.GetOwnProfileForExport(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	profile := exportProfile{
		Email:           profileRow.Email,
		Phone:           profileRow.Phone,
		DisplayName:     profileRow.DisplayName,
		AvatarURL:       profileRow.AvatarUrl,
		Metadata:        metadataOf(profileRow.Metadata),
		Status:          profileRow.Status,
		EmailVerifiedAt: profileRow.EmailVerifiedAt,
		PhoneVerifiedAt: profileRow.PhoneVerifiedAt,
		CreatedAt:       profileRow.CreatedAt,
	}

	sessRows, err := s.q.ListOwnSessionsForExport(ctx, userID)
	if err != nil {
		return nil, err
	}
	sessions := make([]exportSession, 0, len(sessRows))
	for _, r := range sessRows {
		sessions = append(sessions, exportSession{
			ID:         r.ID,
			IP:         strutil.NilIfEmpty(r.Ip),
			UserAgent:  r.UserAgent,
			CreatedAt:  r.CreatedAt,
			LastSeenAt: r.LastSeenAt,
			RevokedAt:  r.RevokedAt,
		})
	}

	pkRows, err := s.q.ListUserPasskeysForExport(ctx, userID)
	if err != nil {
		return nil, err
	}
	passkeys := make([]exportPasskey, 0, len(pkRows))
	for _, r := range pkRows {
		passkeys = append(passkeys, exportPasskey{
			ID:         r.ID,
			Name:       r.Name,
			Transports: r.Transports,
			CreatedAt:  r.CreatedAt,
			LastUsedAt: r.LastUsedAt,
		})
	}

	roleRows, err := s.q.ListOwnRolesForExport(ctx, userID)
	if err != nil {
		return nil, err
	}
	roles := make([]exportSelfRole, 0, len(roleRows))
	for _, r := range roleRows {
		roles = append(roles, exportSelfRole{RoleName: r.RoleName, Organization: r.OrganizationName, GrantedAt: r.GrantedAt})
	}

	// ErrNoRows means no TOTP factor, so mfaEnabled stays false.
	mfaEnabled, err := s.q.GetUserMFAStatus(ctx, userID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	out := map[string]any{
		"profile":          profile,
		"sessions":         sessions,
		"passkeys":         passkeys,
		"roles":            roles,
		"mfa_totp_enabled": mfaEnabled,
		"generated_at":     time.Now().UTC(),
	}
	if err := exportSections(ctx, s.q, userID, nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

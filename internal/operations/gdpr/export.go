package gdpr

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	dbgen "github.com/qeetgroup/qeet-id-server/internal/operations/gdpr/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
)

// ExportRetention is how long a built export's payload is kept for download.
// It is then deleted and the request marked expired.
const ExportRetention = 7 * 24 * time.Hour

// ExpireExports deletes the payloads of exports that became ready longer ago
// than retention, marking them expired, and returns how many. Run on a
// schedule.
func ExpireExports(ctx context.Context, pool *pgxpool.Pool, retention time.Duration) (int64, error) {
	q := dbgen.New(pool)
	cutoff := time.Now().UTC().Add(-retention)
	return postgres.DeleteInBatches(ctx, func(ctx context.Context, limit int32) (int64, error) {
		return q.ExpireReadyExports(ctx, dbgen.ExpireReadyExportsParams{Cutoff: cutoff, MaxRows: limit})
	})
}

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
	organization := pgUUIDNullable(organizationID)

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
			Channel: r.Channel, Destination: maskDestination(r.Channel, r.Destination),
			VerifiedAt: toTimePtr(r.VerifiedAt), CreatedAt: r.CreatedAt,
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

// maskDestination keeps the first character of an email address's local part
// and the last three digits of a phone number.
func maskDestination(channel, dest string) string {
	if channel == "email" {
		at := strings.IndexByte(dest, '@')
		if at < 1 {
			return "***"
		}
		return dest[:1] + "***" + dest[at:]
	}
	if len(dest) <= 3 {
		return "***"
	}
	return "***" + dest[len(dest)-3:]
}

// metadataOf decodes a user's metadata column; an unreadable value exports as
// empty.
func metadataOf(raw []byte) map[string]any {
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

//go:build integration

package gdpr

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
)

// TestExportSelfCoversEveryOrganization checks that a person's own export,
// asked for while signed in to one organization and so scoped to it by
// row-level security, still lists their roles in every organization.
func TestExportSelfCoversEveryOrganization(t *testing.T) {
	home, other := dbtest.Organization(t), dbtest.Organization(t)
	a := dbtest.User(t, home, home, other)
	h := &Handler{Service: NewService(dbtest.Pool(t), 30*24*time.Hour)}
	rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(a.ID, home), h.Mount), http.MethodPost, "/account/export", nil)
	var body struct {
		Profile struct {
			Email string `json:"email"`
		} `json:"profile"`
		Roles []exportSelfRole `json:"roles"`
	}
	dbtest.Decode(t, rec, &body)
	if rec.Code != http.StatusOK || body.Profile.Email != a.Email || len(body.Roles) != 2 {
		t.Errorf("export: %d, %s with %d roles; want the account's roles in both organizations", rec.Code, body.Profile.Email, len(body.Roles))
	}
}

// signedIn records a sign-in of the account to organization in the audit trail.
func signedIn(t *testing.T, organization, userID uuid.UUID, action string) {
	t.Helper()
	ctx := dbtest.Context(t)
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := audit.Record(ctx, tx, audit.Event{OrganizationID: &organization, ActorUserID: &userID, Action: action,
		ResourceType: "user", ResourceID: &userID, IP: "203.0.113.7", UserAgent: "Firefox",
		Metadata: map[string]any{"method": "password"}}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// orgTraces gives the account, in a second organization, a linked account, a
// consent and a grant to one of its applications, and a group.
func orgTraces(t *testing.T, organization uuid.UUID, a dbtest.Account) {
	t.Helper()
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	client, group := dbtest.Unique("app"), uuid.New()
	for _, s := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO auth.oidc_clients (organization_id, client_id, name) VALUES ($1, $2, 'Payroll')`, []any{organization, client}},
		{`INSERT INTO auth.oidc_consents (user_id, client_id, scopes) VALUES ($1, $2, '{openid}')`, []any{a.ID, client}},
		{`INSERT INTO auth.oidc_refresh_tokens (token_hash, client_id, user_id, organization_id, expires_at) VALUES ($1, $2, $3, $4, NOW() + INTERVAL '1 hour')`, []any{dbtest.Unique("rt"), client, a.ID, organization}},
		{`INSERT INTO account.external_identities (user_id, organization_id, provider, subject) VALUES ($1, $2, 'saml', $3)`, []any{a.ID, organization, dbtest.Unique("sub")}},
		{`INSERT INTO organization.groups (id, organization_id, name) VALUES ($1, $2, 'Finance')`, []any{group, organization}},
		{`INSERT INTO organization.group_members (group_id, user_id, organization_id) VALUES ($1, $2, $3)`, []any{group, a.ID, organization}},
	} {
		if _, err := pool.Exec(ctx, s.sql, s.args...); err != nil {
			t.Fatalf("%s: %v", s.sql, err)
		}
	}
}

// TestExportsCoverEveryPart checks that both an organization's export of a
// member and the person's own export carry their metadata, linked accounts,
// masked email and SMS factors, application consents and grants, groups and
// sign-ins, and that the organization's export leaves out another
// organization's part.
func TestExportsCoverEveryPart(t *testing.T) {
	ctx := dbtest.Context(t)
	organization, other := dbtest.Organization(t), dbtest.Organization(t)
	admin := dbtest.User(t, organization, organization)
	a := dbtest.User(t, organization, organization, other)
	leaveTraces(t, organization, a)
	orgTraces(t, other, a)
	signedIn(t, organization, a.ID, "auth.login_succeeded")
	signedIn(t, organization, a.ID, "auth.sign_in_failed")
	signedIn(t, other, a.ID, "auth.login_succeeded")

	svc := NewService(dbtest.Pool(t), 0)
	h := requests(t, svc)
	var own exported
	rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(a.ID, organization), h.Mount), http.MethodPost, "/account/export", nil)
	dbtest.Decode(t, rec, &own)

	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, organization), h.Mount)
	var req ExportRequest
	dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodPost, "/gdpr/export", map[string]any{"user_id": a.ID}), &req)
	if err := svc.exportSweepTick(ctx); err != nil {
		t.Fatal(err)
	}
	var ready ExportRequest
	dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodGet, "/organizations/"+organization.String()+"/gdpr/export/"+req.ID.String(), nil), &ready)
	raw, err := json.Marshal(ready.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var org exported
	if err := json.Unmarshal(raw, &org); err != nil {
		t.Fatal(err)
	}

	for name, c := range map[string]struct {
		got  exported
		orgs int // organizations covered
	}{"own export": {own, 2}, "organization's export": {org, 1}} {
		e := c.got
		if e.Profile.Metadata["team"] != "core" || e.Profile.AvatarURL == "" {
			t.Errorf("%s: profile %+v, want the metadata and avatar", name, e.Profile)
		}
		// One per organization, and the platform's own social sign-in.
		if want := c.orgs + 1; len(e.Identities) != want {
			t.Errorf("%s: %d linked accounts, want %d", name, len(e.Identities), want)
		}
		if len(e.OTPFactors) != 1 || strings.Contains(e.OTPFactors[0].Destination, "555") {
			t.Errorf("%s: factors %+v, want the one, masked", name, e.OTPFactors)
		}
		if len(e.AppConsents) != c.orgs || len(e.AppGrants) != c.orgs || e.AppConsents[0].ClientName != "Payroll" {
			t.Errorf("%s: consents %+v and grants %+v, want one of each per organization", name, e.AppConsents, e.AppGrants)
		}
		if len(e.Groups) != c.orgs {
			t.Errorf("%s: groups %+v, want one per organization", name, e.Groups)
		}
		if want := c.orgs + 1; len(e.SignIns) != want || e.SignIns[0].IP != "203.0.113.7" {
			t.Errorf("%s: %d sign-ins %+v, want %d with their address", name, len(e.SignIns), e.SignIns, want)
		}
	}
	if strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "+15550100") {
		t.Error("the export carries a secret or an unmasked number")
	}
}

// exported is the part of an export the test reads.
type exported struct {
	Profile struct {
		Metadata  map[string]any `json:"metadata"`
		AvatarURL string         `json:"avatar_url"`
	} `json:"profile"`
	Identities  []exportIdentity  `json:"identities"`
	OTPFactors  []exportOTPFactor `json:"otp_factors"`
	AppConsents []exportConsent   `json:"app_consents"`
	AppGrants   []exportGrant     `json:"app_grants"`
	Groups      []exportGroup     `json:"groups"`
	SignIns     []exportSignIn    `json:"sign_ins"`
}

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

// signedIn records a sign-in of the account to tenant in the audit trail.
func signedIn(t *testing.T, tenant, userID uuid.UUID, action string) {
	t.Helper()
	ctx := dbtest.Context(t)
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err := audit.Record(ctx, tx, audit.Event{TenantID: &tenant, ActorUserID: &userID, Action: action,
		ResourceType: "user", ResourceID: &userID, IP: "203.0.113.7", UserAgent: "Firefox",
		Metadata: map[string]any{"method": "password"}}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// orgTraces gives the account, in a second organisation, a linked account, a
// consent and a grant to one of its applications, and a group.
func orgTraces(t *testing.T, tenant uuid.UUID, a dbtest.Account) {
	t.Helper()
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	client, group := dbtest.Unique("app"), uuid.New()
	for _, s := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO auth.oidc_clients (tenant_id, client_id, name) VALUES ($1, $2, 'Payroll')`, []any{tenant, client}},
		{`INSERT INTO auth.oidc_consents (user_id, client_id, scopes) VALUES ($1, $2, '{openid}')`, []any{a.ID, client}},
		{`INSERT INTO auth.oidc_refresh_tokens (token_hash, client_id, user_id, tenant_id, expires_at) VALUES ($1, $2, $3, $4, NOW() + INTERVAL '1 hour')`, []any{dbtest.Unique("rt"), client, a.ID, tenant}},
		{`INSERT INTO account.external_identities (user_id, tenant_id, provider, subject) VALUES ($1, $2, 'saml', $3)`, []any{a.ID, tenant, dbtest.Unique("sub")}},
		{`INSERT INTO tenant.groups (id, tenant_id, name) VALUES ($1, $2, 'Finance')`, []any{group, tenant}},
		{`INSERT INTO tenant.group_members (group_id, user_id, tenant_id) VALUES ($1, $2, $3)`, []any{group, a.ID, tenant}},
	} {
		if _, err := pool.Exec(ctx, s.sql, s.args...); err != nil {
			t.Fatalf("%s: %v", s.sql, err)
		}
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

// TestExportsCoverEveryPart checks that both an organisation's export of a
// member and the person's own export carry their metadata, linked accounts,
// masked email and SMS factors, application consents and grants, groups and
// sign-ins, and that the organisation's export leaves out another
// organisation's part.
func TestExportsCoverEveryPart(t *testing.T) {
	ctx := dbtest.Context(t)
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	a := dbtest.User(t, tenant, tenant, other)
	leaveTraces(t, tenant, a)
	orgTraces(t, other, a)
	signedIn(t, tenant, a.ID, "auth.login_succeeded")
	signedIn(t, tenant, a.ID, "auth.sign_in_failed")
	signedIn(t, other, a.ID, "auth.login_succeeded")

	svc := NewService(dbtest.Pool(t), 0)
	h := requests(t, svc)
	var own exported
	rec := dbtest.Do(t, dbtest.Serve(dbtest.Principal(a.ID, tenant), h.Mount), http.MethodPost, "/account/export", nil)
	dbtest.Decode(t, rec, &own)

	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, tenant), h.Mount)
	var req ExportRequest
	dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodPost, "/gdpr/export", map[string]any{"user_id": a.ID}), &req)
	if err := svc.exportSweepTick(ctx); err != nil {
		t.Fatal(err)
	}
	var ready ExportRequest
	dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodGet, "/tenants/"+tenant.String()+"/gdpr/export/"+req.ID.String(), nil), &ready)
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
		orgs int // organisations covered
	}{"own export": {own, 2}, "organisation's export": {org, 1}} {
		e := c.got
		if e.Profile.Metadata["team"] != "core" || e.Profile.AvatarURL == "" {
			t.Errorf("%s: profile %+v, want the metadata and avatar", name, e.Profile)
		}
		// One per organisation, and the platform's own social sign-in.
		if want := c.orgs + 1; len(e.Identities) != want {
			t.Errorf("%s: %d linked accounts, want %d", name, len(e.Identities), want)
		}
		if len(e.OTPFactors) != 1 || strings.Contains(e.OTPFactors[0].Destination, "555") {
			t.Errorf("%s: factors %+v, want the one, masked", name, e.OTPFactors)
		}
		if len(e.AppConsents) != c.orgs || len(e.AppGrants) != c.orgs || e.AppConsents[0].ClientName != "Payroll" {
			t.Errorf("%s: consents %+v and grants %+v, want one of each per organisation", name, e.AppConsents, e.AppGrants)
		}
		if len(e.Groups) != c.orgs {
			t.Errorf("%s: groups %+v, want one per organisation", name, e.Groups)
		}
		if want := c.orgs + 1; len(e.SignIns) != want || e.SignIns[0].IP != "203.0.113.7" {
			t.Errorf("%s: %d sign-ins %+v, want %d with their address", name, len(e.SignIns), e.SignIns, want)
		}
	}
	if strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "+15550100") {
		t.Error("the export carries a secret or an unmasked number")
	}
}

// TestExportPayloadExpires checks that a built export's payload is deleted
// after the retention window, or once its account is deleted for good,
// leaving the request expired and still naming the account, and that an
// export still within the window is kept.
func TestExportPayloadExpires(t *testing.T) {
	ctx, pool := dbtest.Context(t), dbtest.Pool(t)
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	old, fresh, gone := account(t, tenant), account(t, tenant), account(t, tenant)
	svc := NewService(pool, 0)
	asAdmin := dbtest.Serve(dbtest.Principal(admin.ID, tenant), requests(t, svc).Mount)
	queue := func(userID uuid.UUID) uuid.UUID {
		var req ExportRequest
		dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodPost, "/gdpr/export", map[string]any{"user_id": userID}), &req)
		return req.ID
	}
	oldReq, freshReq, goneReq := queue(old.ID), queue(fresh.ID), queue(gone.ID)
	if err := svc.exportSweepTick(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE account.export_requests SET completed_at = $2 WHERE id = $1`,
		oldReq, time.Now().Add(-ExportRetention-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE account.users SET status = 'deleted', deleted_at = NOW() WHERE id = $1`, gone.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM account.users WHERE id = $1`, gone.ID); err != nil {
		t.Fatal(err)
	}
	n, err := ExpireExports(ctx, pool, ExportRetention)
	if err != nil || n != 2 {
		t.Fatalf("expired %d (%v), want 2", n, err)
	}
	get := func(id uuid.UUID) ExportRequest {
		var out ExportRequest
		dbtest.Decode(t, dbtest.Do(t, asAdmin, http.MethodGet, "/tenants/"+tenant.String()+"/gdpr/export/"+id.String(), nil), &out)
		return out
	}
	if got := get(goneReq); got.Status != "expired" || got.Payload != nil || got.UserID != gone.ID {
		t.Errorf("the export of a deleted account: %s for %s, want expired, without a payload, naming the account", got.Status, got.UserID)
	}
	if got := get(oldReq); got.Status != "expired" || got.Payload != nil {
		t.Errorf("an export past retention: %s with payload %v, want expired without one", got.Status, got.Payload != nil)
	}
	if got := get(freshReq); got.Status != "ready" || got.Payload == nil {
		t.Errorf("a recent export: %s, want ready with its payload", got.Status)
	}
}

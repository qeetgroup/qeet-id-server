package connections

import (
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/cmd/seed/internal/world"
	"github.com/qeetgroup/qeet-id-server/internal/federation/oidcsso"
	"github.com/qeetgroup/qeet-id-server/internal/federation/saml"
	"github.com/qeetgroup/qeet-id-server/internal/federation/ssosync"
)

// groupMapping is the groups attribute an organisation's identity provider
// sends, and which of its groups land in which of the organisation's.
type groupMapping struct {
	attribute string
	groups    [][2]string // identity-provider group, the organisation's group
}

// groupMappings are each organisation's: Okta sends group names, Microsoft
// Entra ID the groups' object IDs. Only ordinary groups are mapped: one whose
// roles carry administration can't be handed out by the identity provider.
var groupMappings = map[string]groupMapping{
	"northwind": {attribute: "groups", groups: [][2]string{
		{"NW-Credit-Underwriting", "Credit Underwriting"}, {"NW-Collections", "Collections"},
		{"NW-Disbursement", "Disbursement"}, {"NW-Customer-Service", "Customer Service"},
	}},
	"meridian": {attribute: "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups", groups: [][2]string{
		{"3f1b6c2e-8d4a-4e71-9b0c-5a2f7d9e1c43", "Nursing"}, {"a8e02d71-4c9b-4f36-8e15-0b7d3c6a9f28", "Emergency Department"},
		{"5c7d9e1f-2a3b-4c5d-8e6f-7a8b9c0d1e2f", "Radiology"}, {"e1d2c3b4-a5f6-4789-9a0b-c1d2e3f4a5b6", "Billing & Coding"},
	}},
}

// groupSync makes conn send o's groups and maps them to o's own, a day after
// the connection went live: from then on a sign-in through it adds and
// removes people from those groups.
func (f *fed) groupSync(o *world.Org, conn uuid.UUID, live time.Time) {
	m, ok := groupMappings[o.Spec.Slug]
	if !ok {
		return
	}
	w := f.w
	at := w.WorkHours(live.Add(24*time.Hour), o.Loc)
	by := adminAt(o, at)
	w.At(at, func() {
		w.Exec("groups attribute", `UPDATE tenant.saml_connections SET groups_attribute = $3 WHERE id = $1 AND tenant_id = $2`, conn, o.ID, m.attribute)
	})
	f.record(at, o, by, "saml.connection_updated", "saml_connection", &conn, map[string]any{"groups_attribute": m.attribute})
	for i, g := range m.groups {
		gid, ok := o.Groups[g[1]]
		if !ok {
			continue
		}
		t := at.Add(time.Duration(2+i*3) * time.Minute)
		var id uuid.UUID
		w.At(t, func() {
			w.Tx("map "+g[0], func(tx pgx.Tx) error {
				mp, err := w.Deps.SSOGroups.Service.CreateMapping(w.Ctx, tx, o.ID, conn, ssosync.MappingInput{IdPGroup: g[0], GroupID: gid}, g[1])
				if err == nil {
					id = mp.ID
				}
				return err
			})
		})
		f.record(t, o, by, "saml.group_mapping_created", "saml_connection", &conn,
			map[string]any{"mapping_id": id, "idp_group": g[0], "group_id": gid, "group": g[1]})
	}
}

// breakGlass names o's break-glass members once single sign-on is enforced:
// the owner and an administrator, who may still sign in with a password and
// second factor if the identity provider is down.
func (f *fed) breakGlass(o *world.Org, live time.Time) {
	w := f.w
	at := w.WorkHours(live.Add(2*24*time.Hour), o.Loc)
	members := []*world.Person{o.Owner}
	if a := adminAt(o, at); a != o.Owner {
		members = append(members, a)
	}
	for i, p := range members {
		t := at.Add(time.Duration(i) * time.Minute)
		w.At(t, func() {
			w.Check(w.Deps.DomainVerify.Service.SetBreakGlass(w.Ctx, o.ID, p.ID, true, o.Owner.Actor()), "break-glass "+p.Email)
		})
	}
}

// assign makes only the people assigned to SAML application sp able to sign
// in to it, then assigns s's groups and people, as by at t.
func (f *fed) assign(o *world.Org, by *world.Person, t time.Time, sp uuid.UUID, s spec) {
	if len(s.groups) == 0 && len(s.users) == 0 {
		return
	}
	w := f.w
	required := true
	w.At(t, func() {
		w.Tx("assignment required", func(tx pgx.Tx) error {
			_, err := w.Deps.SAML.IdP.UpdateSP(w.Ctx, tx, sp, o.ID, saml.UpdateSPInput{AssignmentRequired: &required})
			return err
		})
	})
	f.record(t, o, by, "saml.sp_updated", "saml_service_provider", &sp, map[string]any{"assignment_required": true})
	for i, g := range s.groups {
		gid, ok := o.Groups[g]
		if !ok {
			continue
		}
		at := t.Add(time.Duration(1+i) * time.Minute)
		w.At(at, func() {
			w.Tx("assign "+g, func(tx pgx.Tx) error {
				_, err := w.Deps.SAML.IdP.AssignGroup(w.Ctx, tx, o.ID, sp, gid, &by.ID)
				return err
			})
		})
		f.record(at, o, by, "saml.sp_group_assigned", "saml_service_provider", &sp, map[string]any{"group_id": gid})
	}
	for i, e := range s.users {
		p := o.Person(e)
		if p == nil || p.Status != world.StatusActive {
			continue
		}
		at := t.Add(time.Duration(5+i) * time.Minute)
		w.At(at, func() {
			w.Tx("assign "+e, func(tx pgx.Tx) error {
				_, err := w.Deps.SAML.IdP.AssignUser(w.Ctx, tx, o.ID, sp, p.ID, &by.ID)
				return err
			})
		})
		f.record(at, o, by, "saml.sp_user_assigned", "saml_service_provider", &sp, map[string]any{"user_id": p.ID})
	}
}

// spec is who a SAML application is assigned to: groups by name, people by
// email.
type spec struct{ groups, users []string }

// oidcConnections are organisations' OpenID Connect identity providers: Lumen
// Labs signs in its contract developers from their agency's Microsoft Entra ID.
var oidcConnections = map[string]struct {
	name, entraTenant string
	share             float64 // of the Engineering department who sign in through it
}{
	"lumen": {name: "Brightwave Studios contractors (Microsoft Entra ID)", entraTenant: "7d1c5b8e-2f4a-4b9d-a3c6-9e8f1d2b4a70", share: 0.25},
}

// oidcConnection adds o's OpenID Connect identity provider, live a day later,
// and links the people who sign in through it.
func (f *fed) oidcConnection(o *world.Org) {
	c, ok := oidcConnections[o.Spec.Slug]
	if !ok || !o.Has("pro") {
		return
	}
	w := f.w
	created := w.WorkHours(o.Spec.Since.Add(40*24*time.Hour), o.Loc)
	by := adminAt(o, created)
	groups := "groups"
	in := oidcsso.CreateInput{
		Name: c.name, Issuer: "https://login.microsoftonline.com/" + c.entraTenant + "/v2.0",
		ClientID: f.uuid().String(), ClientSecret: f.token(alnum, 3) + "8Q~" + f.token(alnum+"-_.~", 34),
		Scopes: []string{"openid", "email", "profile"}, AllowedIdPTenantIDs: []string{c.entraTenant},
		ClaimMapping: &oidcsso.ClaimMappingInput{Groups: &groups}, Status: "draft",
	}
	var id uuid.UUID
	w.At(created, func() {
		w.Tx("OIDC connection "+c.name, func(tx pgx.Tx) error {
			conn, err := w.Deps.OIDCSSO.Service.Create(w.Ctx, tx, o.ID, in)
			if err == nil {
				id = conn.ID
			}
			return err
		})
	})
	f.record(created, o, by, "oidc_connection.created", "oidc_connection", &id, map[string]any{"name": c.name, "issuer": in.Issuer})
	live := created.Add(26 * time.Hour)
	w.At(live, func() {
		w.Exec("OIDC connection live", `UPDATE tenant.oidc_connections SET status = 'active', updated_at = NOW() WHERE id = $1 AND tenant_id = $2`, id, o.ID)
	})
	f.record(live, o, by, "oidc_connection.updated", "oidc_connection", &id, map[string]any{"status": "active"})

	batch := &pgx.Batch{}
	var last time.Time
	for _, p := range o.InDept("Engineering") {
		if p.Status != world.StatusActive || p.Role == world.RoleOwner || p.Login != "" || !w.Chance(c.share) {
			continue
		}
		from := later(p.Joined.Add(time.Hour), live.Add(time.Hour))
		if !from.Before(w.Now.Add(-2 * time.Hour)) {
			continue
		}
		linked := f.workTime(from, w.Now.Add(-2*time.Hour), p.Loc)
		last = later(last, linked)
		batch.Queue(`INSERT INTO account.external_identities (id, user_id, tenant_id, provider, connection_id, subject, email, metadata, linked_at)
			VALUES ($1, $2, $3, 'oidc', $4, $5, $6, $7, $8)`, uuid.New(), p.ID, o.ID, id, f.token(alnum+"-_", 43), p.Email,
			map[string]any{"tid": c.entraTenant, "iss": in.Issuer}, linked)
	}
	w.Check(w.Admin.SendBatch(w.Ctx, batch).Close(), "link OIDC identities in "+o.Spec.Slug)
	if !last.IsZero() {
		w.Exec("OIDC last sign-in", `UPDATE tenant.oidc_connections SET last_login_at = $3 WHERE id = $1 AND tenant_id = $2`,
			id, o.ID, f.ago(20*time.Minute, 3*time.Hour))
	}
}

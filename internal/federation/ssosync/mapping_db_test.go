//go:build integration

package ssosync

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/access/authorization/rbac"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// samlConnection creates a SAML connection of organization.
func samlConnection(t *testing.T, organization uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := dbtest.Pool(t).QueryRow(context.Background(), `
		INSERT INTO organization.saml_connections (organization_id, name, idp_entity_id, idp_sso_url, idp_certificate)
		VALUES ($1, 'Okta', 'https://idp.example.test', 'https://idp.example.test/sso', 'cert') RETURNING id
	`, organization).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// ldapConnection creates an LDAP connection of organization.
func ldapConnection(t *testing.T, organization uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := dbtest.Pool(t).QueryRow(context.Background(), `
		INSERT INTO organization.ldap_connections (organization_id, name, server_url, bind_dn, bind_password_ct, bind_password_nonce, base_dn)
		VALUES ($1, 'Directory', 'ldap://127.0.0.1:1', 'cn=service', '\x00', '\x00', 'dc=example') RETURNING id
	`, organization).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestGroupMappings checks the mapping API: whoever maps a group must hold the
// authority its roles carry, a group granting the owner role or an
// administrative permission can't be mapped even by an owner, a connection or
// group of another organization answers 404, and removing the last mapping to
// a group ends the memberships of it the connection's sign-ins made.
func TestGroupMappings(t *testing.T) {
	ctx := context.Background()
	pool := dbtest.Pool(t)
	organization := dbtest.Organization(t)
	conn, ldapConn := samlConnection(t, organization), ldapConnection(t, organization)
	owner := ownerRole(t, organization)
	payments := makeGroup(t, organization, "Payments", "")
	auditors := makeGroup(t, organization, "Auditors", "", dbtest.Role(t, organization, "audit.read"))
	analysts := makeGroup(t, organization, "Analysts", "", dbtest.Role(t, organization, "analytics.read"))
	privacy := makeGroup(t, organization, "Privacy", "", dbtest.Role(t, organization, "gdpr.write"))
	admins := makeGroup(t, organization, "Admins", "", dbtest.Role(t, organization, "user.write"))
	owners := makeGroup(t, organization, "Owners", "", owner)

	editor := dbtest.User(t, organization)
	dbtest.Assign(t, editor.ID, organization, dbtest.Role(t, organization, "group.write", "connection.read", "audit.read"))
	grants := rbac.NewRepository(pool).CheckGrantGroup
	as := func(userID uuid.UUID) http.Handler {
		return dbtest.Serve(dbtest.Principal(userID, organization), (&Handler{Service: NewService(pool), GrantCheck: grants}).Mount)
	}
	h := as(editor.ID)
	base := "/organizations/" + organization.String() + "/saml/" + conn.String() + "/group-mappings"
	post := func(h http.Handler, path, idpGroup string, g uuid.UUID) *httptest.ResponseRecorder {
		return dbtest.Do(t, h, http.MethodPost, path, map[string]any{"idp_group": idpGroup, "group_id": g})
	}
	mapped := func(rec *httptest.ResponseRecorder) Mapping {
		t.Helper()
		var m Mapping
		dbtest.Decode(t, rec, &m)
		if rec.Code != http.StatusCreated || m.ID == uuid.Nil {
			t.Fatalf("map: %d %s", rec.Code, rec.Body.String())
		}
		return m
	}

	first := mapped(post(h, base, " Payments ", payments))
	if first.IdPGroup != "Payments" || first.GroupID != payments || !strings.HasPrefix(first.GroupName, "Payments") {
		t.Errorf("mapping %+v, want Payments to the Payments group", first)
	}
	mapped(post(h, base, "Auditors", auditors))
	ownerAccount := dbtest.User(t, organization)
	dbtest.Assign(t, ownerAccount.ID, organization, owner)
	asLDAP := "/organizations/" + organization.String() + "/ldap/" + conn.String() + "/group-mappings"
	for name, c := range map[string]struct {
		h              http.Handler
		path, idpGroup string
		group          uuid.UUID
		status         int
		code           string
	}{
		"the same pair in another case":     {h, base, "PAYMENTS", payments, http.StatusConflict, CodeGroupMappingExists},
		"a group with authority not held":   {h, base, "Analysts", analysts, http.StatusForbidden, errs.CodeRBACGrantExceedsCaller},
		"a group granting user.write":       {h, base, "Admins", admins, http.StatusUnprocessableEntity, CodeGroupMappingPrivileged},
		"a group granting gdpr.write":       {h, base, "Privacy", privacy, http.StatusUnprocessableEntity, CodeGroupMappingPrivileged},
		"the owners' group":                 {h, base, "Owners", owners, http.StatusUnprocessableEntity, CodeGroupMappingPrivileged},
		"the owners' group, as an owner":    {as(ownerAccount.ID), base, "Owners", owners, http.StatusUnprocessableEntity, CodeGroupMappingPrivileged},
		"an empty identity provider group":  {h, base, "   ", payments, http.StatusUnprocessableEntity, errs.CodeValidation},
		"a group that doesn't exist":        {h, base, "Ghosts", uuid.New(), http.StatusNotFound, errs.CodeGroupNotFound},
		"the SAML connection as LDAP's one": {h, asLDAP, "Payments", payments, http.StatusNotFound, ""},
	} {
		rec := post(c.h, c.path, c.idpGroup, c.group)
		if rec.Code != c.status || !strings.Contains(rec.Body.String(), c.code) {
			t.Errorf("%s: %d %s, want %d %s", name, rec.Code, rec.Body.String(), c.status, c.code)
		}
	}
	mapped(post(h, "/organizations/"+organization.String()+"/ldap/"+ldapConn.String()+"/group-mappings", "CN=Payments,OU=Groups,DC=corp", payments))
	if ids := dbtest.IDs(t, dbtest.Do(t, h, http.MethodGet, base, nil)); len(ids) != 2 {
		t.Errorf("the SAML connection lists %d mappings, want 2", len(ids))
	}
	if n := audited(t, organization, "saml.group_mapping_created", conn, "user"); n != 2 {
		t.Errorf("%d saml.group_mapping_created events, want 2", n)
	}

	// Another organization's connection, group and mapping are out of reach.
	theirs := dbtest.Organization(t)
	theirConn := samlConnection(t, theirs)
	theirGroup := makeGroup(t, theirs, "Theirs", "")
	mapGroup(t, theirs, theirConn, "Theirs", theirGroup)
	var theirMapping uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM organization.sso_group_mappings WHERE organization_id = $1`, theirs).Scan(&theirMapping); err != nil {
		t.Fatal(err)
	}
	ourPathTheirConn := "/organizations/" + organization.String() + "/saml/" + theirConn.String() + "/group-mappings"
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"list their connection's":       dbtest.Do(t, h, http.MethodGet, ourPathTheirConn, nil),
		"map on their connection":       post(h, ourPathTheirConn, "Payments", payments),
		"delete on their connection":    dbtest.Do(t, h, http.MethodDelete, ourPathTheirConn+"/"+theirMapping.String(), nil),
		"delete their mapping as ours":  dbtest.Do(t, h, http.MethodDelete, base+"/"+theirMapping.String(), nil),
		"map our connection to theirs":  post(h, base, "Theirs", theirGroup),
		"their organization in the URL": post(h, "/organizations/"+theirs.String()+"/saml/"+theirConn.String()+"/group-mappings", "Payments", payments),
	} {
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusForbidden {
			t.Errorf("%s: %d %s, want 404 or 403", name, rec.Code, rec.Body.String())
		}
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM organization.sso_group_mappings WHERE organization_id = $1`, theirs); n != 1 {
		t.Errorf("their organization has %d mappings, want its one", n)
	}

	// Removing a mapping ends the sign-ins' memberships of its group only once
	// no other mapping of the connection reaches it.
	person := dbtest.User(t, organization)
	second := mapped(post(h, base, "Pay", payments))
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, tx, SignIn{OrganizationID: organization, UserID: person.ID, ConnectionID: conn, Provider: "saml",
		Groups: []string{"Payments", "Pay"}, Actor: audit.Actor{Type: "saml"}}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	inPayments := func() int {
		return dbtest.Count(t, `SELECT count(*) FROM organization.group_members WHERE organization_id = $1 AND group_id = $2 AND user_id = $3`, organization, payments, person.ID)
	}
	if inPayments() != 1 {
		t.Fatal("the sign-in didn't put the person in Payments")
	}
	if rec := dbtest.Do(t, h, http.MethodDelete, base+"/"+first.ID.String(), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if inPayments() != 1 {
		t.Error("the person left Payments while another mapping still reaches it")
	}
	if rec := dbtest.Do(t, h, http.MethodDelete, base+"/"+second.ID.String(), nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body.String())
	}
	if inPayments() != 0 {
		t.Error("the person is still in Payments after its last mapping went")
	}
	if n := audited(t, organization, "group.member_removed", payments, "user"); n != 1 {
		t.Errorf("%d member_removed events by the administrator, want 1", n)
	}
	if n := audited(t, organization, "saml.group_mapping_deleted", conn, "user"); n != 2 {
		t.Errorf("%d saml.group_mapping_deleted events, want 2", n)
	}
	if rec := dbtest.Do(t, h, http.MethodDelete, base+"/"+second.ID.String(), nil); rec.Code != http.StatusNotFound {
		t.Errorf("delete again: %d, want 404", rec.Code)
	}
}

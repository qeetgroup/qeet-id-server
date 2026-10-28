//go:build integration

package saml

// Database tests for what an organisation's IdP tells its service providers
// about a person: the NameID each asks for, and the attributes it maps, from
// that organisation's data only.

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/google/uuid"

	"github.com/qeetgroup/qeet-id-server/internal/platform/database/dbtest"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// asserted is what the assertion of a successful SSO response says.
type asserted struct {
	nameID, format string
	attributes     map[string]assertionAttribute
}

// assertedIn reads the assertion a successful SSO response posts.
func assertedIn(t *testing.T, rec *httptest.ResponseRecorder) asserted {
	t.Helper()
	m := samlResponseRe.FindStringSubmatch(rec.Body.String())
	if rec.Code != http.StatusOK || m == nil {
		t.Fatalf("SSO = %d %s, want an assertion", rec.Code, rec.Body.String())
	}
	raw, err := base64.StdEncoding.DecodeString(html.UnescapeString(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		t.Fatal(err)
	}
	nid := doc.FindElement("//Assertion/Subject/NameID")
	if nid == nil {
		t.Fatalf("assertion has no NameID: %s", raw)
	}
	out := asserted{nameID: nid.Text(), format: nid.SelectAttrValue("Format", ""), attributes: map[string]assertionAttribute{}}
	for _, a := range doc.FindElements("//Assertion/AttributeStatement/Attribute") {
		attr := assertionAttribute{name: a.SelectAttrValue("Name", ""), nameFormat: a.SelectAttrValue("NameFormat", "")}
		for _, v := range a.SelectElements("AttributeValue") {
			attr.values = append(attr.values, v.Text())
		}
		out.attributes[attr.name] = attr
	}
	return out
}

// spWith registers an active service provider in tenant with in's settings.
func spWith(t *testing.T, ctx context.Context, idp *IdP, tenant uuid.UUID, in CreateSPInput) *ServiceProvider {
	t.Helper()
	in.Name, in.Status = "App", "active"
	in.EntityID = "https://" + dbtest.Unique("sp") + ".example.test"
	in.ACSURL = in.EntityID + "/acs"
	tx, err := dbtest.Pool(t).Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	sp, err := idp.CreateSP(ctx, tx, tenant, in)
	if err != nil {
		t.Fatalf("CreateSP: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return sp
}

// execSQL runs a statement for a test's fixtures.
func execSQL(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := dbtest.Pool(t).Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// newGroup creates a group in tenant with members of it.
func newGroup(t *testing.T, tenant uuid.UUID, name string, members ...uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := dbtest.Pool(t).QueryRow(context.Background(),
		`INSERT INTO tenant.groups (tenant_id, name) VALUES ($1, $2) RETURNING id`, tenant, name).Scan(&id); err != nil {
		t.Fatalf("create group: %v", err)
	}
	for _, member := range members {
		execSQL(t, `INSERT INTO tenant.group_members (group_id, user_id, tenant_id) VALUES ($1, $2, $3)`, id, member, tenant)
	}
	return id
}

// roleName is the name of the role id.
func roleName(t *testing.T, id uuid.UUID) string {
	t.Helper()
	var name string
	if err := dbtest.Pool(t).QueryRow(context.Background(), `SELECT name FROM rbac.roles WHERE id = $1`, id).Scan(&name); err != nil {
		t.Fatal(err)
	}
	return name
}

// TestIdPNameIDFollowsTheSPFormat checks that each SP gets the NameID it was
// set up for: the email by default, a persistent value of the person's own at
// that SP which outlasts an email change, the user id, or a metadata value,
// and that a person with no such value is refused, audited. A service
// provider saved before these settings keeps getting the email and name.
func TestIdPNameIDFollowsTheSPFormat(t *testing.T) {
	ctx := dbtest.Context(t)
	s := newIdPSide(t)
	tenant := dbtest.Tenant(t)
	member := dbtest.User(t, tenant)
	execSQL(t, `UPDATE "user".users SET display_name = 'Asha Rao' WHERE id = $1`, member.ID)
	cookie := s.signIn(member.ID)
	sso := func(sp *ServiceProvider) *httptest.ResponseRecorder {
		return idpGet(t, s.router, "/saml/idp/"+tenant.String()+"/sso?sp="+sp.ID.String(), cookie)
	}

	byEmail := spWith(t, ctx, s.idp, tenant, CreateSPInput{})
	if byEmail.NameIDFormat != nameIDEmail || byEmail.NameIDAttribute != sourceEmail || !reflect.DeepEqual(byEmail.Attributes, defaultAttributes()) {
		t.Errorf("default SP %+v, want an emailAddress NameID of the email and the default attributes", byEmail)
	}
	got := assertedIn(t, sso(byEmail))
	wantDefault := map[string]assertionAttribute{
		"email": {"email", attrNameFormatBasic, []string{member.Email}},
		"name":  {"name", attrNameFormatBasic, []string{"Asha Rao"}},
	}
	if got.nameID != member.Email || got.format != nameIDEmail || !reflect.DeepEqual(got.attributes, wantDefault) {
		t.Errorf("default SP was told %+v, want the email as an emailAddress NameID, and the email and name", got)
	}

	var legacyID uuid.UUID
	if err := dbtest.Pool(t).QueryRow(ctx, `
		INSERT INTO tenant.saml_service_providers (tenant_id, name, entity_id, acs_url, name_id_format, name_id_attribute, status)
		VALUES ($1, 'Old app', 'https://old.example.test', 'https://old.example.test/acs', $2, 'email', 'active') RETURNING id
	`, tenant, nameIDPersistent).Scan(&legacyID); err != nil {
		t.Fatal(err)
	}
	legacy, err := s.idp.GetSP(ctx, legacyID, tenant)
	if err != nil || !reflect.DeepEqual(legacy.Attributes, defaultAttributes()) {
		t.Fatalf("an SP saved without the new settings = %+v, %v; want the default attributes", legacy, err)
	}

	persistent := spWith(t, ctx, s.idp, tenant, CreateSPInput{NameIDFormat: nameIDPersistent})
	if persistent.NameIDAttribute != sourcePersistentID {
		t.Errorf("a persistent SP's NameID comes from %q, want %q", persistent.NameIDAttribute, sourcePersistentID)
	}
	first := assertedIn(t, sso(persistent))
	if raw, err := hex.DecodeString(first.nameID); err != nil || len(raw) != 16 || first.format != nameIDPersistent ||
		strings.Contains(first.nameID, member.Email) || first.nameID == member.ID.String() {
		t.Errorf("persistent NameID %q (%s), want an opaque value", first.nameID, first.format)
	}
	if old := assertedIn(t, sso(legacy)); old.nameID == member.Email || old.format != nameIDPersistent || old.nameID == first.nameID {
		t.Errorf("an SP saved as persistent with the email was told %q, want a persistent value of its own", old.nameID)
	}
	execSQL(t, `UPDATE "user".users SET email = $2 WHERE id = $1`, member.ID, dbtest.Unique("moved")+"@example.test")
	if again := assertedIn(t, sso(persistent)); again.nameID != first.nameID {
		t.Errorf("after an email change the persistent NameID is %q, want %q", again.nameID, first.nameID)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM tenant.saml_idp_persistent_ids WHERE tenant_id = $1 AND user_id = $2`, tenant, member.ID); n != 2 {
		t.Errorf("%d persistent NameIDs kept, want one for each persistent SP", n)
	}

	byUserID := spWith(t, ctx, s.idp, tenant, CreateSPInput{NameIDFormat: nameIDUnspecified, NameIDAttribute: sourceUserID})
	if got := assertedIn(t, sso(byUserID)); got.nameID != member.ID.String() || got.format != nameIDUnspecified {
		t.Errorf("user-id SP was told %q (%s), want %s", got.nameID, got.format, member.ID)
	}

	byMetadata := spWith(t, ctx, s.idp, tenant, CreateSPInput{NameIDFormat: nameIDUnspecified, NameIDAttribute: "metadata.employee_id"})
	rec := sso(byMetadata)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), errs.CodeSAMLNameIDUnavailable) || strings.Contains(rec.Body.String(), "SAMLResponse") {
		t.Errorf("metadata NameID without the key: %d %s, want 403 %s", rec.Code, rec.Body.String(), errs.CodeSAMLNameIDUnavailable)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'saml.idp_assertion_refused'
		AND resource_id = $2 AND actor_user_id = $3 AND metadata->>'reason' = 'name_id_unavailable'`, tenant, byMetadata.ID, member.ID); n != 1 {
		t.Errorf("%d refusals audited, want 1", n)
	}
	execSQL(t, `UPDATE "user".users SET metadata = '{"employee_id": "E-7"}' WHERE id = $1`, member.ID)
	if got := assertedIn(t, sso(byMetadata)); got.nameID != "E-7" {
		t.Errorf("metadata SP was told %q, want E-7", got.nameID)
	}
}

// TestIdPSendsMappedAttributesOfItsOrganisationOnly checks that an SP gets
// each attribute it maps under its name and format, with the groups, roles
// and directory names of its own organisation, never those another
// organisation the person belongs to holds.
func TestIdPSendsMappedAttributesOfItsOrganisationOnly(t *testing.T) {
	ctx := dbtest.Context(t)
	s := newIdPSide(t)
	tenant, other := dbtest.Tenant(t), dbtest.Tenant(t)
	member := dbtest.User(t, tenant)
	direct, viaGroup := dbtest.Role(t, tenant), dbtest.Role(t, tenant)
	dbtest.Assign(t, member.ID, tenant, direct)
	dbtest.Assign(t, member.ID, other, dbtest.Role(t, other))
	newGroup(t, tenant, "Finance", member.ID)
	admins := newGroup(t, tenant, "Admins", member.ID)
	execSQL(t, `INSERT INTO rbac.group_roles (tenant_id, group_id, role_id) VALUES ($1, $2, $3)`, tenant, admins, viaGroup)
	newGroup(t, other, "Elsewhere", member.ID)
	profile := `INSERT INTO tenant.directory_profiles (tenant_id, user_id, connection_id, profile) VALUES ($1, $2, $3, $4)`
	execSQL(t, profile, tenant, member.ID, "scim:"+tenant.String(), `{"first_name": "Asha", "last_name": "Rao"}`)
	execSQL(t, profile, other, member.ID, "scim:"+other.String(), `{"first_name": "Someone", "last_name": "Else"}`)
	execSQL(t, `UPDATE "user".users SET metadata = '{"department": "Finance", "family_name": "Rao-Iyer", "api_key": "kept"}' WHERE id = $1`, member.ID)

	sp := spWith(t, ctx, s.idp, tenant, CreateSPInput{Attributes: &[]AttributeMapping{
		{Name: "mail", Source: sourceEmail},
		{Name: "givenName", Source: sourceGivenName},
		{Name: "urn:oid:2.5.4.4", Source: sourceFamilyName, NameFormat: "uri"},
		{Name: "memberOf", Source: sourceGroups},
		{Name: "roles", Source: sourceRoles},
		{Name: "dept", Source: "metadata.department"},
		{Name: "display", Source: sourceDisplayName},
		{Name: "missing", Source: "metadata.none"},
	}})
	got := assertedIn(t, idpGet(t, s.router, "/saml/idp/"+tenant.String()+"/sso?sp="+sp.ID.String(), s.signIn(member.ID)))
	roles := []string{roleName(t, direct), roleName(t, viaGroup)}
	sort.Strings(roles)
	want := map[string]assertionAttribute{
		"mail":            {"mail", attrNameFormatBasic, []string{member.Email}},
		"givenName":       {"givenName", attrNameFormatBasic, []string{"Asha"}},
		"urn:oid:2.5.4.4": {"urn:oid:2.5.4.4", attrNameFormatURI, []string{"Rao-Iyer"}},
		"memberOf":        {"memberOf", attrNameFormatBasic, []string{"Admins", "Finance"}},
		"roles":           {"roles", attrNameFormatBasic, roles},
		"dept":            {"dept", attrNameFormatBasic, []string{"Finance"}},
	}
	if !reflect.DeepEqual(got.attributes, want) {
		t.Errorf("SP was told %+v,\nwant %+v", got.attributes, want)
	}
	if got.nameID != member.Email {
		t.Errorf("NameID %q, want the email", got.nameID)
	}
}

// TestSPSettingsAreCheckedAndAudited checks that the registry refuses NameID
// settings and attributes that don't fit, moves the NameID's source with its
// format, and audits what a change set.
func TestSPSettingsAreCheckedAndAudited(t *testing.T) {
	tenant := dbtest.Tenant(t)
	admin := dbtest.User(t, tenant, tenant)
	idp, _ := newIdPRouter(t, sessionsByCookie{})
	h := dbtest.Serve(dbtest.Principal(admin.ID, tenant), (&Handler{Service: &Service{}, IdP: idp}).Mount)
	base := "/tenants/" + tenant.String() + "/saml-providers"
	register := func(extra map[string]any) map[string]any {
		body := map[string]any{"name": "App", "entity_id": "https://" + dbtest.Unique("sp") + ".example.test", "acs_url": "https://sp.example.test/acs"}
		for k, v := range extra {
			body[k] = v
		}
		return body
	}

	for _, c := range []struct {
		name  string
		extra map[string]any
		code  string
	}{
		{"a transient NameID", map[string]any{"name_id_format": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"}, errs.CodeSAMLNameIDFormatInvalid},
		{"an emailAddress NameID of the user id", map[string]any{"name_id_attribute": "user_id"}, errs.CodeSAMLNameIDAttributeInvalid},
		{"a persistent NameID of the email", map[string]any{"name_id_format": nameIDPersistent, "name_id_attribute": "email"}, errs.CodeSAMLNameIDAttributeInvalid},
		{"an attribute of a secret", map[string]any{"attributes": []map[string]any{{"name": "pw", "source": "password_hash"}}}, errs.CodeSAMLAttributesInvalid},
	} {
		if rec := dbtest.Do(t, h, http.MethodPost, base, register(c.extra)); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), c.code) {
			t.Errorf("registering %s: %d %s, want 422 %s", c.name, rec.Code, rec.Body.String(), c.code)
		}
	}

	rec := dbtest.Do(t, h, http.MethodPost, base, register(map[string]any{
		"name_id_format": nameIDPersistent,
		"attributes":     []map[string]any{{"name": "uid", "source": "user_id", "name_format": "uri"}},
	}))
	var sp ServiceProvider
	dbtest.Decode(t, rec, &sp)
	if rec.Code != http.StatusCreated || sp.NameIDAttribute != sourcePersistentID ||
		!reflect.DeepEqual(sp.Attributes, []AttributeMapping{{Name: "uid", Source: sourceUserID, NameFormat: "uri"}}) {
		t.Fatalf("register = %d %s, want a persistent NameID and the uid attribute", rec.Code, rec.Body.String())
	}
	path := base + "/" + sp.ID.String()

	patch := func(body map[string]any) (*httptest.ResponseRecorder, ServiceProvider) {
		rec := dbtest.Do(t, h, http.MethodPatch, path, body)
		var out ServiceProvider
		if rec.Code == http.StatusOK {
			dbtest.Decode(t, rec, &out)
		}
		return rec, out
	}
	if rec, out := patch(map[string]any{"name_id_format": nameIDEmail}); rec.Code != http.StatusOK || out.NameIDAttribute != sourceEmail {
		t.Errorf("switching to an emailAddress NameID: %d %s, want its source moved to the email", rec.Code, rec.Body.String())
	}
	if rec, _ := patch(map[string]any{"name_id_attribute": "user_id"}); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), errs.CodeSAMLNameIDAttributeInvalid) {
		t.Errorf("an emailAddress NameID of the user id: %d %s, want 422", rec.Code, rec.Body.String())
	}
	rec, out := patch(map[string]any{"attributes": []any{}})
	if rec.Code != http.StatusOK || len(out.Attributes) != 0 || out.Attributes == nil {
		t.Errorf("clearing attributes: %d %s", rec.Code, rec.Body.String())
	}

	var raw []byte
	if err := dbtest.Pool(t).QueryRow(dbtest.Context(t), `SELECT metadata FROM audit.events
		WHERE tenant_id = $1 AND action = 'saml.sp_updated' AND resource_id = $2 AND metadata->'changed' @> '["attributes"]'`, tenant, sp.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var meta struct {
		Changed    []string           `json:"changed"`
		Attributes []AttributeMapping `json:"attributes"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil || !reflect.DeepEqual(meta.Changed, []string{"attributes"}) ||
		meta.Attributes == nil || len(meta.Attributes) != 0 {
		t.Errorf("update audited as %s, want the attributes it changed", raw)
	}
	if n := dbtest.Count(t, `SELECT count(*) FROM audit.events WHERE tenant_id = $1 AND action = 'saml.sp_created'
		AND resource_id = $2 AND metadata->>'name_id_format' = $3 AND metadata->'attributes'->0->>'name' = 'uid'`, tenant, sp.ID, nameIDPersistent); n != 1 {
		t.Errorf("%d registrations audited with their NameID and attribute settings, want 1", n)
	}
}

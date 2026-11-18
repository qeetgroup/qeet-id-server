package saml

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/google/uuid"
	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// TestNameIDSettingsAreChecked checks that a new service provider's NameID
// defaults to the email, that a persistent one defaults to the persistent
// value, and that a format or source that doesn't fit is refused.
func TestNameIDSettingsAreChecked(t *testing.T) {
	for _, c := range []struct {
		format, attribute         string
		wantFormat, wantAttribute string
		wantErr                   error
	}{
		{"", "", nameIDEmail, sourceEmail, nil},
		{nameIDEmail, "", nameIDEmail, sourceEmail, nil},
		{nameIDPersistent, "", nameIDPersistent, sourcePersistentID, nil},
		{nameIDPersistent, sourceUserID, nameIDPersistent, sourceUserID, nil},
		{nameIDUnspecified, "", nameIDUnspecified, sourceEmail, nil},
		{nameIDUnspecified, "metadata.employee_id", nameIDUnspecified, "metadata.employee_id", nil},
		{nameIDUnspecified, sourcePersistentID, nameIDUnspecified, sourcePersistentID, nil},
		{nameIDPersistent, sourceEmail, "", "", ErrNameIDAttributeInvalid},
		{nameIDPersistent, "metadata.employee_id", "", "", ErrNameIDAttributeInvalid},
		{nameIDEmail, sourceUserID, "", "", ErrNameIDAttributeInvalid},
		{nameIDUnspecified, "password_hash", "", "", ErrNameIDAttributeInvalid},
		{nameIDUnspecified, "metadata.", "", "", ErrNameIDAttributeInvalid},
		{nameIDUnspecified, sourceGroups, "", "", ErrNameIDAttributeInvalid},
		{"urn:oasis:names:tc:SAML:2.0:nameid-format:transient", "", "", "", ErrNameIDFormatInvalid},
	} {
		format, attribute := c.format, c.attribute
		err := checkNameID(&format, &attribute)
		if c.wantErr != nil {
			if !errors.Is(err, c.wantErr) {
				t.Errorf("checkNameID(%q, %q) = %v, want %v", c.format, c.attribute, err, c.wantErr)
			}
			continue
		}
		if err != nil || format != c.wantFormat || attribute != c.wantAttribute {
			t.Errorf("checkNameID(%q, %q) = %q, %q, %v; want %q, %q", c.format, c.attribute, format, attribute, err, c.wantFormat, c.wantAttribute)
		}
	}
}

// TestNameIDChangesFollowTheFormat checks that changing a service provider's
// NameID format moves a source that no longer fits to the format's default,
// that a source given must fit, and that a stored setting the rules refuse
// still names a value of the right kind.
func TestNameIDChangesFollowTheFormat(t *testing.T) {
	str := func(s string) *string { return &s }
	for _, c := range []struct {
		name                      string
		curFormat, curAttribute   string
		format, attribute         *string
		wantFormat, wantAttribute string
		wantErr                   error
	}{
		{"to persistent", nameIDEmail, sourceEmail, str(nameIDPersistent), nil, nameIDPersistent, sourcePersistentID, nil},
		{"back to email", nameIDPersistent, sourcePersistentID, str(nameIDEmail), nil, nameIDEmail, sourceEmail, nil},
		{"to unspecified keeps the source", nameIDPersistent, sourceUserID, str(nameIDUnspecified), nil, nameIDUnspecified, sourceUserID, nil},
		{"a source alone", nameIDUnspecified, sourceEmail, nil, str("metadata.upn"), nameIDUnspecified, "metadata.upn", nil},
		{"an empty format", nameIDUnspecified, sourceUserID, str(""), nil, nameIDEmail, sourceEmail, nil},
		{"a source that doesn't fit", nameIDEmail, sourceEmail, nil, str(sourceUserID), "", "", ErrNameIDAttributeInvalid},
		{"both, not fitting", nameIDEmail, sourceEmail, str(nameIDPersistent), str(sourceEmail), "", "", ErrNameIDAttributeInvalid},
		{"an unknown format", nameIDEmail, sourceEmail, str("urn:x"), nil, "", "", ErrNameIDFormatInvalid},
	} {
		format, attribute, err := mergeNameID(c.curFormat, c.curAttribute, c.format, c.attribute)
		if c.wantErr != nil {
			if !errors.Is(err, c.wantErr) {
				t.Errorf("%s: %v, want %v", c.name, err, c.wantErr)
			}
			continue
		}
		if err != nil || format != c.wantFormat || attribute != c.wantAttribute {
			t.Errorf("%s: %q, %q, %v; want %q, %q", c.name, format, attribute, err, c.wantFormat, c.wantAttribute)
		}
	}

	for _, c := range []struct{ format, attribute, want string }{
		{nameIDPersistent, sourceEmail, sourcePersistentID},
		{nameIDPersistent, "metadata.x", sourcePersistentID},
		{nameIDEmail, sourceUserID, sourceEmail},
		{nameIDUnspecified, "not-a-source", sourceEmail},
		{"urn:oasis:names:tc:SAML:2.0:nameid-format:transient", sourceEmail, sourceEmail},
	} {
		if got := nameIDSource(c.format, c.attribute); got != c.want {
			t.Errorf("nameIDSource(%q, %q) = %q, want %q", c.format, c.attribute, got, c.want)
		}
	}
}

// TestAttributeMappingsAreChecked checks that each attribute needs a unique,
// printable name, a known source and a known name format, and that every
// fault is named.
func TestAttributeMappingsAreChecked(t *testing.T) {
	good := []AttributeMapping{
		{Name: " mail ", Source: " email "},
		{Name: "https://aws.amazon.com/SAML/Attributes/Role", Source: sourceRoles, NameFormat: "uri"},
		{Name: "memberOf", Source: sourceGroups, NameFormat: "basic"},
		{Name: "dept", Source: "metadata.department", NameFormat: "unspecified"},
		{Name: "first", Source: sourceGivenName},
		{Name: "last", Source: sourceFamilyName},
		{Name: "uid", Source: sourceUserID},
		{Name: "pid", Source: sourcePersistentID},
		{Name: "displayName", Source: sourceDisplayName},
	}
	if err := checkAttributes(good); err != nil {
		t.Fatalf("checkAttributes(good) = %v", err)
	}
	if good[0].Name != "mail" || good[0].Source != sourceEmail {
		t.Errorf("checkAttributes left %+v untrimmed", good[0])
	}
	if err := checkAttributes([]AttributeMapping{}); err != nil {
		t.Errorf("checkAttributes(none) = %v", err)
	}

	bad := []AttributeMapping{
		{Name: "", Source: sourceEmail},
		{Name: "mail", Source: sourceEmail},
		{Name: "mail", Source: sourceDisplayName},
		{Name: "secret", Source: "password_hash"},
		{Name: "tab\tname", Source: sourceEmail},
		{Name: strings.Repeat("a", maxAttributeNameLen+1), Source: sourceEmail},
		{Name: "fmt", Source: sourceEmail, NameFormat: "urn:x"},
		{Name: "meta", Source: "metadata.a b"},
	}
	e := errs.As(checkAttributes(bad))
	if e == nil || e.Code != CodeAttributesInvalid {
		t.Fatalf("checkAttributes(bad) = %v, want %s", e, CodeAttributesInvalid)
	}
	var faults []string
	for _, f := range e.Fields {
		faults = append(faults, f.Field+":"+f.Code)
	}
	want := []string{
		"attributes[0].name:required", "attributes[2].name:duplicate", "attributes[3].source:invalid",
		"attributes[4].name:invalid", "attributes[5].name:invalid", "attributes[6].name_format:invalid", "attributes[7].source:invalid",
	}
	if !reflect.DeepEqual(faults, want) {
		t.Errorf("faults %v, want %v", faults, want)
	}

	tooMany := make([]AttributeMapping, maxAttributes+1)
	if e := errs.As(checkAttributes(tooMany)); e == nil || len(e.Fields) != 1 || e.Fields[0].Code != "too_many" {
		t.Errorf("checkAttributes(%d attributes) = %v, want too_many", len(tooMany), e)
	}
}

// TestAttributeListsAreStoredAsGiven checks that no list stores the default,
// an empty one stores none, and a stored list that can't be read sends the
// default.
func TestAttributeListsAreStoredAsGiven(t *testing.T) {
	none := []AttributeMapping{}
	for _, c := range []struct {
		in   *[]AttributeMapping
		want []AttributeMapping
	}{
		{nil, defaultAttributes()},
		{&none, []AttributeMapping{}},
		{&[]AttributeMapping{{Name: "uid", Source: sourceUserID}}, []AttributeMapping{{Name: "uid", Source: sourceUserID}}},
	} {
		raw, err := encodeAttributes(c.in)
		if err != nil {
			t.Fatal(err)
		}
		if got := decodeAttributes(raw); !reflect.DeepEqual(got, c.want) {
			t.Errorf("stored %s, read back %+v, want %+v", raw, got, c.want)
		}
	}
	if got := decodeAttributes([]byte("not json")); !reflect.DeepEqual(got, defaultAttributes()) {
		t.Errorf("unreadable list = %+v, want the default", got)
	}
}

// TestSubjectSaysWhatTheSPAsksFor checks the NameID and attributes an SP gets
// from the person's own account: each mapped source under its name and name
// format, metadata values as written, and nothing for a value they don't have.
func TestSubjectSaysWhatTheSPAsksFor(t *testing.T) {
	idp := testIdP(t)
	ctx := context.Background()
	p := &person{
		id: uuid.New(), email: "asha@example.com", displayName: "Asha Rao",
		metadata: decodeMetadata([]byte(`{"employee_id": 12345678901234567890, "department": "Finance",
			"given_name": "Asha", "cost_centres": ["CC-1", 7, true, ["nested"], {"x": 1}], "empty": "", "manager": {"id": 1}}`)),
	}
	sp := &ServiceProvider{
		NameIDFormat: nameIDUnspecified, NameIDAttribute: "metadata.employee_id",
		Attributes: []AttributeMapping{
			{Name: "mail", Source: sourceEmail},
			{Name: "uid", Source: sourceUserID, NameFormat: "uri"},
			{Name: "first", Source: sourceGivenName},
			{Name: "dept", Source: "metadata.department"},
			{Name: "cc", Source: "metadata.cost_centres", NameFormat: "unspecified"},
			{Name: "empty", Source: "metadata.empty"},
			{Name: "manager", Source: "metadata.manager"},
			{Name: "missing", Source: "metadata.nope"},
		},
	}
	subj, err := idp.subjectFor(ctx, sp, p)
	if err != nil {
		t.Fatalf("subjectFor: %v", err)
	}
	if subj.nameID != "12345678901234567890" || subj.nameIDFormat != nameIDUnspecified {
		t.Errorf("NameID %q (%s), want the employee id as written", subj.nameID, subj.nameIDFormat)
	}
	want := []assertionAttribute{
		{"mail", attrNameFormatBasic, []string{"asha@example.com"}},
		{"uid", attrNameFormatURI, []string{p.id.String()}},
		{"first", attrNameFormatBasic, []string{"Asha"}},
		{"dept", attrNameFormatBasic, []string{"Finance"}},
		{"cc", attrNameFormatUnspecified, []string{"CC-1", "7", "true"}},
	}
	if !reflect.DeepEqual(subj.attributes, want) {
		t.Errorf("attributes %+v, want %+v", subj.attributes, want)
	}

	for _, attribute := range []string{"metadata.nope", "metadata.cost_centres", "metadata.manager"} {
		sp := &ServiceProvider{NameIDFormat: nameIDUnspecified, NameIDAttribute: attribute}
		if _, err := idp.subjectFor(ctx, sp, p); !errors.Is(err, ErrNameIDUnavailable) {
			t.Errorf("NameID from %s: %v, want ErrSAMLNameIDUnavailable", attribute, err)
		}
	}
	sp = &ServiceProvider{NameIDFormat: nameIDPersistent, NameIDAttribute: sourceUserID, Attributes: []AttributeMapping{}}
	if subj, err := idp.subjectFor(ctx, sp, p); err != nil || subj.nameID != p.id.String() || subj.attributes != nil {
		t.Errorf("persistent NameID from user_id: %+v, %v; want the user id and no attributes", subj, err)
	}
}

// TestAssertionCarriesMappedAttributes checks that an independent SP reads
// every value of a multi-valued attribute and its name format, and that an
// assertion with no attributes, still signed, has no AttributeStatement,
// which the schema doesn't allow empty.
func TestAssertionCarriesMappedAttributes(t *testing.T) {
	idp := testIdP(t)
	const idpEntity, spEntity, acs = "https://id.qeet.example/saml/idp", "https://sp.example.com", "https://sp.example.com/acs"
	cert, err := x509.ParseCertificate(idp.signer.certDER)
	if err != nil {
		t.Fatal(err)
	}
	certs := &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}}
	verifier := &saml2.SAMLServiceProvider{
		IdentityProviderIssuer: idpEntity, ServiceProviderIssuer: spEntity, AssertionConsumerServiceURL: acs, AudienceURI: spEntity,
		IDPCertificateStore: certs,
	}
	sp := &ServiceProvider{EntityID: spEntity, ACSURL: acs}
	raw, err := idp.buildSignedResponse(idpEntity, sp, acs, assertionSubject{nameID: "4f1c", nameIDFormat: nameIDPersistent, attributes: []assertionAttribute{
		{"https://example.com/claims/groups", attrNameFormatURI, []string{"Finance", "Admins"}},
	}}, "")
	if err != nil {
		t.Fatal(err)
	}
	info, err := verifier.RetrieveAssertionInfo(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatalf("an independent SP refused the assertion: %v", err)
	}
	if info.NameID != "4f1c" || info.Assertions[0].Subject.NameID.Format != nameIDPersistent {
		t.Errorf("NameID %q (%s), want 4f1c, persistent", info.NameID, info.Assertions[0].Subject.NameID.Format)
	}
	groups := info.Values["https://example.com/claims/groups"]
	if got := info.Values.GetAll("https://example.com/claims/groups"); !reflect.DeepEqual(got, []string{"Finance", "Admins"}) || groups.NameFormat != attrNameFormatURI {
		t.Errorf("groups %v as %q, want Finance and Admins as uri", got, groups.NameFormat)
	}

	raw, err = idp.buildSignedResponse(idpEntity, sp, acs, assertionSubject{nameID: "4f1c", nameIDFormat: nameIDPersistent}, "")
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		t.Fatal(err)
	}
	assertion := doc.Root().FindElement("./Assertion")
	if assertion == nil || assertion.FindElement("./AttributeStatement") != nil {
		t.Fatalf("assertion without attributes: %s, want no AttributeStatement", raw)
	}
	if _, err := dsig.NewDefaultValidationContext(certs).Validate(assertion); err != nil {
		t.Errorf("assertion without attributes: signature %v", err)
	}
}

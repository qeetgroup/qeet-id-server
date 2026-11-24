package saml

// What an assertion says about the person signing in to one of their home
// organization's service providers: the NameID the service provider asked for
// and the attributes it maps. Values come only from the person's own account
// and that organization's groups, roles and directory profiles.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/saml/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

const (
	nameIDPersistent  = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	nameIDUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"

	attrNameFormatURI         = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
	attrNameFormatUnspecified = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
)

// Where a NameID or an attribute's values come from.
const (
	sourceEmail        = "email"         // the person's email address
	sourceUserID       = "user_id"       // their account ID, the same at every app
	sourcePersistentID = "persistent_id" // an opaque value of their own at this app
	sourceDisplayName  = "display_name"  // their display name
	sourceGivenName    = "given_name"    // metadata given_name, else their directory first name
	sourceFamilyName   = "family_name"   // metadata family_name, else their directory last name
	sourceGroups       = "groups"        // names of their groups in the organization
	sourceRoles        = "roles"         // names of their roles there, directly or through a group
	sourceMetadata     = "metadata."     // prefix of one key of their user metadata
)

const (
	maxAttributes       = 50  // attributes one service provider receives
	maxAttributeNameLen = 256 // characters in an attribute's SAML name
)

// metadataKeyPattern is a user-metadata key an attribute or NameID may name.
var metadataKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

// attrNameFormats maps an attribute mapping's name_format to its SAML URI.
var attrNameFormats = map[string]string{
	"":            attrNameFormatBasic,
	"basic":       attrNameFormatBasic,
	"uri":         attrNameFormatURI,
	"unspecified": attrNameFormatUnspecified,
}

// AttributeMapping is one attribute a service provider receives: its SAML
// name, the source of its values and its name format (basic when empty).
type AttributeMapping struct {
	Name       string `json:"name"`
	Source     string `json:"source"`
	NameFormat string `json:"name_format,omitempty"`
}

// defaultAttributes is what a service provider receives unless it maps other
// attributes: the email and name every one received before mappings existed.
func defaultAttributes() []AttributeMapping {
	return []AttributeMapping{{Name: "email", Source: sourceEmail}, {Name: "name", Source: sourceDisplayName}}
}

// knownNameIDFormat reports whether a service provider may ask for format.
func knownNameIDFormat(format string) bool {
	return format == nameIDEmail || format == nameIDPersistent || format == nameIDUnspecified
}

// validMetadataSource reports whether source names a user-metadata key.
func validMetadataSource(source string) bool {
	key, ok := strings.CutPrefix(source, sourceMetadata)
	return ok && metadataKeyPattern.MatchString(key)
}

// validNameIDAttribute reports whether a NameID may come from attribute.
func validNameIDAttribute(attribute string) bool {
	switch attribute {
	case sourceEmail, sourceUserID, sourcePersistentID:
		return true
	}
	return validMetadataSource(attribute)
}

// nameIDFits reports whether a NameID of format may carry attribute's value:
// an emailAddress one only the email, a persistent one only a value that
// never changes.
func nameIDFits(format, attribute string) bool {
	switch format {
	case nameIDEmail:
		return attribute == sourceEmail
	case nameIDPersistent:
		return attribute == sourcePersistentID || attribute == sourceUserID
	}
	return true
}

// defaultNameIDAttribute is where a NameID of format comes from unless the
// service provider names another source.
func defaultNameIDAttribute(format string) string {
	if format == nameIDPersistent {
		return sourcePersistentID
	}
	return sourceEmail
}

// nameIDSource is where a NameID of format comes from for a service provider
// whose name_id_attribute is attribute, falling back to the format's default
// for a stored value these rules refuse.
func nameIDSource(format, attribute string) string {
	if validNameIDAttribute(attribute) && nameIDFits(format, attribute) {
		return attribute
	}
	return defaultNameIDAttribute(format)
}

// checkNameID normalises a new service provider's NameID settings, defaulting
// an empty format to emailAddress and an empty attribute to the format's own,
// and refuses a combination nameIDFits refuses.
func checkNameID(format, attribute *string) error {
	if *format == "" {
		*format = nameIDEmail
	}
	if !knownNameIDFormat(*format) {
		return ErrNameIDFormatInvalid
	}
	if *attribute == "" {
		*attribute = defaultNameIDAttribute(*format)
	}
	if !validNameIDAttribute(*attribute) || !nameIDFits(*format, *attribute) {
		return ErrNameIDAttributeInvalid
	}
	return nil
}

// mergeNameID applies a change to a service provider's NameID settings, cur
// being what it has now. An attribute not given follows a new format when the
// current one doesn't fit it; one given must fit.
func mergeNameID(curFormat, curAttribute string, format, attribute *string) (string, string, error) {
	f, a := curFormat, curAttribute
	if format != nil {
		f = *format
		if f == "" {
			f = nameIDEmail
		}
		if !knownNameIDFormat(f) {
			return "", "", ErrNameIDFormatInvalid
		}
	}
	if attribute != nil {
		a = *attribute
		if a == "" {
			a = defaultNameIDAttribute(f)
		}
		if !validNameIDAttribute(a) || !nameIDFits(f, a) {
			return "", "", ErrNameIDAttributeInvalid
		}
		return f, a, nil
	}
	if !validNameIDAttribute(a) || !nameIDFits(f, a) {
		a = defaultNameIDAttribute(f)
	}
	return f, a, nil
}

// validSource reports whether an attribute's values may come from source.
func validSource(source string) bool {
	switch source {
	case sourceEmail, sourceUserID, sourcePersistentID, sourceDisplayName,
		sourceGivenName, sourceFamilyName, sourceGroups, sourceRoles:
		return true
	}
	return validMetadataSource(source)
}

// checkAttributes trims list's names and sources and refuses more than
// maxAttributes, a missing, overlong, unprintable or repeated name, an
// unknown source or an unknown name format, naming each field at fault.
func checkAttributes(list []AttributeMapping) error {
	if len(list) > maxAttributes {
		return ErrAttributesInvalid.WithFields([]errs.FieldError{{
			Field: "attributes", Code: "too_many", Message: fmt.Sprintf("At most %d attributes.", maxAttributes),
		}})
	}
	var faults []errs.FieldError
	fault := func(i int, field, code, message string) {
		faults = append(faults, errs.FieldError{Field: fmt.Sprintf("attributes[%d].%s", i, field), Code: code, Message: message})
	}
	seen := make(map[string]bool, len(list))
	for i := range list {
		m := &list[i]
		m.Name, m.Source, m.NameFormat = strings.TrimSpace(m.Name), strings.TrimSpace(m.Source), strings.TrimSpace(m.NameFormat)
		switch {
		case m.Name == "":
			fault(i, "name", "required", "An attribute needs a name.")
		case utf8.RuneCountInString(m.Name) > maxAttributeNameLen || !utf8.ValidString(m.Name) ||
			strings.IndexFunc(m.Name, unicode.IsControl) >= 0:
			fault(i, "name", "invalid", fmt.Sprintf("A name is up to %d printable characters.", maxAttributeNameLen))
		case seen[m.Name]:
			fault(i, "name", "duplicate", "Another attribute has this name.")
		}
		seen[m.Name] = true
		if !validSource(m.Source) {
			fault(i, "source", "invalid", "The source must be email, user_id, persistent_id, display_name, given_name, family_name, groups, roles or metadata.<key>.")
		}
		if _, ok := attrNameFormats[m.NameFormat]; !ok {
			fault(i, "name_format", "invalid", "The name format must be basic, uri or unspecified.")
		}
	}
	if faults != nil {
		return ErrAttributesInvalid.WithFields(faults)
	}
	return nil
}

// encodeAttributes is list as stored; nil stores the default.
func encodeAttributes(list *[]AttributeMapping) ([]byte, error) {
	if list == nil {
		return json.Marshal(defaultAttributes())
	}
	if *list == nil {
		return []byte("[]"), nil
	}
	return json.Marshal(*list)
}

// decodeAttributes is a stored attribute list, or the default for one that
// can't be read.
func decodeAttributes(raw []byte) []AttributeMapping {
	list := []AttributeMapping{}
	if err := json.Unmarshal(raw, &list); err != nil {
		return defaultAttributes()
	}
	return list
}

// person is an account signing in to a service provider of its home
// organization, organizationID.
type person struct {
	id             uuid.UUID
	organizationID uuid.UUID
	email          string
	displayName    string
	metadata       map[string]any
}

// decodeMetadata reads user metadata, keeping numbers as written.
func decodeMetadata(raw []byte) map[string]any {
	meta := map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&meta); err != nil {
		return map[string]any{}
	}
	return meta
}

// metadataValues is a metadata value as attribute values: a string, number or
// boolean as one, an array of those as one each, and nothing for the rest.
func metadataValues(v any) []string {
	switch v := v.(type) {
	case string:
		if v != "" {
			return []string{v}
		}
	case json.Number:
		return []string{v.String()}
	case bool:
		return []string{strconv.FormatBool(v)}
	case []any:
		var out []string
		for _, e := range v {
			if _, nested := e.([]any); !nested {
				out = append(out, metadataValues(e)...)
			}
		}
		return out
	}
	return nil
}

// assertionAttribute is one attribute of an assertion.
type assertionAttribute struct {
	name, nameFormat string
	values           []string
}

// assertionSubject is what an assertion says about the person: their NameID, its
// format, and the attributes the service provider maps.
type assertionSubject struct {
	nameID, nameIDFormat string
	attributes           []assertionAttribute
}

// claims reads the values of one person's sources for one service provider,
// each at most once.
type claims struct {
	idp  *IdP
	sp   *ServiceProvider
	p    *person
	seen map[string][]string
}

// values returns source's values for the person, empty when they have none.
func (c *claims) values(ctx context.Context, source string) ([]string, error) {
	if v, ok := c.seen[source]; ok {
		return v, nil
	}
	v, err := c.read(ctx, source)
	if err != nil {
		return nil, err
	}
	c.seen[source] = v
	return v, nil
}

// read loads source's values, scoped to the service provider's organization.
func (c *claims) read(ctx context.Context, source string) ([]string, error) {
	q, organizationID, userID := c.idp.q, c.sp.OrganizationID, c.p.id
	switch source {
	case sourceEmail:
		return nonEmpty(c.p.email), nil
	case sourceUserID:
		return []string{userID.String()}, nil
	case sourceDisplayName:
		return nonEmpty(c.p.displayName), nil
	case sourcePersistentID:
		id, err := c.idp.persistentID(ctx, c.sp, userID)
		return nonEmpty(id), err
	case sourceGroups:
		return q.ListIdPUserGroupNames(ctx, dbgen.ListIdPUserGroupNamesParams{OrganizationID: organizationID, UserID: userID})
	case sourceRoles:
		return q.ListIdPUserRoleNames(ctx, dbgen.ListIdPUserRoleNamesParams{OrganizationID: organizationID, UserID: userID})
	case sourceGivenName, sourceFamilyName:
		if v := metadataValues(c.p.metadata[source]); len(v) == 1 {
			return v, nil
		}
		names, err := q.GetIdPNameParts(ctx, dbgen.GetIdPNamePartsParams{OrganizationID: organizationID, UserID: userID})
		if err != nil {
			return nil, err
		}
		if source == sourceGivenName {
			return nonEmpty(names.GivenName), nil
		}
		return nonEmpty(names.FamilyName), nil
	}
	if key, ok := strings.CutPrefix(source, sourceMetadata); ok {
		return metadataValues(c.p.metadata[key]), nil
	}
	return nil, nil
}

func nonEmpty(v string) []string {
	if v == "" {
		return nil
	}
	return []string{v}
}

// subjectFor is what sp is told about p: the NameID it asks for, refused with
// ErrSAMLNameIDUnavailable when p has no single value for it, and each mapped
// attribute p has a value for.
func (i *IdP) subjectFor(ctx context.Context, sp *ServiceProvider, p *person) (assertionSubject, error) {
	c := &claims{idp: i, sp: sp, p: p, seen: map[string][]string{}}
	format := sp.NameIDFormat
	if format == "" {
		format = nameIDEmail
	}
	ids, err := c.values(ctx, nameIDSource(format, sp.NameIDAttribute))
	if err != nil {
		return assertionSubject{}, err
	}
	if len(ids) != 1 {
		return assertionSubject{}, ErrNameIDUnavailable
	}
	s := assertionSubject{nameID: ids[0], nameIDFormat: format}
	for _, m := range sp.Attributes {
		values, err := c.values(ctx, m.Source)
		if err != nil {
			return assertionSubject{}, err
		}
		if len(values) == 0 {
			continue
		}
		nameFormat, ok := attrNameFormats[m.NameFormat]
		if !ok {
			nameFormat = attrNameFormatBasic
		}
		s.attributes = append(s.attributes, assertionAttribute{name: m.Name, nameFormat: nameFormat, values: values})
	}
	return s, nil
}

// persistentID returns userID's persistent NameID at sp, making a random one
// the first time they sign in to it. It never changes after, whatever happens
// to their email, and no other app can work it out.
func (i *IdP) persistentID(ctx context.Context, sp *ServiceProvider, userID uuid.UUID) (string, error) {
	id, err := i.q.GetSamlPersistentID(ctx, dbgen.GetSamlPersistentIDParams{OrganizationID: sp.OrganizationID, SpID: sp.ID, UserID: userID})
	if err == nil || !errors.Is(err, pgx.ErrNoRows) {
		return id, err
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return i.q.InsertSamlPersistentID(ctx, dbgen.InsertSamlPersistentIDParams{
		OrganizationID: sp.OrganizationID, SpID: sp.ID, UserID: userID, NameID: hex.EncodeToString(raw),
	})
}

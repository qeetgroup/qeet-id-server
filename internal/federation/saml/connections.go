package saml

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/saml/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// CreateInput is what Create takes.
type CreateInput struct {
	Name            string `json:"name"`
	IdpEntityID     string `json:"idp_entity_id"`
	IdpSSOURL       string `json:"idp_sso_url"`
	IdpCertificate  string `json:"idp_certificate"`
	EmailAttribute  string `json:"email_attribute"`
	NameAttribute   string `json:"name_attribute"`
	GroupsAttribute string `json:"groups_attribute"`
	Status          string `json:"status"`
}

// errGroupsAttributeInvalid refuses a groups attribute over 256 characters.
var errGroupsAttributeInvalid = errs.ErrValidationFailed.WithFields([]errs.FieldError{{
	Field: "groups_attribute", Code: "too_long", Message: "Name the groups attribute in up to 256 characters.",
}})

// validGroupsAttribute trims attribute and reports whether it fits.
func validGroupsAttribute(attribute *string) bool {
	*attribute = strings.TrimSpace(*attribute)
	return utf8.RuneCountInString(*attribute) <= 256
}

// check trims the IdP SSO URL, then requires it to pass validIdPSSOURL, the
// certificate to parse, the status, if given, to be a known one and the groups
// attribute to fit. A draft named before the IdP's details are known needs
// none of them, and can't be anything but a draft.
func (in *CreateInput) check() error {
	if in.Status != "" && !validStatus(in.Status) {
		return ErrStatusInvalid
	}
	if !validGroupsAttribute(&in.GroupsAttribute) {
		return errGroupsAttributeInvalid
	}
	if in.awaitsIdP() {
		if in.Status != "" && in.Status != "draft" {
			return ErrConnectionIncomplete
		}
		return nil
	}
	in.IdpSSOURL = strings.TrimSpace(in.IdpSSOURL)
	if !validIdPSSOURL(in.IdpSSOURL) {
		return ErrSSOURLInvalid
	}
	if _, err := parseCertificate(in.IdpCertificate); err != nil {
		return ErrCertificateInvalid
	}
	return nil
}

// awaitsIdP reports whether the connection is named before any of its IdP's
// details: entity ID, SSO URL and certificate.
func (in *CreateInput) awaitsIdP() bool {
	return strings.TrimSpace(in.IdpEntityID) == "" && strings.TrimSpace(in.IdpSSOURL) == "" &&
		strings.TrimSpace(in.IdpCertificate) == ""
}

// AwaitsIdP reports whether the input names a draft before any of its IdP's details exist, so
// its service-provider addresses can go to the IdP first (the admin portal's guided setup).
func (in *CreateInput) AwaitsIdP() bool { return in.awaitsIdP() }

// validStatus reports whether status is one a connection or service provider
// can have.
func validStatus(status string) bool {
	return status == "draft" || status == "active" || status == "disabled"
}

// Create stores a connection in organizationID, recorded as actor's, refusing
// input that fails check whichever API sent it.
func (s *Service) Create(ctx context.Context, organizationID uuid.UUID, in CreateInput, actor audit.Actor) (*Connection, error) {
	if err := in.check(); err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	conn, err := s.create(ctx, tx, organizationID, in)
	if err != nil {
		return nil, err
	}
	if err := recordChange(ctx, tx, actor, organizationID, conn.ID, "saml.connection_created", map[string]any{"name": conn.Name, "idp": conn.IdpEntityID}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return conn, nil
}

// recordChange audits, in tx, actor's change to organizationID's connection id.
func recordChange(ctx context.Context, tx pgx.Tx, actor audit.Actor, organizationID, id uuid.UUID, action string, meta map[string]any) error {
	return audit.Record(ctx, tx, actor.Event(organizationID, action, "saml_connection", id, meta))
}

// create stores a connection in organizationID within tx, refusing input that
// fails check.
func (s *Service) create(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, in CreateInput) (*Connection, error) {
	if err := in.check(); err != nil {
		return nil, err
	}
	status := in.Status
	if status == "" {
		status = "draft"
	}
	q := s.q.WithTx(tx)
	row, err := q.InsertSamlConnection(ctx, dbgen.InsertSamlConnectionParams{
		OrganizationID: organizationID,
		Name:           in.Name,
		IdpEntityID:    in.IdpEntityID,
		IdpSsoUrl:      in.IdpSSOURL,
		IdpCertificate: in.IdpCertificate,
		EmailAttribute: in.EmailAttribute,
		NameAttribute:  in.NameAttribute,
		Status:         status,
	})
	if err != nil {
		return nil, err
	}
	if !in.awaitsIdP() {
		cert, err := parseCertificate(in.IdpCertificate)
		if err != nil {
			return nil, ErrCertificateInvalid
		}
		if err := replaceCertificates(ctx, q, row.ID, organizationID, cert); err != nil {
			return nil, err
		}
	}
	out := toConnection(dbgen.GetSamlConnectionRow(row))
	if out.Certificates, err = listCertificates(ctx, q, row.ID, organizationID); err != nil {
		return nil, err
	}
	if in.GroupsAttribute != "" {
		if err := q.SetSamlGroupsAttribute(ctx, dbgen.SetSamlGroupsAttributeParams{
			ID: out.ID, OrganizationID: organizationID, GroupsAttribute: in.GroupsAttribute,
		}); err != nil {
			return nil, err
		}
		out.GroupsAttribute = in.GroupsAttribute
	}
	return out, nil
}

// List returns the organization's SAML connections.
func (s *Service) List(ctx context.Context, organizationID uuid.UUID) ([]Connection, error) {
	rows, err := s.q.ListSamlConnections(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]Connection, len(rows))
	for i, r := range rows {
		out[i] = *toConnection(dbgen.GetSamlConnectionRow(r))
	}
	flags, err := s.idpInitiatedFlags(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	attributes, err := s.q.ListSamlGroupsAttributes(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	groups := make(map[uuid.UUID]string, len(attributes))
	for _, a := range attributes {
		groups[a.ID] = a.GroupsAttribute
	}
	certs, err := s.q.ListSamlCertificatesForOrganization(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	byConnection := map[uuid.UUID][]Certificate{}
	for _, c := range certs {
		byConnection[c.ConnectionID] = append(byConnection[c.ConnectionID], toCertificate(c))
	}
	for i := range out {
		out[i].AllowIdPInitiated = flags[out[i].ID]
		out[i].GroupsAttribute = groups[out[i].ID]
		if c := byConnection[out[i].ID]; c != nil {
			out[i].Certificates = c
		}
	}
	if err := s.withMetadataSources(ctx, organizationID, out); err != nil {
		return nil, err
	}
	return out, nil
}

// idpInitiatedFlags loads the whole organization's opt-in state in one round trip so
// List doesn't issue a query per connection.
func (s *Service) idpInitiatedFlags(ctx context.Context, organizationID uuid.UUID) (map[uuid.UUID]bool, error) {
	rows, err := s.q.ListSamlIdPInitiatedFlags(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	flags := make(map[uuid.UUID]bool, len(rows))
	for _, r := range rows {
		flags[r.ID] = r.AllowIdpInitiated
	}
	return flags, nil
}

// Get returns one of the organization's SAML connections.
func (s *Service) Get(ctx context.Context, id, organizationID uuid.UUID) (*Connection, error) {
	r, err := s.q.GetSamlConnection(ctx, dbgen.GetSamlConnectionParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	out := toConnection(r)
	out.AllowIdPInitiated, err = s.AllowsIdPInitiated(ctx, id)
	if err != nil {
		return nil, err
	}
	out.GroupsAttribute, err = s.groupsAttribute(ctx, out)
	if err != nil {
		return nil, err
	}
	if out.Certificates, err = listCertificates(ctx, s.q, id, organizationID); err != nil {
		return nil, err
	}
	if err := withMetadataSource(ctx, s.q, out); err != nil {
		return nil, err
	}
	return out, nil
}

// groupsAttribute returns the attribute conn reads a person's groups from.
func (s *Service) groupsAttribute(ctx context.Context, conn *Connection) (string, error) {
	return s.q.GetSamlGroupsAttribute(ctx, dbgen.GetSamlGroupsAttributeParams{ID: conn.ID, OrganizationID: conn.OrganizationID})
}

// getByID loads a connection without organization scoping, for the public SSO
// endpoints, where the unguessable connection ID in the path is the key.
func (s *Service) getByID(ctx context.Context, id uuid.UUID) (*Connection, error) {
	r, err := s.q.GetSamlConnectionByID(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return toConnection(dbgen.GetSamlConnectionRow(r)), nil
}

// UpdateInput changes a connection; a nil field is kept. AllowIdPInitiated opts
// into unsolicited assertions (see AllowsIdPInitiated). IdpCertificate becomes
// the only certificate the connection trusts.
type UpdateInput struct {
	Name              *string `json:"name"`
	IdpEntityID       *string `json:"idp_entity_id"`
	IdpSSOURL         *string `json:"idp_sso_url"`
	IdpCertificate    *string `json:"idp_certificate"`
	EmailAttribute    *string `json:"email_attribute"`
	NameAttribute     *string `json:"name_attribute"`
	GroupsAttribute   *string `json:"groups_attribute"`
	Status            *string `json:"status"`
	AllowIdPInitiated *bool   `json:"allow_idp_initiated"`
}

// ChangesTrust reports whether in changes what c trusts: its IdP's entity ID
// or signing certificate. A connection signing in its linked accounts on that
// trust, such a change can sign in as any of them.
func (in UpdateInput) ChangesTrust(c *Connection) bool {
	if in.IdpEntityID != nil && strings.TrimSpace(*in.IdpEntityID) != c.IdpEntityID {
		return true
	}
	if in.IdpCertificate == nil {
		return false
	}
	next, err := parseCertificate(*in.IdpCertificate)
	if err != nil {
		return true
	}
	current, err := parseCertificate(c.IdpCertificate)
	return err != nil || !bytes.Equal(next.Raw, current.Raw)
}

// check applies CreateInput's checks to the fields being changed.
func (in *UpdateInput) check() error {
	if in.IdpSSOURL != nil {
		sso := strings.TrimSpace(*in.IdpSSOURL)
		if !validIdPSSOURL(sso) {
			return ErrSSOURLInvalid
		}
		in.IdpSSOURL = &sso
	}
	if in.IdpCertificate != nil {
		if _, err := parseCertificate(*in.IdpCertificate); err != nil {
			return ErrCertificateInvalid
		}
	}
	if in.GroupsAttribute != nil && !validGroupsAttribute(in.GroupsAttribute) {
		return errGroupsAttributeInvalid
	}
	return nil
}

// Update changes the given fields of a connection in organizationID, recorded as
// actor's, refusing input that fails check whichever API sent it.
func (s *Service) Update(ctx context.Context, id, organizationID uuid.UUID, in UpdateInput, actor audit.Actor) (*Connection, error) {
	if err := in.check(); err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	conn, err := s.update(ctx, tx, id, organizationID, in)
	if err != nil {
		return nil, err
	}
	if err := recordChange(ctx, tx, actor, organizationID, conn.ID, "saml.connection_updated", map[string]any{"status": conn.Status}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return conn, nil
}

// update changes the given fields of a connection in organizationID within tx.
func (s *Service) update(ctx context.Context, tx pgx.Tx, id, organizationID uuid.UUID, in UpdateInput) (*Connection, error) {
	q := s.q.WithTx(tx)
	r, err := q.UpdateSamlConnection(ctx, dbgen.UpdateSamlConnectionParams{
		ID:             id,
		OrganizationID: organizationID,
		Name:           in.Name,
		IdpEntityID:    in.IdpEntityID,
		IdpSsoUrl:      in.IdpSSOURL,
		IdpCertificate: in.IdpCertificate,
		EmailAttribute: in.EmailAttribute,
		NameAttribute:  in.NameAttribute,
		Status:         in.Status,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if in.IdpCertificate != nil {
		cert, err := parseCertificate(*in.IdpCertificate)
		if err != nil {
			return nil, ErrCertificateInvalid
		}
		if err := replaceCertificates(ctx, q, id, organizationID, cert); err != nil {
			return nil, err
		}
	}
	if in.AllowIdPInitiated != nil {
		if err := q.SetSamlAllowIdPInitiated(ctx, dbgen.SetSamlAllowIdPInitiatedParams{
			ID: id, OrganizationID: organizationID, AllowIdpInitiated: *in.AllowIdPInitiated,
		}); err != nil {
			return nil, err
		}
	}
	if in.GroupsAttribute != nil {
		if err := q.SetSamlGroupsAttribute(ctx, dbgen.SetSamlGroupsAttributeParams{
			ID: id, OrganizationID: organizationID, GroupsAttribute: *in.GroupsAttribute,
		}); err != nil {
			return nil, err
		}
	}
	out := toConnection(dbgen.GetSamlConnectionRow(r))
	if out.GroupsAttribute, err = q.GetSamlGroupsAttribute(ctx, dbgen.GetSamlGroupsAttributeParams{
		ID: id, OrganizationID: organizationID,
	}); err != nil {
		return nil, err
	}
	if in.AllowIdPInitiated != nil {
		out.AllowIdPInitiated = *in.AllowIdPInitiated
	} else if out.AllowIdPInitiated, err = q.GetSamlAllowIdPInitiated(ctx, dbgen.GetSamlAllowIdPInitiatedParams{
		ID: id, OrganizationID: organizationID,
	}); err != nil {
		return nil, err
	}
	if out.Certificates, err = listCertificates(ctx, q, id, organizationID); err != nil {
		return nil, err
	}
	// A connection that signs people in has its IdP's details, however it got
	// them: given here, imported or read from metadata.
	if out.Status == "active" && (out.IdpEntityID == "" || out.IdpSSOURL == "" || len(out.Certificates) == 0) {
		return nil, ErrConnectionIncomplete
	}
	if err := withMetadataSource(ctx, q, out); err != nil {
		return nil, err
	}
	return out, nil
}

// AllowsIdPInitiated reports whether the connection accepts an assertion with no
// InResponseTo, sent by the IdP unasked. The opt-in relaxes only request
// correlation: every other check still runs, and replayed IDs are still refused.
func (s *Service) AllowsIdPInitiated(ctx context.Context, connectionID uuid.UUID) (bool, error) {
	allowed, err := s.q.SamlAllowsIdPInitiated(ctx, connectionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, errs.ErrNotFound
	}
	return allowed, err
}

// Delete removes one of the organization's SAML connections, recorded as actor's.
func (s *Service) Delete(ctx context.Context, id, organizationID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := s.q.WithTx(tx).DeleteSamlConnection(ctx, dbgen.DeleteSamlConnectionParams{ID: id, OrganizationID: organizationID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	if err := recordChange(ctx, tx, actor, organizationID, id, "saml.connection_deleted", nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// validIdPSSOURL reports whether raw is an absolute https URL with a host and
// no userinfo, as the IdP SSO endpoint a browser is sent to must be.
func validIdPSSOURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil
}

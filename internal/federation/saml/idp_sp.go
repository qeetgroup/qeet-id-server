package saml

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/saml/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/entitlements"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
)

// CreateSPInput is what CreateSP takes. Attributes nil sends the default
// attributes; an empty list sends none. A certificate is given for
// RequireSignedRequests, EncryptAssertions or both.
type CreateSPInput struct {
	Name               string              `json:"name"`
	EntityID           string              `json:"entity_id"`
	ACSURL             string              `json:"acs_url"`
	NameIDFormat       string              `json:"name_id_format"`
	NameIDAttribute    string              `json:"name_id_attribute"`
	Certificate        string              `json:"certificate"`
	Status             string              `json:"status"`
	Attributes         *[]AttributeMapping `json:"attributes"`
	AssignmentRequired bool                `json:"assignment_required"`

	RequireSignedRequests bool `json:"require_signed_requests"`
	EncryptAssertions     bool `json:"encrypt_assertions"`
}

// check requires the ACS URL to pass validACSURL, a certificate, if given, to
// parse and to be kept for a use (checkCertificateUse), and the NameID
// settings and attributes to pass checkNameID and checkAttributes.
func (in *CreateSPInput) check() error {
	if in.Status != "" && !validStatus(in.Status) {
		return ErrStatusInvalid
	}
	in.ACSURL = strings.TrimSpace(in.ACSURL)
	if !validACSURL(in.ACSURL) {
		return ErrACSURLInvalid
	}
	if in.Certificate != "" {
		if _, err := parseCertificate(in.Certificate); err != nil {
			return ErrCertificateInvalid
		}
	}
	if err := checkCertificateUse(in.Certificate, in.RequireSignedRequests, in.EncryptAssertions); err != nil {
		return err
	}
	in.NameIDFormat, in.NameIDAttribute = strings.TrimSpace(in.NameIDFormat), strings.TrimSpace(in.NameIDAttribute)
	if err := checkNameID(&in.NameIDFormat, &in.NameIDAttribute); err != nil {
		return err
	}
	if in.Attributes != nil {
		return checkAttributes(*in.Attributes)
	}
	return nil
}

// validACSURL reports whether raw is an absolute https URL with a host and no
// user information, or plain http to a loopback host, where a signed assertion
// may be posted.
func validACSURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil {
		return false
	}
	switch h := u.Hostname(); u.Scheme {
	case "https":
		return true
	case "http":
		return h == "localhost" || h == "127.0.0.1" || h == "::1"
	}
	return false
}

// requireSSO refuses with ErrUpgradeRequired when the organization's plan doesn't
// include enterprise SSO (SAML), a paid feature. It reads on the pool, so the
// handler runs it before it opens the transaction CreateSP joins.
func (i *IdP) requireSSO(ctx context.Context, organizationID uuid.UUID) error {
	return requireSSO(ctx, i.gate, organizationID)
}

// requireSSO refuses with ErrUpgradeRequired when gate finds that the
// organization's plan doesn't include enterprise SSO.
func requireSSO(ctx context.Context, gate entitlements.PlanGate, organizationID uuid.UUID) error {
	ok, err := gate.FeatureAllowed(ctx, organizationID, "sso")
	if err != nil {
		return err
	}
	if !ok {
		return errs.ErrUpgradeRequired.WithMetadata(map[string]any{"feature": "sso"})
	}
	return nil
}

// CreateSP registers a service provider in organizationID, recorded as actor's,
// refusing input that fails check. Callers check the plan first, with
// requireSSO.
func (i *IdP) CreateSP(ctx context.Context, organizationID uuid.UUID, in CreateSPInput, actor audit.Actor) (*ServiceProvider, error) {
	tx, err := i.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	sp, err := i.createSP(ctx, tx, organizationID, in)
	if err != nil {
		return nil, err
	}
	if err := recordSPChange(ctx, tx, actor, organizationID, sp.ID, "saml.sp_created", map[string]any{
		"name": sp.Name, "entity_id": sp.EntityID, "name_id_format": sp.NameIDFormat, "name_id_attribute": sp.NameIDAttribute,
		"attributes": sp.Attributes, "assignment_required": sp.AssignmentRequired,
		"require_signed_requests": sp.RequireSignedRequests, "encrypt_assertions": sp.EncryptAssertions,
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return sp, nil
}

// recordSPChange audits, in tx, actor's change to organizationID's service
// provider id.
func recordSPChange(ctx context.Context, tx pgx.Tx, actor audit.Actor, organizationID, id uuid.UUID, action string, meta map[string]any) error {
	return audit.Record(ctx, tx, actor.Event(organizationID, action, "saml_service_provider", id, meta))
}

// createSP registers a service provider in organizationID within tx, refusing
// input that fails check.
func (i *IdP) createSP(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, in CreateSPInput) (*ServiceProvider, error) {
	if err := in.check(); err != nil {
		return nil, err
	}
	status := in.Status
	if status == "" {
		status = "draft"
	}
	attributes, err := encodeAttributes(in.Attributes)
	if err != nil {
		return nil, err
	}
	r, err := i.q.WithTx(tx).InsertSamlSP(ctx, dbgen.InsertSamlSPParams{
		OrganizationID:     organizationID,
		Name:               in.Name,
		EntityID:           in.EntityID,
		AcsUrl:             in.ACSURL,
		NameIDFormat:       in.NameIDFormat,
		NameIDAttribute:    in.NameIDAttribute,
		Certificate:        in.Certificate,
		Status:             status,
		Attributes:         attributes,
		AssignmentRequired: in.AssignmentRequired,

		RequireSignedRequests: in.RequireSignedRequests,
		EncryptAssertions:     in.EncryptAssertions,
	})
	if postgres.IsUnique(err) {
		return nil, ErrSPEntityIDTaken
	}
	if err != nil {
		return nil, err
	}
	return toSP(r), nil
}

// ListSP returns the organization's service providers.
func (i *IdP) ListSP(ctx context.Context, organizationID uuid.UUID) ([]ServiceProvider, error) {
	rows, err := i.q.ListSamlSPs(ctx, organizationID)
	if err != nil {
		return nil, err
	}
	out := make([]ServiceProvider, len(rows))
	for j, r := range rows {
		out[j] = *toSP(r)
	}
	return out, nil
}

// GetSP returns one of the organization's service providers.
func (i *IdP) GetSP(ctx context.Context, id, organizationID uuid.UUID) (*ServiceProvider, error) {
	r, err := i.q.GetSamlSP(ctx, dbgen.GetSamlSPParams{ID: id, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return toSP(r), nil
}

// UpdateSPInput is what UpdateSP takes. Attributes replaces the whole list.
type UpdateSPInput struct {
	Name               *string             `json:"name"`
	EntityID           *string             `json:"entity_id"`
	ACSURL             *string             `json:"acs_url"`
	NameIDFormat       *string             `json:"name_id_format"`
	NameIDAttribute    *string             `json:"name_id_attribute"`
	Certificate        *string             `json:"certificate"`
	Status             *string             `json:"status"`
	Attributes         *[]AttributeMapping `json:"attributes"`
	AssignmentRequired *bool               `json:"assignment_required"`

	RequireSignedRequests *bool `json:"require_signed_requests"`
	EncryptAssertions     *bool `json:"encrypt_assertions"`
}

// check applies CreateSPInput's checks to the fields being changed; UpdateSP
// checks the NameID settings and the certificate's use against the ones they
// change.
func (in *UpdateSPInput) check() error {
	if in.ACSURL != nil {
		acs := strings.TrimSpace(*in.ACSURL)
		if !validACSURL(acs) {
			return ErrACSURLInvalid
		}
		in.ACSURL = &acs
	}
	if in.Certificate != nil && *in.Certificate != "" {
		if _, err := parseCertificate(*in.Certificate); err != nil {
			return ErrCertificateInvalid
		}
	}
	if in.NameIDFormat != nil {
		f := strings.TrimSpace(*in.NameIDFormat)
		if f != "" && !knownNameIDFormat(f) {
			return ErrNameIDFormatInvalid
		}
		in.NameIDFormat = &f
	}
	if in.NameIDAttribute != nil {
		a := strings.TrimSpace(*in.NameIDAttribute)
		if a != "" && !validNameIDAttribute(a) {
			return ErrNameIDAttributeInvalid
		}
		in.NameIDAttribute = &a
	}
	if in.Attributes != nil {
		return checkAttributes(*in.Attributes)
	}
	return nil
}

// UpdateSP changes the given fields of a service provider in organizationID,
// recorded as actor's, refusing input that fails check or NameID settings
// mergeNameID refuses.
func (i *IdP) UpdateSP(ctx context.Context, id, organizationID uuid.UUID, in UpdateSPInput, actor audit.Actor) (*ServiceProvider, error) {
	tx, err := i.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	sp, err := i.updateSP(ctx, tx, id, organizationID, in)
	if err != nil {
		return nil, err
	}
	if err := recordSPChange(ctx, tx, actor, organizationID, sp.ID, "saml.sp_updated", spUpdateAudit(in, sp)); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return sp, nil
}

// updateSP changes the given fields of a service provider in organizationID
// within tx, refusing input that fails check or NameID settings mergeNameID
// refuses.
func (i *IdP) updateSP(ctx context.Context, tx pgx.Tx, id, organizationID uuid.UUID, in UpdateSPInput) (*ServiceProvider, error) {
	if err := in.check(); err != nil {
		return nil, err
	}
	q := i.q.WithTx(tx)
	certUse := in.Certificate != nil || in.RequireSignedRequests != nil || in.EncryptAssertions != nil
	if in.NameIDFormat != nil || in.NameIDAttribute != nil || certUse {
		cur, err := q.GetSamlSPForUpdate(ctx, dbgen.GetSamlSPForUpdateParams{ID: id, OrganizationID: organizationID})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errs.ErrNotFound
		}
		if err != nil {
			return nil, err
		}
		if in.NameIDFormat != nil || in.NameIDAttribute != nil {
			format, attribute, err := mergeNameID(cur.NameIDFormat, cur.NameIDAttribute, in.NameIDFormat, in.NameIDAttribute)
			if err != nil {
				return nil, err
			}
			in.NameIDFormat, in.NameIDAttribute = &format, &attribute
		}
		if certUse {
			cert, signed, encrypt := cur.Certificate, cur.RequireSignedRequests, cur.EncryptAssertions
			if in.Certificate != nil {
				cert = *in.Certificate
			}
			if in.RequireSignedRequests != nil {
				signed = *in.RequireSignedRequests
			}
			if in.EncryptAssertions != nil {
				encrypt = *in.EncryptAssertions
			}
			if err := checkCertificateUse(cert, signed, encrypt); err != nil {
				return nil, err
			}
		}
	}
	var attributes []byte
	if in.Attributes != nil {
		var err error
		if attributes, err = encodeAttributes(in.Attributes); err != nil {
			return nil, err
		}
	}
	r, err := q.UpdateSamlSP(ctx, dbgen.UpdateSamlSPParams{
		ID:                 id,
		OrganizationID:     organizationID,
		Name:               in.Name,
		EntityID:           in.EntityID,
		AcsUrl:             in.ACSURL,
		NameIDFormat:       in.NameIDFormat,
		NameIDAttribute:    in.NameIDAttribute,
		Certificate:        in.Certificate,
		Status:             in.Status,
		Attributes:         attributes,
		AssignmentRequired: in.AssignmentRequired,

		RequireSignedRequests: in.RequireSignedRequests,
		EncryptAssertions:     in.EncryptAssertions,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return toSP(r), nil
}

// DeleteSP removes one of the organization's service providers, recorded as
// actor's.
func (i *IdP) DeleteSP(ctx context.Context, id, organizationID uuid.UUID, actor audit.Actor) error {
	tx, err := i.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	n, err := i.q.WithTx(tx).DeleteSamlSP(ctx, dbgen.DeleteSamlSPParams{ID: id, OrganizationID: organizationID})
	if err != nil {
		return err
	}
	if n == 0 {
		return errs.ErrNotFound
	}
	if err := recordSPChange(ctx, tx, actor, organizationID, id, "saml.sp_deleted", nil); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// lookupSPByEntityID resolves the organization's (non-disabled) SP by its EntityID,
// which is unique only within an organization.
func (i *IdP) lookupSPByEntityID(ctx context.Context, organizationID uuid.UUID, entityID string) (*ServiceProvider, error) {
	r, err := i.q.GetSamlSPByEntityID(ctx, dbgen.GetSamlSPByEntityIDParams{OrganizationID: organizationID, EntityID: entityID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return toSP(r), nil
}

// lookupSP resolves the organization's SP by provider UUID (IdP-initiated
// ?sp=<uuid>) or EntityID.
func (i *IdP) lookupSP(ctx context.Context, organizationID uuid.UUID, key string) (*ServiceProvider, error) {
	if id, err := uuid.Parse(key); err == nil {
		return i.GetSP(ctx, id, organizationID)
	}
	return i.lookupSPByEntityID(ctx, organizationID, key)
}

// spUpdateAudit is what the audit records of a change to a service provider:
// the fields it named, and the new values of those deciding where assertions
// go, who gets them and what they say.
func spUpdateAudit(in UpdateSPInput, sp *ServiceProvider) map[string]any {
	meta := map[string]any{"status": sp.Status}
	changed := []string{}
	for _, f := range []struct {
		name  string
		set   bool
		value any
	}{
		{"name", in.Name != nil, nil},
		{"entity_id", in.EntityID != nil, sp.EntityID},
		{"acs_url", in.ACSURL != nil, sp.ACSURL},
		{"name_id_format", in.NameIDFormat != nil || in.NameIDAttribute != nil, sp.NameIDFormat},
		{"name_id_attribute", in.NameIDFormat != nil || in.NameIDAttribute != nil, sp.NameIDAttribute},
		{"certificate", in.Certificate != nil, nil},
		{"status", in.Status != nil, nil},
		{"attributes", in.Attributes != nil, sp.Attributes},
		{"assignment_required", in.AssignmentRequired != nil, sp.AssignmentRequired},
		{"require_signed_requests", in.RequireSignedRequests != nil, sp.RequireSignedRequests},
		{"encrypt_assertions", in.EncryptAssertions != nil, sp.EncryptAssertions},
	} {
		if !f.set {
			continue
		}
		changed = append(changed, f.name)
		if f.value != nil {
			meta[f.name] = f.value
		}
	}
	meta["changed"] = changed
	return meta
}

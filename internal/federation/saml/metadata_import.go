package saml

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/saml/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/operations/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/network/egress"
)

const (
	maxMetadataBytes        = 1 << 20          // largest metadata document read
	maxMetadataURLLength    = 2048             // longest metadata URL kept
	metadataFetchTimeout    = 10 * time.Second // one fetch, connecting included
	MetadataRefreshInterval = time.Hour        // how often the refresh job runs
	metadataRefreshAge      = 6 * time.Hour    // how old a fetch gets before the job repeats it
	metadataRefreshBatch    = 50               // connections one run fetches at most
)

const (
	nsMetadata       = "urn:oasis:names:tc:SAML:2.0:metadata"
	protocolSAML2    = "urn:oasis:names:tc:SAML:2.0:protocol"
	useSigning       = "signing"
	metadataFromURL  = "url"
	metadataFromXML  = "xml"
	errMetadataNoIdP = "The metadata describes no SAML 2.0 identity provider."
)

// IdPMetadata is what a connection takes from its IdP's metadata: the IdP's
// entity ID, its HTTP-Redirect SSO endpoint and its signing certificates.
type IdPMetadata struct {
	EntityID     string
	SSOURL       string
	Certificates []*x509.Certificate
}

// The parts of SAML 2.0 metadata a connection reads. Elements match by local
// name, so prefixes don't matter.
type (
	mdDocument struct {
		XMLName xml.Name
		mdEntity
		Entities []mdEntity `xml:"EntityDescriptor"`
	}
	mdEntity struct {
		EntityID string     `xml:"entityID,attr"`
		IdPs     []mdIdPSSO `xml:"IDPSSODescriptor"`
	}
	mdIdPSSO struct {
		Protocols string       `xml:"protocolSupportEnumeration,attr"`
		Keys      []mdKey      `xml:"KeyDescriptor"`
		SSO       []mdEndpoint `xml:"SingleSignOnService"`
	}
	mdKey struct {
		Use          string   `xml:"use,attr"`
		Certificates []string `xml:"KeyInfo>X509Data>X509Certificate"`
	}
	mdEndpoint struct {
		Binding  string `xml:"Binding,attr"`
		Location string `xml:"Location,attr"`
	}
)

// metadataInvalid is ErrSAMLMetadataInvalid saying why.
func metadataInvalid(format string, args ...any) error {
	return ErrMetadataInvalid.WithDetail(fmt.Sprintf(format, args...))
}

// parseIdPMetadata reads the IdP in raw, an EntityDescriptor or an
// EntitiesDescriptor. entityID, when given, names the IdP to read; otherwise
// raw must describe exactly one.
func parseIdPMetadata(raw []byte, entityID string) (*IdPMetadata, error) {
	if len(raw) > maxMetadataBytes {
		return nil, metadataInvalid("The metadata is larger than %d KiB.", maxMetadataBytes>>10)
	}
	var doc mdDocument
	if err := xml.NewDecoder(bytes.NewReader(raw)).Decode(&doc); err != nil {
		return nil, metadataInvalid("The metadata isn't well-formed XML.")
	}
	var entities []mdEntity
	switch {
	case doc.XMLName.Space == nsMetadata && doc.XMLName.Local == "EntityDescriptor":
		entities = []mdEntity{doc.mdEntity}
	case doc.XMLName.Space == nsMetadata && doc.XMLName.Local == "EntitiesDescriptor":
		entities = doc.Entities
	default:
		return nil, metadataInvalid("The document isn't SAML 2.0 metadata.")
	}
	var idps []mdEntity
	for _, e := range entities {
		if slices.ContainsFunc(e.IdPs, func(d mdIdPSSO) bool { return strings.Contains(d.Protocols, protocolSAML2) }) {
			idps = append(idps, e)
		}
	}
	entityID = strings.TrimSpace(entityID)
	switch {
	case entityID != "":
		i := slices.IndexFunc(idps, func(e mdEntity) bool { return strings.TrimSpace(e.EntityID) == entityID })
		if i < 0 {
			return nil, metadataInvalid("The metadata doesn't describe the identity provider %s.", entityID)
		}
		idps = idps[i : i+1]
	case len(idps) == 0:
		return nil, metadataInvalid(errMetadataNoIdP)
	case len(idps) > 1:
		return nil, metadataInvalid("The metadata describes %d identity providers; give the entity ID of the one to use.", len(idps))
	}
	return idpFromEntity(idps[0])
}

// idpFromEntity reads the SSO endpoint and signing certificates of e's SAML
// 2.0 IdP descriptors.
func idpFromEntity(e mdEntity) (*IdPMetadata, error) {
	md := &IdPMetadata{EntityID: strings.TrimSpace(e.EntityID)}
	if md.EntityID == "" || len(md.EntityID) > 1024 {
		return nil, metadataInvalid("The identity provider's entity ID is missing or too long.")
	}
	for _, d := range e.IdPs {
		if !strings.Contains(d.Protocols, protocolSAML2) {
			continue
		}
		for _, sso := range d.SSO {
			if location := strings.TrimSpace(sso.Location); md.SSOURL == "" && sso.Binding == bindingRedirect && validIdPSSOURL(location) {
				md.SSOURL = location
			}
		}
		for _, key := range d.Keys {
			if key.Use != "" && key.Use != useSigning {
				continue
			}
			for _, raw := range key.Certificates {
				cert, err := parseCertificate(raw)
				if err != nil {
					return nil, metadataInvalid("A signing certificate in the metadata isn't a valid X.509 certificate.")
				}
				if !slices.ContainsFunc(md.Certificates, cert.Equal) {
					md.Certificates = append(md.Certificates, cert)
				}
			}
		}
	}
	switch {
	case md.SSOURL == "":
		return nil, metadataInvalid("The metadata has no https SingleSignOnService with the HTTP-Redirect binding.")
	case len(md.Certificates) == 0:
		return nil, metadataInvalid("The metadata lists no signing certificate.")
	case len(md.Certificates) > maxCertificates:
		return nil, metadataInvalid("The metadata lists more than %d signing certificates.", maxCertificates)
	}
	return md, nil
}

// SetEgressPolicy sets the outbound policy metadata URLs are fetched through;
// public https addresses only until it is called.
func (s *Service) SetEgressPolicy(p *egress.Policy) {
	s.egress = p
	s.metadataHTTP = p.HTTPClient(metadataFetchTimeout)
}

// fetchMetadata reads the metadata at rawURL through the egress policy. The
// errors say what failed without echoing what the URL resolved to.
func (s *Service) fetchMetadata(ctx context.Context, rawURL string) ([]byte, error) {
	if len(rawURL) > maxMetadataURLLength {
		return nil, ErrMetadataURLInvalid
	}
	u, err := s.egress.ValidateHTTPURL(rawURL)
	if err != nil {
		return nil, ErrMetadataURLInvalid
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, ErrMetadataURLInvalid
	}
	req.Header.Set("Accept", "application/samlmetadata+xml, application/xml;q=0.9, text/xml;q=0.8")
	resp, err := s.metadataHTTP.Do(req)
	if err != nil {
		slog.Info("saml metadata: fetch failed", "err", err)
		return nil, ErrMetadataUnreachable.WithDetail("The metadata URL couldn't be reached.")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, ErrMetadataUnreachable.WithDetail(fmt.Sprintf("The metadata URL answered HTTP %d.", resp.StatusCode))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataBytes+1))
	if err != nil {
		return nil, ErrMetadataUnreachable.WithDetail("The metadata couldn't be read from its URL.")
	}
	if len(body) > maxMetadataBytes {
		return nil, metadataInvalid("The metadata is larger than %d KiB.", maxMetadataBytes>>10)
	}
	return body, nil
}

// LoadMetadata returns the IdP described by metadataXML, or by the metadata
// fetched from metadataURL; exactly one must be given. entityID, when given,
// names the IdP to read from metadata describing several.
func (s *Service) LoadMetadata(ctx context.Context, metadataURL, metadataXML, entityID string) (*IdPMetadata, error) {
	metadataURL, metadataXML = strings.TrimSpace(metadataURL), strings.TrimSpace(metadataXML)
	if (metadataURL == "") == (metadataXML == "") {
		return nil, ErrMetadataRequired
	}
	raw := []byte(metadataXML)
	if metadataURL != "" {
		var err error
		if raw, err = s.fetchMetadata(ctx, metadataURL); err != nil {
			return nil, err
		}
	}
	return parseIdPMetadata(raw, entityID)
}

// MetadataChange is what applying metadata changed: the fingerprints of the
// certificates added and removed, and the new SSO URL if it moved.
type MetadataChange struct {
	Added   []string
	Removed []string
	SSOURL  string
}

// empty reports whether nothing changed.
func (c *MetadataChange) empty() bool {
	return len(c.Added) == 0 && len(c.Removed) == 0 && c.SSOURL == ""
}

// ApplyMetadata gives connectionID md's SSO URL and certificates within tx.
// Certificates md lists are trusted from now on; ones an earlier metadata
// listed and md doesn't are dropped; ones an administrator added stay.
// metadataURL is where to refresh from later, nil for nowhere.
func (s *Service) ApplyMetadata(ctx context.Context, tx pgx.Tx, connectionID, organizationID uuid.UUID, md *IdPMetadata, metadataURL *string) (*MetadataChange, error) {
	q := s.q.WithTx(tx)
	current, err := q.LockSamlMetadataSource(ctx, dbgen.LockSamlMetadataSourceParams{ID: connectionID, OrganizationID: organizationID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	rows, err := q.ListSamlCertificates(ctx, dbgen.ListSamlCertificatesParams{ConnectionID: connectionID, OrganizationID: organizationID})
	if err != nil {
		return nil, err
	}
	change := &MetadataChange{}
	if current.IdpSsoUrl != md.SSOURL {
		change.SSOURL = md.SSOURL
	}
	listed := make([]bool, len(md.Certificates))
	kept := 0
	for _, r := range rows {
		i := slices.IndexFunc(md.Certificates, func(c *x509.Certificate) bool { return sameCertificate(r.Certificate, c) })
		switch {
		case i >= 0:
			listed[i] = true
			kept++
			if r.Source != certificateMetadata {
				if err := q.SetSamlCertificateSource(ctx, dbgen.SetSamlCertificateSourceParams{Source: certificateMetadata, ID: r.ID, OrganizationID: organizationID}); err != nil {
					return nil, err
				}
			}
		case r.Source == certificateMetadata:
			if err := q.DeleteSamlCertificate(ctx, dbgen.DeleteSamlCertificateParams{ID: r.ID, ConnectionID: connectionID, OrganizationID: organizationID}); err != nil {
				return nil, err
			}
			change.Removed = append(change.Removed, toCertificate(r).FingerprintSHA256)
		default:
			kept++
		}
	}
	for i, cert := range md.Certificates {
		if listed[i] {
			continue
		}
		if kept >= maxCertificates {
			return nil, ErrCertificateLimit
		}
		if _, err := q.InsertSamlCertificate(ctx, dbgen.InsertSamlCertificateParams{
			OrganizationID: organizationID, ConnectionID: connectionID, Certificate: certificatePEM(cert), Source: certificateMetadata,
		}); err != nil {
			return nil, err
		}
		kept++
		change.Added = append(change.Added, fingerprint(cert))
	}
	if len(change.Added) > 0 || len(change.Removed) > 0 {
		if err := q.SyncSamlPrimaryCertificate(ctx, dbgen.SyncSamlPrimaryCertificateParams{ID: connectionID, OrganizationID: organizationID}); err != nil {
			return nil, err
		}
	}
	return change, q.SetSamlIdPFromMetadata(ctx, dbgen.SetSamlIdPFromMetadataParams{
		IdpSsoUrl: md.SSOURL, MetadataUrl: metadataURL, ID: connectionID, OrganizationID: organizationID,
	})
}

// ImportInput creates a connection from its IdP's metadata, given as the XML
// or as a URL to fetch it from and refresh it from later. IdpEntityID names
// the IdP to use from metadata describing several.
type ImportInput struct {
	Name            string `json:"name"`
	MetadataURL     string `json:"metadata_url"`
	MetadataXML     string `json:"metadata_xml"`
	IdpEntityID     string `json:"idp_entity_id"`
	EmailAttribute  string `json:"email_attribute"`
	NameAttribute   string `json:"name_attribute"`
	GroupsAttribute string `json:"groups_attribute"`
	Status          string `json:"status"`
}

// Import creates a connection in organizationID with md's entity ID, SSO URL and
// certificates, refreshed from in.MetadataURL when that is given, recorded as
// actor's.
func (s *Service) Import(ctx context.Context, organizationID uuid.UUID, in ImportInput, md *IdPMetadata, actor audit.Actor) (*Connection, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	conn, err := s.create(ctx, tx, organizationID, CreateInput{
		Name: in.Name, IdpEntityID: md.EntityID, IdpSSOURL: md.SSOURL, IdpCertificate: certificatePEM(md.Certificates[0]),
		EmailAttribute: in.EmailAttribute, NameAttribute: in.NameAttribute, GroupsAttribute: in.GroupsAttribute, Status: in.Status,
	})
	if err != nil {
		return nil, err
	}
	var refreshFrom *string
	if u := strings.TrimSpace(in.MetadataURL); u != "" {
		refreshFrom = &u
	}
	if _, err := s.ApplyMetadata(ctx, tx, conn.ID, organizationID, md, refreshFrom); err != nil {
		return nil, err
	}
	source := metadataFromXML
	if refreshFrom != nil {
		source = metadataFromURL
	}
	if err := recordChange(ctx, tx, actor, organizationID, conn.ID, "saml.connection_created", map[string]any{
		"name": conn.Name, "idp": conn.IdpEntityID, "metadata": source,
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return conn, nil
}

// UpdateFromMetadata gives organizationID's connection id md's SSO URL and
// certificates, refreshed from refreshFrom when that is given (from XML, it
// stops refreshing), recorded as actor's.
func (s *Service) UpdateFromMetadata(ctx context.Context, id, organizationID uuid.UUID, md *IdPMetadata, refreshFrom *string, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	change, err := s.ApplyMetadata(ctx, tx, id, organizationID, md, refreshFrom)
	if err != nil {
		return err
	}
	source := metadataFromXML
	if refreshFrom != nil {
		source = metadataFromURL
	}
	if err := recordChange(ctx, tx, actor, organizationID, id, "saml.connection_updated", map[string]any{
		"metadata": source, "certificates_added": change.Added, "certificates_removed": change.Removed, "idp_sso_url": change.SSOURL,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// withMetadataSource fills c's metadata fields from q.
func withMetadataSource(ctx context.Context, q *dbgen.Queries, c *Connection) error {
	r, err := q.GetSamlMetadataSource(ctx, dbgen.GetSamlMetadataSourceParams{ID: c.ID, OrganizationID: c.OrganizationID})
	if err != nil {
		return err
	}
	c.MetadataURL, c.RefreshedAt, c.MetadataError = r.MetadataUrl, r.MetadataRefreshedAt, r.MetadataError
	return nil
}

// withMetadataSources fills the metadata fields of the organization's connections.
func (s *Service) withMetadataSources(ctx context.Context, organizationID uuid.UUID, conns []Connection) error {
	rows, err := s.q.ListSamlMetadataSources(ctx, organizationID)
	if err != nil {
		return err
	}
	byID := make(map[uuid.UUID]dbgen.ListSamlMetadataSourcesRow, len(rows))
	for _, r := range rows {
		byID[r.ID] = r
	}
	for i := range conns {
		r := byID[conns[i].ID]
		conns[i].MetadataURL, conns[i].RefreshedAt, conns[i].MetadataError = r.MetadataUrl, r.MetadataRefreshedAt, r.MetadataError
	}
	return nil
}

// importConnection creates a connection from its IdP's metadata.
func (h *Handler) importConnection(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var in ImportInput
	if err := httpx.DecodeJSON(r, &in); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if in.Name = strings.TrimSpace(in.Name); in.Name == "" {
		httpx.WriteError(w, r, ErrConnectionFieldsRequired.WithMessage("A name is required."))
		return
	}
	if in.Status != "" && !validStatus(in.Status) {
		httpx.WriteError(w, r, ErrStatusInvalid)
		return
	}
	ctx := r.Context()
	// Before the metadata is fetched: a plan without SSO sets up no connection.
	if err := h.Service.RequireSSO(ctx, organizationID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	md, err := h.Service.LoadMetadata(ctx, in.MetadataURL, in.MetadataXML, in.IdpEntityID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	conn, err := h.Service.Import(ctx, organizationID, in, md, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	created, err := h.Service.Get(ctx, conn.ID, organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, h.view(r, created))
}

// applyMetadata gives a connection its IdP's metadata, from a URL (kept for
// refreshing), from XML (which stops refreshing), or, given neither, from the
// URL it refreshes from. The metadata must describe the connection's IdP.
func (h *Handler) applyMetadata(w http.ResponseWriter, r *http.Request) {
	organizationID, err := httpx.PathOrganization(r)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	id, err := httpx.PathUUID(r, "id", ErrIDInvalid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var body struct {
		MetadataURL string `json:"metadata_url"`
		MetadataXML string `json:"metadata_xml"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	conn, err := h.Service.Get(ctx, id, organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	metadataURL, metadataXML := strings.TrimSpace(body.MetadataURL), strings.TrimSpace(body.MetadataXML)
	// Metadata from anywhere but the connection's own URL changes what it
	// trusts; a refresh from that URL is the IdP's own rollover.
	if metadataXML != "" || (metadataURL != "" && (conn.MetadataURL == nil || metadataURL != *conn.MetadataURL)) {
		if err := h.checkTrust(r, organizationID, id); err != nil {
			httpx.WriteError(w, r, err)
			return
		}
	}
	if metadataURL == "" && metadataXML == "" && conn.MetadataURL != nil {
		metadataURL = *conn.MetadataURL
	}
	md, err := h.Service.LoadMetadata(ctx, metadataURL, metadataXML, conn.IdpEntityID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	var refreshFrom *string
	if metadataURL != "" {
		refreshFrom = &metadataURL
	}
	if err := h.Service.UpdateFromMetadata(ctx, id, organizationID, md, refreshFrom, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	updated, err := h.Service.Get(ctx, id, organizationID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, h.view(r, updated))
}

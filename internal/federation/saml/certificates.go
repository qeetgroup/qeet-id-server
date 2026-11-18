package saml

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/federation/saml/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

const (
	certificateManual   = "manual"   // added by an administrator
	certificateMetadata = "metadata" // listed in the IdP's metadata
	maxCertificates     = 8          // trusted by one connection at once
)

// Certificate is one of the IdP signing certificates a connection trusts; an
// assertion signed with any of them is accepted. Subject, fingerprint and
// validity are read from the certificate, and are empty if it doesn't parse.
type Certificate struct {
	ID                uuid.UUID  `json:"id"`
	Certificate       string     `json:"certificate"`
	Subject           string     `json:"subject"`
	FingerprintSHA256 string     `json:"fingerprint_sha256"`
	NotBefore         *time.Time `json:"not_before"`
	NotAfter          *time.Time `json:"not_after"`
	Source            string     `json:"source"`
	CreatedAt         time.Time  `json:"created_at"`
}

// toCertificate maps a stored certificate to its API form.
func toCertificate(r dbgen.OrganizationSamlConnectionCertificate) Certificate {
	out := Certificate{ID: r.ID, Certificate: r.Certificate, Source: r.Source, CreatedAt: r.CreatedAt}
	if cert, err := parseCertificate(r.Certificate); err == nil {
		notBefore, notAfter := cert.NotBefore, cert.NotAfter
		out.Subject = cert.Subject.String()
		out.FingerprintSHA256 = fingerprint(cert)
		out.NotBefore, out.NotAfter = &notBefore, &notAfter
	}
	return out
}

// fingerprint is the certificate's SHA-256 fingerprint, as IdP consoles show it.
func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	pairs := make([]string, len(sum))
	for i, b := range sum {
		pairs[i] = strings.ToUpper(hex.EncodeToString([]byte{b}))
	}
	return strings.Join(pairs, ":")
}

// certificatePEM is cert as a PEM block, the form new certificates are stored in.
func certificatePEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
}

// sameCertificate reports whether the stored raw certificate is cert.
func sameCertificate(raw string, cert *x509.Certificate) bool {
	stored, err := parseCertificate(raw)
	return err == nil && stored.Equal(cert)
}

// listCertificates returns the certificates connectionID trusts, oldest first.
func listCertificates(ctx context.Context, q *dbgen.Queries, connectionID, organizationID uuid.UUID) ([]Certificate, error) {
	rows, err := q.ListSamlCertificates(ctx, dbgen.ListSamlCertificatesParams{ConnectionID: connectionID, OrganizationID: organizationID})
	if err != nil {
		return nil, err
	}
	out := make([]Certificate, len(rows))
	for i, r := range rows {
		out[i] = toCertificate(r)
	}
	return out, nil
}

// signingCertificates returns the certificates conn's IdP may sign with, leaving
// out any that don't parse.
func (s *Service) signingCertificates(ctx context.Context, conn *Connection) ([]*x509.Certificate, error) {
	rows, err := s.q.ListSamlCertificates(ctx, dbgen.ListSamlCertificatesParams{ConnectionID: conn.ID, OrganizationID: conn.OrganizationID})
	if err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	for _, r := range rows {
		if cert, err := parseCertificate(r.Certificate); err == nil {
			out = append(out, cert)
		}
	}
	return out, nil
}

// replaceCertificates makes cert the only one connectionID trusts, within q's
// transaction.
func replaceCertificates(ctx context.Context, q *dbgen.Queries, connectionID, organizationID uuid.UUID, cert *x509.Certificate) error {
	if err := q.DeleteSamlCertificates(ctx, dbgen.DeleteSamlCertificatesParams{ConnectionID: connectionID, OrganizationID: organizationID}); err != nil {
		return err
	}
	_, err := q.InsertSamlCertificate(ctx, dbgen.InsertSamlCertificateParams{
		OrganizationID: organizationID, ConnectionID: connectionID, Certificate: certificatePEM(cert), Source: certificateManual,
	})
	return err
}

// AddCertificate makes connectionID also trust the certificate raw, such as the
// IdP's next one ahead of a rollover, recorded as actor's.
func (s *Service) AddCertificate(ctx context.Context, connectionID, organizationID uuid.UUID, raw string, actor audit.Actor) (*Certificate, error) {
	cert, err := parseCertificate(raw)
	if err != nil {
		return nil, ErrCertificateInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	if _, err := q.LockSamlConnection(ctx, dbgen.LockSamlConnectionParams{ID: connectionID, OrganizationID: organizationID}); errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	} else if err != nil {
		return nil, err
	}
	rows, err := q.ListSamlCertificates(ctx, dbgen.ListSamlCertificatesParams{ConnectionID: connectionID, OrganizationID: organizationID})
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if sameCertificate(r.Certificate, cert) {
			return nil, ErrCertificateExists
		}
	}
	if len(rows) >= maxCertificates {
		return nil, ErrCertificateLimit
	}
	row, err := q.InsertSamlCertificate(ctx, dbgen.InsertSamlCertificateParams{
		OrganizationID: organizationID, ConnectionID: connectionID, Certificate: certificatePEM(cert), Source: certificateManual,
	})
	if err != nil {
		return nil, err
	}
	out := toCertificate(row)
	if err := recordChange(ctx, tx, actor, organizationID, connectionID, "saml.certificate_added", map[string]any{
		"fingerprint_sha256": out.FingerprintSHA256, "not_after": out.NotAfter,
	}); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &out, nil
}

// RemoveCertificate stops connectionID trusting certificateID, recorded as
// actor's. The connection's last certificate can't be removed.
func (s *Service) RemoveCertificate(ctx context.Context, connectionID, organizationID, certificateID uuid.UUID, actor audit.Actor) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	if _, err := q.LockSamlConnection(ctx, dbgen.LockSamlConnectionParams{ID: connectionID, OrganizationID: organizationID}); errors.Is(err, pgx.ErrNoRows) {
		return errs.ErrNotFound
	} else if err != nil {
		return err
	}
	certs, err := listCertificates(ctx, q, connectionID, organizationID)
	if err != nil {
		return err
	}
	var removed *Certificate
	for i := range certs {
		if certs[i].ID == certificateID {
			removed = &certs[i]
		}
	}
	if removed == nil {
		return errs.ErrNotFound
	}
	if len(certs) == 1 {
		return ErrCertificateLast
	}
	if err := q.DeleteSamlCertificate(ctx, dbgen.DeleteSamlCertificateParams{ID: certificateID, ConnectionID: connectionID, OrganizationID: organizationID}); err != nil {
		return err
	}
	if err := q.SyncSamlPrimaryCertificate(ctx, dbgen.SyncSamlPrimaryCertificateParams{ID: connectionID, OrganizationID: organizationID}); err != nil {
		return err
	}
	if err := recordChange(ctx, tx, actor, organizationID, connectionID, "saml.certificate_removed", map[string]any{
		"fingerprint_sha256": removed.FingerprintSHA256,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (h *Handler) addCertificate(w http.ResponseWriter, r *http.Request) {
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
		Certificate string `json:"certificate"`
	}
	if err := httpx.DecodeJSON(r, &body); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	ctx := r.Context()
	// Another certificate trusted is another key that can sign its linked
	// accounts in.
	if err := h.checkTrust(r, organizationID, id); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	cert, err := h.Service.AddCertificate(ctx, id, organizationID, body.Certificate, audit.ActorOf(r))
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, cert)
}

func (h *Handler) removeCertificate(w http.ResponseWriter, r *http.Request) {
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
	certificateID, err := httpx.PathUUID(r, "certificateID", ErrIDInvalid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.RemoveCertificate(r.Context(), id, organizationID, certificateID, audit.ActorOf(r)); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// parseCertificate accepts a PEM block or bare base64 DER and returns the cert.
func parseCertificate(raw string) (*x509.Certificate, error) {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "-----BEGIN") {
		block, _ := pem.Decode([]byte(raw))
		if block == nil {
			return nil, errors.New("invalid PEM certificate")
		}
		return x509.ParseCertificate(block.Bytes)
	}
	// Bare base64 DER (as found in IdP metadata <X509Certificate>): strip
	// any whitespace the copy-paste introduced.
	clean := strings.NewReplacer("\n", "", "\r", "", " ", "", "\t", "").Replace(raw)
	der, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("certificate is neither PEM nor base64 DER: %w", err)
	}
	return x509.ParseCertificate(der)
}

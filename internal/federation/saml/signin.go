package saml

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	saml2 "github.com/russellhaering/gosaml2"
	samltypes "github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/qeetgroup/qeet-id-server/internal/federation/saml/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// assertionClockSkew is how far the IdP's clock may be from ours: an assertion
// is accepted this long before its NotBefore and after its NotOnOrAfter.
const assertionClockSkew = 3 * time.Minute

// validateResponse checks the encoded SAMLResponse against each of the IdP's
// certificates valid at now in turn, so one signed with any of them is
// accepted, and returns the response and its assertion. Each attempt trusts a
// single certificate, so a signature without KeyInfo is checked against each.
//
// gosaml2 checks the expiry times on a clock assertionClockSkew behind now, and
// withinValidity the whole window either way; the signature, issuer, audience,
// recipient and destination checks are unchanged. key, when not nil, decrypts
// an EncryptedAssertion, which must still be signed. A signed assertion whose
// conditions fail comes back with ErrSAMLAssertionConditions, for a test
// sign-in to report what it asserted.
func (s *Service) validateResponse(base string, conn *Connection, certs []*x509.Certificate, key *tls.Certificate, encoded string, now time.Time) (*samltypes.Response, *saml2.AssertionInfo, error) {
	var failures []error
	for _, cert := range certs {
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			failures = append(failures, fmt.Errorf("certificate %s is outside its validity period", fingerprint(cert)))
			continue
		}
		sp := s.buildSP(base, conn, []*x509.Certificate{cert})
		sp.Clock = dsig.NewFakeClockAt(now.Add(-assertionClockSkew))
		if key != nil {
			sp.SPKeyStore = dsig.TLSCertKeyStore(*key)
		}
		response, err := sp.ValidateEncodedResponse(encoded)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		info, err := sp.RetrieveAssertionInfo(encoded)
		if err != nil {
			slog.Warn("saml acs: assertion validation failed", "err", err, "connection", conn.ID)
			return nil, nil, errs.ErrSAMLAssertionInvalid.Wrap(err)
		}
		current := withinValidity(info.Assertions, now)
		elsewhere := info.WarningInfo != nil && info.WarningInfo.NotInAudience
		if !current || elsewhere {
			slog.Warn("saml acs: assertion conditions not met", "connection", conn.ID,
				"invalid_time", !current, "not_in_audience", elsewhere)
			why := "the assertion is outside its validity period"
			if elsewhere {
				why = "the assertion's audience isn't this connection's SP entity ID"
			}
			return response, info, ErrAssertionConditions.Wrap(errors.New(why))
		}
		return response, info, nil
	}
	slog.Warn("saml acs: response validation failed", "err", errors.Join(failures...), "connection", conn.ID)
	return nil, nil, errs.ErrSAMLAssertionInvalid.Wrap(errors.Join(failures...))
}

// replayKeepUntil is how long the IDs of a response carrying assertions are
// kept against replay: replayIDTTL from now, or until its longest-lived
// assertion stops being accepted (NotOnOrAfter plus the clock skew allowed),
// whichever is later.
func replayKeepUntil(assertions []samltypes.Assertion, now time.Time) time.Time {
	until := now.Add(replayIDTTL)
	for _, a := range assertions {
		if a.Conditions == nil {
			continue
		}
		if end, err := time.Parse(time.RFC3339, a.Conditions.NotOnOrAfter); err == nil && end.Add(assertionClockSkew).After(until) {
			until = end.Add(assertionClockSkew)
		}
	}
	return until
}

// withinValidity reports whether every assertion's Conditions hold at now,
// allowing assertionClockSkew either way.
func withinValidity(assertions []samltypes.Assertion, now time.Time) bool {
	if len(assertions) == 0 {
		return false
	}
	for _, a := range assertions {
		if a.Conditions == nil {
			return false
		}
		notBefore, err := time.Parse(time.RFC3339, a.Conditions.NotBefore)
		if err != nil {
			return false
		}
		notOnOrAfter, err := time.Parse(time.RFC3339, a.Conditions.NotOnOrAfter)
		if err != nil {
			return false
		}
		if now.Add(assertionClockSkew).Before(notBefore) || !now.Add(-assertionClockSkew).Before(notOnOrAfter) {
			return false
		}
	}
	return true
}

func (s *Service) storeAuthnRequest(ctx context.Context, connectionID uuid.UUID, requestID, returnTo string) error {
	if strings.TrimSpace(requestID) == "" || len(requestID) > 1024 {
		return ErrRequestInvalid
	}
	if sweepDue(&s.nextRequestSweep) {
		if err := s.q.PurgeExpiredSamlAuthnRequests(ctx); err != nil {
			return err
		}
	}
	return s.q.InsertSamlAuthnRequest(ctx, dbgen.InsertSamlAuthnRequestParams{
		RequestID: requestID, ConnectionID: connectionID, ExpiresAt: time.Now().UTC().Add(authnRequestTTL), ReturnTo: returnTo,
	})
}

// hostedReturn is the return_to stored by the latest pending sign-in, among requestIDs, that the
// hosted login began on the connection; "" when there is none.
func (s *Service) hostedReturn(ctx context.Context, connectionID uuid.UUID, requestIDs []string) string {
	if len(requestIDs) == 0 {
		return ""
	}
	stored, err := s.q.HostedSamlReturn(ctx, dbgen.HostedSamlReturnParams{ConnectionID: connectionID, RequestIds: requestIDs})
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			slog.Error("saml: read a pending sign-in's return address", "err", err, "connection", connectionID)
		}
		return ""
	}
	return stored
}

// ConsumeValidatedResponse atomically reserves the response and assertion IDs
// against replay until keepUntil (replayKeepUntil) and consumes the matching
// AuthnRequest, returning where the hosted login asked the browser to go back
// to ("" for a console sign-in). Call it only after the signature and
// conditions are validated. An empty requestID (IdP-initiated) is refused with
// ErrSAMLRequestCorrelation unless allowIdPInitiated.
func (s *Service) ConsumeValidatedResponse(ctx context.Context, connectionID uuid.UUID, requestID, responseID string, assertionIDs []string, keepUntil time.Time, allowIdPInitiated bool) (string, error) {
	returnTo := ""
	idpInitiated := strings.TrimSpace(requestID) == ""
	if idpInitiated && !allowIdPInitiated {
		return "", ErrRequestCorrelation
	}
	if !idpInitiated && len(requestID) > 1024 {
		return "", ErrRequestCorrelation
	}
	if strings.TrimSpace(responseID) == "" || len(responseID) > 1024 || len(assertionIDs) == 0 || len(assertionIDs) > 16 {
		return "", errs.ErrSAMLAssertionInvalid
	}
	ids := make([]struct{ kind, id string }, 0, len(assertionIDs)+1)
	ids = append(ids, struct{ kind, id string }{"response", responseID})
	for _, assertionID := range assertionIDs {
		if strings.TrimSpace(assertionID) == "" || len(assertionID) > 1024 {
			return "", errs.ErrSAMLAssertionInvalid
		}
		ids = append(ids, struct{ kind, id string }{"assertion", assertionID})
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	if sweepDue(&s.nextReplaySweep) {
		if err := q.PurgeExpiredSamlReplayIDs(ctx); err != nil {
			return "", err
		}
	}
	for _, candidate := range ids {
		n, err := q.ReserveSamlReplayID(ctx, dbgen.ReserveSamlReplayIDParams{
			ConnectionID: connectionID, Kind: candidate.kind, SamlID: candidate.id, ExpiresAt: keepUntil.UTC(),
		})
		if err != nil {
			return "", err
		}
		if n != 1 {
			return "", ErrReplayDetected
		}
	}
	// Correlation is consumed only for SP-initiated responses. An opted-in
	// IdP-initiated response has no AuthnRequest to match by definition, so
	// running this would find no row and reject every one of them. The replay
	// reservations above still ran, which is what actually stops a resend.
	if !idpInitiated {
		stored, err := q.ConsumeSamlAuthnRequest(ctx, dbgen.ConsumeSamlAuthnRequestParams{RequestID: requestID, ConnectionID: connectionID})
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrRequestCorrelation
		}
		if err != nil {
			return "", err
		}
		if stored != nil {
			returnTo = *stored
		}
	}
	return returnTo, tx.Commit(ctx)
}

// signInStatus refuses a sign-in through a connection that isn't active: a
// draft one is still being set up, so it signs nobody in until an
// administrator turns it on.
func signInStatus(status string) error {
	switch status {
	case "active":
		return nil
	case "draft":
		return ErrConnectionDraft
	}
	return ErrConnectionDisabled
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.PathUUID(r, "id", ErrIDInvalid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// A sign-in started on the hosted login names where the browser goes back to (the
	// application's authorize request); its answer then returns to the hosted login.
	returnTo := r.URL.Query().Get("return_to")
	if returnTo != "" && (h.Service.loginBaseURL == "" || !h.Service.returnTo.Valid(returnTo)) {
		httpx.WriteError(w, r, ErrReturnToInvalid)
		return
	}
	conn, err := h.Service.getByID(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := signInStatus(conn.Status); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if err := h.Service.RequireSSO(r.Context(), conn.OrganizationID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if !validIdPSSOURL(conn.IdpSSOURL) {
		slog.Error("saml login: IdP SSO URL is not an absolute https URL", "connection", conn.ID)
		httpx.WriteError(w, r, ErrConnectionMisconfigured)
		return
	}
	certs, err := h.Service.signingCertificates(r.Context(), conn)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	if len(certs) == 0 {
		slog.Error("saml login: no readable IdP certificate", "connection", conn.ID)
		httpx.WriteError(w, r, ErrConnectionMisconfigured)
		return
	}
	sp := h.Service.buildSP(h.publicBase(r), conn, certs)
	doc, err := sp.BuildAuthRequestDocument()
	if err != nil {
		slog.Error("saml login: build auth request", "err", err, "connection", conn.ID)
		httpx.WriteError(w, r, errs.ErrInternalServer)
		return
	}
	if doc.Root() == nil {
		slog.Error("saml login: generated auth request has no root", "connection", conn.ID)
		httpx.WriteError(w, r, errs.ErrInternalServer)
		return
	}
	requestID := doc.Root().SelectAttrValue("ID", "")
	authURL, err := sp.BuildAuthURLFromDocument(r.URL.Query().Get("relay"), doc)
	if err != nil {
		slog.Error("saml login: build auth url", "err", err, "connection", conn.ID)
		httpx.WriteError(w, r, errs.ErrInternalServer)
		return
	}
	if err := h.Service.storeAuthnRequest(r.Context(), conn.ID, requestID, returnTo); err != nil {
		slog.Error("saml login: persist request", "err", err, "connection", conn.ID)
		httpx.WriteError(w, r, errs.ErrInternalServer)
		return
	}
	h.binding().Add(w, r, requestID)
	http.Redirect(w, r, authURL, http.StatusFound) // #nosec G710 -- IdP SSO URL checked by validIdPSSOURL on save and above
}

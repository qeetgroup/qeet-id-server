package saml

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	saml2 "github.com/russellhaering/gosaml2"

	"github.com/qeetgroup/qeet-id-server/internal/federation/saml/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// TestSignInRetention is how long a test sign-in, and what the IdP sent it,
// is kept.
const TestSignInRetention = time.Hour

const (
	testPending   = "pending"
	testSucceeded = "succeeded"
	testFailed    = "failed"
	testExpired   = "expired" // pending past its expiry; never stored

	maxTestAttributes  = 64  // attributes a test reports
	maxTestValues      = 32  // values a test reports per attribute
	maxTestValueBytes  = 512 // bytes a test reports per name or value
	maxTestDetailBytes = 300 // bytes of a validation error a test reports
)

// TestSignIn is a test of a connection: a real sign-in at the IdP whose answer
// is checked as a sign-in's is and reported, and which signs nobody in. Status
// is pending, succeeded, failed, or expired when no answer came in time.
type TestSignIn struct {
	ID           uuid.UUID  `json:"id"`
	ConnectionID uuid.UUID  `json:"connection_id"`
	Status       string     `json:"status"`
	RedirectURL  string     `json:"redirect_url,omitempty"` // the IdP address to send the browser to; only as the test begins
	ExpiresAt    time.Time  `json:"expires_at"`
	CreatedAt    time.Time  `json:"created_at"`
	CompletedAt  *time.Time `json:"completed_at"`
	TestSignInResult
}

// TestSignInResult is what a test found: why it failed, if it did, and what
// the IdP asserted once its answer validated.
type TestSignInResult struct {
	ErrorCode           string          `json:"error_code,omitempty"`
	ErrorMessage        string          `json:"error_message,omitempty"`
	ErrorDetail         string          `json:"error_detail,omitempty"`
	NameID              string          `json:"name_id,omitempty"`
	NameIDFormat        string          `json:"name_id_format,omitempty"`
	Email               string          `json:"email,omitempty"`
	Name                string          `json:"name,omitempty"`
	Attributes          []TestAttribute `json:"attributes,omitempty"`
	EmailDomainVerified bool            `json:"email_domain_verified"`
}

// TestAttribute is an attribute the IdP asserted, with its values.
type TestAttribute struct {
	Name         string   `json:"name"`
	FriendlyName string   `json:"friendly_name,omitempty"`
	Values       []string `json:"values"`
}

// BeginTestSignIn starts a test of tenantID's connection id in this browser,
// on tx, and returns it with the IdP address to send the browser to. The IdP's
// answer returns the browser to returnURL, the test's and the connection's IDs
// in its fragment. A draft connection can be tested: the test signs nobody in.
func (h *Handler) BeginTestSignIn(w http.ResponseWriter, r *http.Request, tx pgx.Tx, tenantID, id uuid.UUID, returnURL string) (*TestSignIn, error) {
	ctx := r.Context()
	row, err := h.Service.q.WithTx(tx).GetSamlConnection(ctx, dbgen.GetSamlConnectionParams{ID: id, TenantID: tenantID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	conn := toConnection(row)
	if !validIdPSSOURL(conn.IdpSSOURL) {
		return nil, errs.ErrSAMLSSOURLInvalid
	}
	// The request carries no certificate; the answer is checked against them.
	sp := h.Service.buildSP(h.publicBase(r), conn, nil)
	doc, err := sp.BuildAuthRequestDocument()
	if err != nil {
		return nil, err
	}
	if doc.Root() == nil {
		return nil, errs.ErrInternalServer
	}
	requestID := doc.Root().SelectAttrValue("ID", "")
	if strings.TrimSpace(requestID) == "" || len(requestID) > 1024 {
		return nil, errs.ErrSAMLRequestInvalid
	}
	authURL, err := sp.BuildAuthURLFromDocument("", doc)
	if err != nil {
		return nil, err
	}
	t := &TestSignIn{ConnectionID: conn.ID, Status: testPending, RedirectURL: authURL}
	if err := tx.QueryRow(ctx, `
		INSERT INTO auth.saml_test_sign_ins (connection_id, request_id, return_url, expires_at)
		VALUES ($1, $2, $3, $4)
		RETURNING id, expires_at, created_at
	`, conn.ID, requestID, returnURL, time.Now().UTC().Add(authnRequestTTL)).Scan(&t.ID, &t.ExpiresAt, &t.CreatedAt); err != nil {
		return nil, err
	}
	h.binding().Add(w, r, requestID)
	return t, nil
}

// TestSignIn returns test id of tenantID's connection connectionID.
func (s *Service) TestSignIn(ctx context.Context, id, connectionID, tenantID uuid.UUID) (*TestSignIn, error) {
	t := &TestSignIn{}
	var result []byte
	err := s.pool.QueryRow(ctx, `
		SELECT t.id, t.connection_id, t.status, t.result, t.expires_at, t.created_at, t.completed_at
		FROM auth.saml_test_sign_ins t
		JOIN tenant.saml_connections c ON c.id = t.connection_id
		WHERE t.id = $1 AND t.connection_id = $2 AND c.tenant_id = $3
	`, id, connectionID, tenantID).Scan(&t.ID, &t.ConnectionID, &t.Status, &result, &t.ExpiresAt, &t.CreatedAt, &t.CompletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrSAMLTestSignInNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(result) > 0 {
		if err := json.Unmarshal(result, &t.TestSignInResult); err != nil {
			return nil, err
		}
	}
	if t.Status == testPending && time.Now().After(t.ExpiresAt) {
		t.Status = testExpired
	}
	return t, nil
}

// PurgeTestSignIns deletes the test sign-ins begun more than retention ago,
// with what the IdP sent them, and returns how many it deleted.
func PurgeTestSignIns(ctx context.Context, pool *pgxpool.Pool, retention time.Duration) (int64, error) {
	return postgres.PurgeInBatches(ctx, pool, `DELETE FROM auth.saml_test_sign_ins WHERE ctid = ANY(ARRAY(
		SELECT s.ctid FROM auth.saml_test_sign_ins s WHERE s.created_at < $1 LIMIT $2))`,
		time.Now().Add(-retention))
}

// answeredTest is a test sign-in as the ACS finds it, by its AuthnRequest.
type answeredTest struct {
	id        uuid.UUID
	requestID string
	returnURL string
}

// answerTestSignIn handles a post to conn's ACS that answers a test sign-in,
// and reports whether it did. Only the browser that began the test completes
// it; its answer is validated as a sign-in's is and recorded, and the browser
// returns to where the test began.
func (h *Handler) answerTestSignIn(w http.ResponseWriter, r *http.Request, conn *Connection) bool {
	if err := httpx.ParseForm(r, httpx.MaxSAMLBodyBytes); err != nil {
		httpx.WriteError(w, r, err)
		return true
	}
	encoded := r.PostFormValue("SAMLResponse")
	if encoded == "" {
		return false
	}
	// Unverified, as it only picks the path: the answer is validated below,
	// and the sign-in path knows no test's AuthnRequest, so can't accept it.
	unverified, err := saml2.DecodeUnverifiedBaseResponse(encoded)
	if err != nil || unverified.InResponseTo == "" {
		return false
	}
	ctx := r.Context()
	test := &answeredTest{requestID: unverified.InResponseTo}
	err = h.Service.pool.QueryRow(ctx, `
		SELECT id, return_url FROM auth.saml_test_sign_ins
		WHERE connection_id = $1 AND request_id = $2
	`, conn.ID, test.requestID).Scan(&test.id, &test.returnURL)
	if errors.Is(err, pgx.ErrNoRows) {
		return false
	}
	if err != nil {
		httpx.WriteError(w, r, err)
		return true
	}
	if !h.binding().Holds(r, test.requestID) {
		httpx.WriteError(w, r, errs.ErrSAMLOtherBrowser)
		return true
	}
	h.binding().Remove(w, r, test.requestID)
	status, result, err := h.Service.checkTestAnswer(ctx, h.publicBase(r), conn, test.requestID, encoded)
	if err != nil {
		httpx.WriteError(w, r, err)
		return true
	}
	if err := h.Service.finishTestSignIn(ctx, test.id, status, result); err != nil {
		httpx.WriteError(w, r, err)
		return true
	}
	// #nosec G710 -- returnURL is the one BeginTestSignIn stored: the admin portal's own page, from server config
	http.Redirect(w, r, test.returnURL+"#saml_test="+test.id.String()+"&saml_connection="+conn.ID.String(), http.StatusFound)
	return true
}

// checkTestAnswer validates the answer to test requestID as the ACS validates
// a sign-in's, and returns the test's status and findings. It finds and
// creates no account, reporting only whether the asserted address is on a
// domain the organisation verified. err is a fault, never a finding.
func (s *Service) checkTestAnswer(ctx context.Context, base string, conn *Connection, requestID, encoded string) (string, TestSignInResult, error) {
	var res TestSignInResult
	fail := func(e *errs.Error, cause error) (string, TestSignInResult, error) {
		res.ErrorCode, res.ErrorMessage = e.Code, e.Message
		if cause != nil {
			res.ErrorDetail = clip(cause.Error(), maxTestDetailBytes)
		}
		return testFailed, res, nil
	}
	certs, err := s.signingCertificates(ctx, conn)
	if err != nil {
		return "", res, err
	}
	if len(certs) == 0 {
		return fail(errs.ErrSAMLCertificateInvalid, nil)
	}
	// An unencrypted answer doesn't need the key; an encrypted one then fails.
	key, err := s.decryptionKey(ctx, conn)
	if err != nil {
		slog.Error("saml test sign-in: SP encryption key unusable", "err", err, "connection", conn.ID)
	}
	now := time.Now()
	response, info, err := s.validateResponse(base, conn, certs, key, encoded, now)
	if info != nil {
		res.NameID, res.NameIDFormat, res.Attributes = info.NameID, info.NameIDFormat, testAttributes(info.Values)
	}
	if e := errs.As(err); e != nil {
		return fail(e, e.Unwrap())
	}
	if err != nil {
		return "", res, err
	}
	trusted, assertionIDs, err := trustedCorrelation(response)
	if e := errs.As(err); e != nil {
		return fail(e, nil)
	}
	if trusted != requestID {
		return fail(errs.ErrSAMLRequestCorrelation, nil)
	}
	// Reserving its IDs keeps the answer from being presented again anywhere.
	// The test is its own correlation, so no AuthnRequest is consumed.
	if _, err := s.ConsumeValidatedResponse(ctx, conn.ID, "", response.ID, assertionIDs, replayKeepUntil(response.Assertions, now), true); err != nil {
		if e := errs.As(err); e != nil && e.Code != errs.CodeInternal {
			return fail(e, nil)
		}
		return "", res, err
	}

	// The address and name as the ACS takes them.
	email := info.NameID
	if conn.EmailAttribute != "" {
		if v := info.Values.Get(conn.EmailAttribute); v != "" {
			email = v
		}
	}
	res.Email = strings.ToLower(strings.TrimSpace(email))
	if conn.NameAttribute != "" {
		res.Name = info.Values.Get(conn.NameAttribute)
	}
	if res.Email == "" {
		return fail(errs.ErrSAMLAssertionNoEmail, nil)
	}
	manager, managed, err := domainverify.ManagerOf(postgres.AcrossTenants(ctx), s.pool, res.Email)
	if err != nil {
		return "", res, err
	}
	res.EmailDomainVerified = managed && manager == conn.TenantID
	if !res.EmailDomainVerified {
		return fail(errs.ErrSAMLEmailDomainUnverified, nil)
	}
	return testSucceeded, res, nil
}

// finishTestSignIn records test id's outcome, once, while it still waits.
func (s *Service) finishTestSignIn(ctx context.Context, id uuid.UUID, status string, res TestSignInResult) error {
	raw, err := json.Marshal(res)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE auth.saml_test_sign_ins SET status = $2, result = $3, completed_at = NOW()
		WHERE id = $1 AND status = 'pending' AND expires_at > NOW()
	`, id, status, raw)
	return err
}

// testAttributes lists the asserted attributes by name, within a report's
// bounds.
func testAttributes(values saml2.Values) []TestAttribute {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	slices.Sort(names)
	if len(names) > maxTestAttributes {
		names = names[:maxTestAttributes]
	}
	out := make([]TestAttribute, 0, len(names))
	for _, name := range names {
		all := append([]string{}, values.GetAll(name)...)
		if len(all) > maxTestValues {
			all = all[:maxTestValues]
		}
		for i := range all {
			all[i] = clip(all[i], maxTestValueBytes)
		}
		out = append(out, TestAttribute{
			Name:         clip(name, maxTestValueBytes),
			FriendlyName: clip(values[name].FriendlyName, maxTestValueBytes),
			Values:       all,
		})
	}
	return out
}

// clip shortens s to at most n bytes of valid UTF-8.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

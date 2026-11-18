package saml

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"html"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
)

// activeOrganization reports whether organizationID names an active, undeleted organization.
func (i *IdP) activeOrganization(ctx context.Context, organizationID uuid.UUID) (bool, error) {
	return i.q.IsOrganizationActive(ctx, organizationID)
}

// loadUser returns the account an assertion about userID describes, with its
// home organization, or ErrAuthAccountInactive for an account that isn't active.
func (i *IdP) loadUser(ctx context.Context, userID uuid.UUID) (*person, error) {
	row, err := i.q.GetUserForIdP(ctx, userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errs.ErrAuthAccountInactive
	}
	if err != nil {
		return nil, err
	}
	// A suspended account gets no assertion, whatever its open sign-in session.
	if row.Status != "active" {
		return nil, errs.ErrAuthAccountInactive
	}
	p := &person{id: userID, email: row.Email, metadata: decodeMetadata(row.Metadata)}
	if row.DisplayName != nil {
		p.displayName = *row.DisplayName
	}
	if row.OrganizationID != nil {
		p.organizationID = *row.OrganizationID
	}
	return p, nil
}

// signedIn is the person userID, signed in to the IdP, as the actor of its
// audit events about r.
func signedIn(r *http.Request, userID uuid.UUID) audit.Actor {
	return audit.Actor{UserID: &userID, Type: "user", IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r)}
}

// recordIssued stamps sp's last sign-in and audits the assertion it was sent
// about actor.
func (i *IdP) recordIssued(ctx context.Context, actor audit.Actor, sp *ServiceProvider) error {
	tx, err := i.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := i.q.WithTx(tx).TouchSamlSPLastLogin(ctx, sp.ID); err != nil {
		return err
	}
	if err := audit.Record(ctx, tx, actor.Event(sp.OrganizationID, "saml.idp_assertion_issued", "saml_service_provider", sp.ID,
		map[string]any{"sp_entity_id": sp.EntityID})); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// recordRefused audits that the IdP refused actor an assertion for sp, and why.
func (i *IdP) recordRefused(ctx context.Context, actor audit.Actor, sp *ServiceProvider, reason string) error {
	return audit.RecordAlone(ctx, i.pool, actor.Event(sp.OrganizationID, "saml.idp_assertion_refused", "saml_service_provider", sp.ID,
		map[string]any{"sp_entity_id": sp.EntityID, "reason": reason}))
}

// ssoReturnURL is where the hosted login sends the browser once the person has
// signed in: this endpoint, by GET. A POST's parameters move into the query,
// its SAMLRequest re-encoded for the Redirect binding that the GET decodes.
func ssoReturnURL(base string, r *http.Request) (string, error) {
	if r.Method != http.MethodPost {
		return base + r.URL.RequestURI(), nil
	}
	q := url.Values{}
	if samlReq := r.FormValue("SAMLRequest"); samlReq != "" {
		enc, err := redirectEncoded(samlReq)
		if err != nil {
			return "", err
		}
		q.Set("SAMLRequest", enc)
	} else if spKey := strings.TrimSpace(r.FormValue("sp")); spKey != "" {
		q.Set("sp", spKey)
	}
	if relayState := r.FormValue("RelayState"); relayState != "" {
		q.Set("RelayState", relayState)
	}
	return base + r.URL.EscapedPath() + "?" + q.Encode(), nil
}

// autoSubmit posts the page's form to the service provider once it loads.
const autoSubmit = `document.forms[0].submit()`

// postFormCSP is the API's script-free policy, letting exactly autoSubmit run.
var postFormCSP = func() string {
	sum := sha256.Sum256([]byte(autoSubmit))
	return "default-src 'none'; script-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'; frame-ancestors 'none'"
}()

// writePostForm answers with the HTTP-POST binding page: a form carrying the
// signed response to acs, submitted by autoSubmit or, without script, a button.
func writePostForm(w http.ResponseWriter, acs, samlResponse, relayState string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", postFormCSP)
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Signing in…</title></head><body>`)
	b.WriteString(`<form method="POST" action="` + html.EscapeString(acs) + `">`)
	b.WriteString(`<input type="hidden" name="SAMLResponse" value="` + html.EscapeString(samlResponse) + `"/>`)
	if relayState != "" {
		b.WriteString(`<input type="hidden" name="RelayState" value="` + html.EscapeString(relayState) + `"/>`)
	}
	b.WriteString(`<noscript><button type="submit">Continue</button></noscript></form>`)
	b.WriteString(`<script>` + autoSubmit + `</script></body></html>`)
	_, _ = w.Write([]byte(b.String()))
}

// errorPageCSP lets the SSO error page show its text and nothing else.
const errorPageCSP = "default-src 'none'; frame-ancestors 'none'"

// writeSSOError answers the SSO endpoint's browser, which asks for HTML, with a
// page saying why it can't sign in and the error's code; anything else, or an
// error outside the catalogue, gets the JSON error.
func writeSSOError(w http.ResponseWriter, r *http.Request, err error) {
	e := errs.As(err)
	if e == nil || !strings.Contains(r.Header.Get("Accept"), "text/html") {
		httpx.WriteError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", errorPageCSP)
	w.WriteHeader(httpx.StatusForCode(e.Code))
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Can't sign you in</title></head><body>`)
	b.WriteString(`<h1>Can't sign you in</h1><p>` + html.EscapeString(e.Message) + `</p>`)
	b.WriteString(`<p>Error code: <code>` + html.EscapeString(e.Code) + `</code>`)
	if id := httpx.RequestID(r); id != "" {
		b.WriteString(` · Request ID: <code>` + html.EscapeString(id) + `</code>`)
	}
	b.WriteString(`</p></body></html>`)
	_, _ = w.Write([]byte(b.String())) // #nosec G705 -- every value on the page is HTML-escaped
}

// loginAfterParam marks an SSO request sent back from the sign-in it asked
// for: a session signed in at or after the time it names (Unix seconds) was
// signed in for this request. It decides only whether to refuse rather than
// ask again, so it needn't be signed.
const loginAfterParam = "login_after"

// meetsSignInRules applies sp's organization's sign-in rules to the hosted-login session, as OIDC
// authorize does: an address its rules refuse is refused and recorded, and a required second factor
// the session didn't meet sends the browser to sign in again, once (a fresh sign-in still short of it
// is refused). It reports whether to go on, having answered if not.
func (h *Handler) meetsSignInRules(w http.ResponseWriter, r *http.Request, sp *ServiceProvider, userID uuid.UUID) bool {
	ctx := r.Context()
	if err := h.IdP.addresses.CheckSignIn(ctx, sp.OrganizationID, userID, httpx.ClientIP(r), "saml_idp"); err != nil {
		writeSSOError(w, r, err)
		return false
	}
	c, err := r.Cookie(authentication.LoginSessionCookie)
	if err != nil {
		writeSSOError(w, r, errs.ErrUnauthorized)
		return false
	}
	sessionID, sessionUser, signedInAt, err := h.IdP.factors.ResolveLoginSessionAt(ctx, c.Value)
	if err == nil && sessionUser != userID {
		err = errs.ErrUnauthorized
	}
	if err == nil {
		err = h.IdP.factors.LoginSessionFactorShortfall(ctx, sessionID, userID, sp.OrganizationID)
	}
	switch {
	case err == nil:
		return true
	case !errors.Is(err, errs.ErrStepUpRequired) && !errors.Is(err, errs.ErrMFAEnrollmentRequired):
		writeSSOError(w, r, err)
	case signedInForRequest(r, signedInAt):
		h.refuse(w, r, sp, userID, err, "second_factor_required")
	default:
		ret, err := ssoReturnURL(h.publicBase(r), r)
		if err != nil {
			writeSSOError(w, r, ErrAuthnRequestInvalid)
			return false
		}
		ret += "&" + loginAfterParam + "=" + strconv.FormatInt(time.Now().Unix(), 10)
		http.Redirect(w, r, h.IdP.loginBaseURL+"/sign-in?prompt=login&return_to="+url.QueryEscape(ret), http.StatusFound)
	}
	return false
}

// signedInForRequest reports whether a sign-in at signedInAt was made for r:
// r came back from the sign-in it asked for, and the sign-in is no older.
func signedInForRequest(r *http.Request, signedInAt time.Time) bool {
	la, err := strconv.ParseInt(r.FormValue(loginAfterParam), 10, 64)
	return err == nil && !signedInAt.Before(time.Unix(la, 0))
}

// refuse answers a signed-in person sp won't sign in with err, and audits the
// refusal with reason.
func (h *Handler) refuse(w http.ResponseWriter, r *http.Request, sp *ServiceProvider, userID uuid.UUID, err error, reason string) {
	if auditErr := h.IdP.recordRefused(r.Context(), signedIn(r, userID), sp, reason); auditErr != nil {
		slog.Warn("saml idp sso: record refused assertion", "err", auditErr, "sp", sp.ID)
	}
	writeSSOError(w, r, err)
}

func (h *Handler) idpSessionUser(r *http.Request) (uuid.UUID, bool) {
	c, err := r.Cookie(authentication.LoginSessionCookie)
	if err != nil {
		return uuid.Nil, false
	}
	uid, err := h.IdP.sessions.ResolveLoginSession(r.Context(), c.Value)
	if err != nil {
		return uuid.Nil, false
	}
	return uid, true
}

// idpOrganization returns the path's organization for the IdP endpoints. A malformed,
// unknown or inactive one is ErrNotFound, the same answer as an unknown SP.
func (h *Handler) idpOrganization(r *http.Request) (uuid.UUID, error) {
	organizationID, err := httpx.PathUUID(r, "organizationID", errs.ErrNotFound)
	if err != nil {
		return uuid.Nil, err
	}
	active, err := h.IdP.activeOrganization(r.Context(), organizationID)
	if err != nil {
		return uuid.Nil, err
	}
	if !active {
		return uuid.Nil, errs.ErrNotFound
	}
	return organizationID, nil
}

// idpSSO is the organization's SingleSignOnService: SP-initiated (a SAMLRequest by HTTP-Redirect or
// HTTP-POST) and IdP-initiated (?sp=<id|entityID>) SSO, for the path organization's SPs only. Without a
// hosted-login SSO cookie the browser goes to the hosted login and back. An SP limited to assigned
// people refuses, and audits refusing, anyone else.
func (h *Handler) idpSSO(w http.ResponseWriter, r *http.Request) {
	if h.IdP == nil {
		writeSSOError(w, r, ErrIdPNotConfigured)
		return
	}
	organizationID, err := h.idpOrganization(r)
	if err != nil {
		writeSSOError(w, r, err)
		return
	}
	if err := httpx.ParseForm(r, httpx.MaxSAMLBodyBytes); err != nil {
		writeSSOError(w, r, err)
		return
	}
	relayState := r.FormValue("RelayState")
	req, err := h.readSSORequest(r, organizationID)
	if err != nil {
		writeSSOError(w, r, err)
		return
	}
	sp := req.sp
	// A draft app is still being set up: it signs no one in, and an attempt by
	// someone signed in is audited.
	if sp.Status == "draft" {
		if userID, ok := h.idpSessionUser(r); ok {
			h.refuse(w, r, sp, userID, ErrServiceProviderDraft, "draft")
		} else {
			writeSSOError(w, r, ErrServiceProviderDraft)
		}
		return
	}
	// The plan is checked at every sign-in, not only when the service provider
	// was registered, so one set up on a plan that has since lapsed stops.
	if err := h.IdP.requireSSO(r.Context(), sp.OrganizationID); err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// A supplied ACS URL must match the registered one (prevents redirecting a
	// signed assertion to an attacker-chosen endpoint).
	if req.acsOverride != "" && req.acsOverride != sp.ACSURL {
		writeSSOError(w, r, ErrACSMismatch)
		return
	}

	base := h.publicBase(r)
	userID, ok := h.idpSessionUser(r)
	if !ok {
		ret, err := ssoReturnURL(base, r)
		if err != nil {
			writeSSOError(w, r, ErrAuthnRequestInvalid)
			return
		}
		http.Redirect(w, r, h.IdP.loginBaseURL+"/sign-in?return_to="+url.QueryEscape(ret), http.StatusFound)
		return
	}
	subj, ok := h.ssoSubject(w, r, sp, userID)
	if !ok {
		return
	}

	respXML, err := h.IdP.buildSignedResponse(idpEntityID(base, organizationID), sp, sp.ACSURL, subj, req.inResponseTo)
	if err != nil {
		slog.Error("saml idp sso: build assertion", "err", err, "sp", sp.ID)
		writeSSOError(w, r, errs.ErrInternalServer)
		return
	}
	if err := h.IdP.recordIssued(r.Context(), signedIn(r, userID), sp); err != nil {
		// Audit/bookkeeping failure shouldn't block the user's SSO — log only.
		slog.Warn("saml idp sso: record issued assertion", "err", err, "sp", sp.ID)
	}
	writePostForm(w, sp.ACSURL, base64.StdEncoding.EncodeToString(respXML), relayState)
}

// ssoRequest is a sign-in request to the IdP: the service provider it names,
// the ID of the AuthnRequest an assertion answers ("" when the IdP starts the
// sign-in), and the ACS the request asks for ("" for the registered one).
type ssoRequest struct {
	sp           *ServiceProvider
	inResponseTo string
	acsOverride  string
}

// readSSORequest reads the sign-in request of r to organizationID's IdP: an
// AuthnRequest, or for a sign-in the IdP starts the service provider in sp.
// It refuses an unknown or disabled service provider, and a request one that
// signs its requests didn't sign: only what its signature covers is read.
func (h *Handler) readSSORequest(r *http.Request, organizationID uuid.UUID) (ssoRequest, error) {
	var (
		req        ssoRequest
		lookupErr  error
		requestXML []byte
	)
	if samlReq := r.FormValue("SAMLRequest"); samlReq != "" {
		raw, err := authnRequestXML(samlReq, r.Method)
		var ar authnRequest
		if err == nil {
			err = xml.Unmarshal(raw, &ar) // #nosec G709 -- decodes into a typed struct
		}
		if err != nil {
			return req, ErrAuthnRequestInvalid
		}
		requestXML = raw
		req.inResponseTo = ar.ID
		req.acsOverride = strings.TrimSpace(ar.AssertionConsumerServiceURL)
		req.sp, lookupErr = h.IdP.lookupSPByEntityID(r.Context(), organizationID, strings.TrimSpace(ar.Issuer))
	} else if spKey := strings.TrimSpace(r.FormValue("sp")); spKey != "" {
		req.sp, lookupErr = h.IdP.lookupSP(r.Context(), organizationID, spKey)
	} else {
		return req, ErrRequestParamMissing
	}
	if lookupErr != nil || req.sp == nil {
		// lookupErr is errs.ErrNotFound (no rows) or a real DB error → 404/500.
		if lookupErr == nil {
			return req, errs.ErrNotFound
		}
		return req, lookupErr
	}
	if req.sp.Status == "disabled" {
		return req, ErrServiceProviderDisabled
	}
	// An app that signs its requests has them checked before anything else, and
	// only what its signature covers is read. Sign-in the IdP starts has no
	// request to sign.
	if req.sp.RequireSignedRequests && requestXML != nil {
		ar, err := verifiedAuthnRequest(r, requestXML, req.sp.Certificate)
		if err == nil && strings.TrimSpace(ar.Issuer) != req.sp.EntityID {
			err = ErrRequestSignatureInvalid
		}
		if err != nil {
			return req, err
		}
		req.inResponseTo = ar.ID
		req.acsOverride = strings.TrimSpace(ar.AssertionConsumerServiceURL)
	}
	return req, nil
}

// ssoSubject returns what an assertion to sp says about the signed-in
// person userID, who must be active, of sp's organization, assigned to sp when
// it asks, and within the organization's sign-in rules; ok is false once it
// answered the request itself, a refusal of someone signed in audited.
func (h *Handler) ssoSubject(w http.ResponseWriter, r *http.Request, sp *ServiceProvider, userID uuid.UUID) (assertionSubject, bool) {
	ctx := r.Context()
	who, err := h.IdP.loadUser(ctx, userID)
	if errors.Is(err, errs.ErrAuthAccountInactive) {
		writeSSOError(w, r, err)
		return assertionSubject{}, false
	}
	if err != nil {
		slog.Error("saml idp sso: user lookup", "err", err, "user", userID)
		writeSSOError(w, r, errs.ErrInternalServer)
		return assertionSubject{}, false
	}
	if who.organizationID != sp.OrganizationID {
		writeSSOError(w, r, ErrUserOrganizationMismatch)
		return assertionSubject{}, false
	}
	if sp.AssignmentRequired {
		assigned, err := h.IdP.assigned(ctx, sp, userID)
		if err != nil {
			slog.Error("saml idp sso: assignment lookup", "err", err, "sp", sp.ID)
			writeSSOError(w, r, errs.ErrInternalServer)
			return assertionSubject{}, false
		}
		if !assigned {
			h.refuse(w, r, sp, userID, ErrSPNotAssigned, "not_assigned")
			return assertionSubject{}, false
		}
	}
	if !h.meetsSignInRules(w, r, sp, userID) {
		return assertionSubject{}, false
	}
	subj, err := h.IdP.subjectFor(ctx, sp, who)
	if errors.Is(err, ErrNameIDUnavailable) {
		h.refuse(w, r, sp, userID, err, "name_id_unavailable")
		return assertionSubject{}, false
	}
	if err != nil {
		slog.Error("saml idp sso: assertion subject", "err", err, "sp", sp.ID)
		writeSSOError(w, r, errs.ErrInternalServer)
		return assertionSubject{}, false
	}
	return subj, true
}

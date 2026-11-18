package saml

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	saml2 "github.com/russellhaering/gosaml2"
	samltypes "github.com/russellhaering/gosaml2/types"

	"github.com/qeetgroup/qeet-id-server/internal/federation/logincode"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/errs"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/httpx"
	"github.com/qeetgroup/qeet-id-server/internal/platform/http/returnto"
)

func (h *Handler) acs(w http.ResponseWriter, r *http.Request) {
	id, err := httpx.PathUUID(r, "id", ErrIDInvalid)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	conn, err := h.Service.getByID(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	// The answer to a test sign-in is reported, and signs nobody in.
	if h.answerTestSignIn(w, r, conn) {
		return
	}
	// From here a failure of a sign-in the hosted login began goes back to its sign-in page.
	hostedReturnTo := ""
	fail := func(err error) { h.acsFailed(w, r, conn.ID, hostedReturnTo, err) }
	reply, err := h.validatedAnswer(r, conn)
	if err != nil {
		fail(err)
		return
	}
	returnTo, bound, err := h.consumeAnswer(w, r, conn, reply)
	if err != nil {
		fail(err)
		return
	}
	if bound {
		hostedReturnTo = returnTo
	}
	ctx := r.Context()
	userID, err := h.answeredAccount(ctx, r, conn, reply)
	if err != nil {
		fail(err)
		return
	}
	rawCode, err := logincode.Issue(ctx, h.Service.pool, logincode.Code{
		Kind: logincode.KindSAML, UserID: userID, OrganizationID: conn.OrganizationID, ConnectionID: conn.ID,
	}, loginCodeTTL)
	if err != nil {
		slog.Error("saml acs: persist login code", "err", err)
		fail(errs.ErrInternalServer)
		return
	}
	h.Service.touchLastLogin(ctx, conn.ID)

	// Hand the page the one-time code in the URL fragment (never sent to a
	// server / proxy log). A console sign-in trades it at /saml/exchange; one
	// the hosted login started goes back to its sign-in page, which trades it at
	// /saml/session and continues to return_to.
	target := h.Service.appBaseURL + "/sso/callback#saml_code=" + rawCode
	if returnTo != "" && h.Service.loginBaseURL != "" {
		target = h.Service.loginBaseURL + "/sign-in?" + url.Values{"return_to": {returnTo}}.Encode() + "#saml_code=" + rawCode
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// acsAnswer is an IdP's answer the ACS validated: its response, what its
// assertion says, the address it asserts and when it was checked.
type acsAnswer struct {
	response *samltypes.Response
	info     *saml2.AssertionInfo
	email    string
	now      time.Time
}

// validatedAnswer reads the SAMLResponse posted to conn's ACS and validates
// it against the IdP's certificates, while conn signs people in and the plan
// includes SSO, and returns it with the address it asserts.
func (h *Handler) validatedAnswer(r *http.Request, conn *Connection) (acsAnswer, error) {
	var a acsAnswer
	if err := signInStatus(conn.Status); err != nil {
		return a, err
	}
	// The plan is checked when the assertion arrives too, so a connection set
	// up on a plan that has since lapsed signs no one in.
	if err := h.Service.RequireSSO(r.Context(), conn.OrganizationID); err != nil {
		return a, err
	}
	if err := httpx.ParseForm(r, httpx.MaxSAMLBodyBytes); err != nil {
		return a, err
	}
	encoded := r.PostFormValue("SAMLResponse")
	if encoded == "" {
		return a, ErrResponseMissing
	}
	certs, err := h.Service.signingCertificates(r.Context(), conn)
	if err != nil {
		return a, err
	}
	if len(certs) == 0 {
		slog.Error("saml acs: no readable IdP certificate", "connection", conn.ID)
		return a, ErrConnectionMisconfigured
	}
	key, err := h.Service.decryptionKey(r.Context(), conn)
	if err != nil {
		// An unencrypted assertion doesn't need the key; an encrypted one fails.
		slog.Error("saml acs: SP encryption key unusable", "err", err, "connection", conn.ID)
	}
	a.now = time.Now()
	a.response, a.info, err = h.Service.validateResponse(h.publicBase(r), conn, certs, key, encoded, a.now)
	if err != nil {
		return a, err
	}

	email := a.info.NameID
	if conn.EmailAttribute != "" {
		if v := a.info.Values.Get(conn.EmailAttribute); v != "" {
			email = v
		}
	}
	a.email = strings.ToLower(strings.TrimSpace(email))
	if a.email == "" {
		return a, ErrAssertionNoEmail
	}
	return a, nil
}

// consumeAnswer reserves the answer's IDs against replay and spends the request it answers, returning
// where the hosted login asked to go back to. An answer completes only in the browser that sent the
// request, and spends it either way (bound reports that it did); an IdP-initiated answer has no request
// to bind, so it is opt-in.
func (h *Handler) consumeAnswer(w http.ResponseWriter, r *http.Request, conn *Connection, a acsAnswer) (returnTo string, bound bool, err error) {
	requestID, assertionIDs, err := trustedCorrelation(a.response)
	if err != nil {
		return "", false, err
	}
	allowIdPInitiated, err := h.Service.AllowsIdPInitiated(r.Context(), conn.ID)
	if err != nil {
		return "", false, err
	}
	returnTo, err = h.Service.ConsumeValidatedResponse(r.Context(), conn.ID, requestID, a.response.ID, assertionIDs, replayKeepUntil(a.response.Assertions, a.now), allowIdPInitiated)
	if err != nil {
		return "", false, err
	}
	if requestID == "" {
		return returnTo, false, nil
	}
	if !h.binding().Holds(r, requestID) {
		return "", false, ErrOtherBrowser
	}
	h.binding().Remove(w, r, requestID)
	return returnTo, true, nil
}

// answeredAccount returns the account the answer signs in through conn,
// found, adopted or provisioned, which must still be allowed to sign in: a
// suspended or deleted account gets no code to sign in with.
func (h *Handler) answeredAccount(ctx context.Context, r *http.Request, conn *Connection, a acsAnswer) (uuid.UUID, error) {
	groupsAttribute, err := h.Service.groupsAttribute(ctx, conn)
	if err != nil {
		slog.Error("saml acs: read the groups attribute", "err", err, "connection", conn.ID)
		return uuid.Nil, errs.ErrInternalServer
	}
	groups, withheld := assertedGroups(a.info.Values, groupsAttribute)
	userID, err := h.Service.findOrCreateUser(ctx, conn.OrganizationID, conn.ID, assertion{
		subject: a.info.NameID, email: a.email, name: assertedName(a.info.Values, conn.NameAttribute),
		groups: groups, groupsWithheld: withheld,
	}, audit.Actor{Type: provider, IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r)})
	if e := errs.As(err); e != nil && e.Code != errs.CodeInternal {
		return uuid.Nil, err
	}
	if err != nil {
		slog.Error("saml acs: provisioning failed", "err", err, "connection", conn.ID)
		return uuid.Nil, errs.ErrInternalServer
	}
	if err := h.Service.auth.CheckSignInAccount(ctx, userID, conn.OrganizationID, provider, httpx.ClientIP(r), r.UserAgent()); err != nil {
		return uuid.Nil, err
	}
	return userID, nil
}

// acsFailed answers a sign-in that failed after its connection was found. One the hosted login began
// goes back to its sign-in page (returnto.Failed) with the stored return_to: returnTo once bound to this
// browser, else that of its latest pending request on the connection, named by its binding cookie,
// which scripts and other sites can't set. Any other sign-in gets the error itself.
func (h *Handler) acsFailed(w http.ResponseWriter, r *http.Request, connectionID uuid.UUID, returnTo string, err error) {
	if h.Service.loginBaseURL != "" && returnTo == "" {
		returnTo = h.Service.hostedReturn(r.Context(), connectionID, h.binding().Held(r))
	}
	if h.Service.loginBaseURL == "" || returnTo == "" {
		httpx.WriteError(w, r, err)
		return
	}
	slog.Warn("saml acs: sign-in failed", "err", err, "connection", connectionID)
	http.Redirect(w, r, returnto.Failed(h.Service.loginBaseURL, returnTo, err), http.StatusFound) // #nosec G710 -- always the configured hosted sign-in page; return_to is only a query value
}

func trustedCorrelation(response *samltypes.Response) (string, []string, error) {
	requestID := ""
	if response.SignatureValidated {
		requestID = response.InResponseTo
	}
	assertionIDs := make([]string, 0, len(response.Assertions))
	for _, assertion := range response.Assertions {
		assertionIDs = append(assertionIDs, assertion.ID)
		if assertion.Subject == nil || assertion.Subject.SubjectConfirmation == nil ||
			assertion.Subject.SubjectConfirmation.SubjectConfirmationData == nil {
			continue
		}
		candidate := assertion.Subject.SubjectConfirmation.SubjectConfirmationData.InResponseTo
		if candidate == "" || (!response.SignatureValidated && !assertion.SignatureValidated) {
			continue
		}
		if requestID == "" {
			requestID = candidate
		} else if requestID != candidate {
			return "", nil, ErrRequestCorrelation
		}
	}
	return requestID, assertionIDs, nil
}

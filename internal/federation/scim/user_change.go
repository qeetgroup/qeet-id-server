package scim

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/qeetgroup/qeet-id-server/internal/access/authentication"
	"github.com/qeetgroup/qeet-id-server/internal/federation/identitylink"
	"github.com/qeetgroup/qeet-id-server/internal/federation/scim/dbgen"
	"github.com/qeetgroup/qeet-id-server/internal/identity/domainverify"
	"github.com/qeetgroup/qeet-id-server/internal/identity/user"
	"github.com/qeetgroup/qeet-id-server/internal/platform/audit"
	"github.com/qeetgroup/qeet-id-server/internal/platform/database/postgres"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/outbox"
	"github.com/qeetgroup/qeet-id-server/internal/platform/events/sessionsignal"
)

type patchBody struct {
	Schemas    []string `json:"schemas"`
	Operations []struct {
		Op    string          `json:"op"`
		Path  string          `json:"path"`
		Value json.RawMessage `json:"value"`
	} `json:"Operations"`
}

// patchUser supports the deprovisioning flow IdPs lean on: replacing the
// `active` attribute (path-scoped or via a value object) and displayName.
func (h *Handler) patchUser(w http.ResponseWriter, r *http.Request) {
	tid, id, ok := h.scimTarget(w, r)
	if !ok {
		return
	}
	var body patchBody
	if !decodeSCIMBody(w, r, &body) {
		return
	}
	profile, err := h.Service.profile(r.Context(), tid, patchProfileSource(body), true)
	if err != nil {
		writeSCIMTypedErr(w, http.StatusBadRequest, "invalidValue", "Directory mapping validation failed")
		return
	}
	c := parseUserPatch(body)
	c.profile = profile
	if !h.applyUserChange(w, r, tid, id, c, "user.updated") {
		return
	}
	row, err := h.Service.getProvisioned(r.Context(), tid, id)
	if err != nil {
		writeSCIMErr(w, http.StatusNotFound, "user not found")
		return
	}
	writeSCIM(w, http.StatusOK, h.toResource(r, row))
}

// parseUserPatch resolves a PatchOp body into a userChange: active (a
// boolean, or the string Entra sends), displayName, name parts, userName or
// the primary email, and externalId, by path or in a path-less value object.
// Other attributes are left to the directory mapping.
func parseUserPatch(body patchBody) userChange {
	var c userChange
	var given, family, formatted *string
	set := func(path string, raw json.RawMessage) {
		switch strings.ToLower(path) {
		case "active":
			if b, ok := scimBool(raw); ok {
				st := statusFromActive(&b)
				c.in.Status = &st
			}
		case "displayname":
			if v, ok := scimString(raw); ok {
				c.in.DisplayName = &v
			}
		case "username", `emails[primary eq true].value`, `emails[type eq "work"].value`:
			if v, ok := scimString(raw); ok && v != "" {
				c.email = v
			}
		case "emails":
			var emails []scimEmail
			if json.Unmarshal(raw, &emails) == nil {
				if v := (scimUserPayload{Emails: emails}).email(); v != "" {
					c.email = v
				}
			}
		case "externalid":
			if v, ok := scimString(raw); ok {
				c.tag = &v
			}
		case "name":
			var n scimName
			if json.Unmarshal(raw, &n) == nil {
				given, family, formatted = &n.GivenName, &n.FamilyName, &n.Formatted
			}
		case "name.givenname":
			if v, ok := scimString(raw); ok {
				given = &v
			}
		case "name.familyname":
			if v, ok := scimString(raw); ok {
				family = &v
			}
		case "name.formatted":
			if v, ok := scimString(raw); ok {
				formatted = &v
			}
		}
	}
	for _, op := range body.Operations {
		if !strings.EqualFold(op.Op, "replace") && !strings.EqualFold(op.Op, "add") {
			continue
		}
		path := strings.Trim(op.Path, `"`)
		if path != "" {
			set(path, op.Value)
			continue
		}
		var obj map[string]json.RawMessage
		if json.Unmarshal(op.Value, &obj) != nil {
			continue
		}
		for key, raw := range obj {
			set(key, raw)
		}
	}
	if c.in.DisplayName == nil {
		switch {
		case formatted != nil && *formatted != "":
			c.in.DisplayName = formatted
		case given != nil && family != nil:
			if full := strings.TrimSpace(*given + " " + *family); full != "" {
				c.in.DisplayName = &full
			}
		}
	}
	return c
}

// scimBool reads a SCIM boolean, which Entra sends as the string "True" or
// "False".
func scimBool(raw json.RawMessage) (bool, bool) {
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b, true
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if v, err := strconv.ParseBool(strings.TrimSpace(s)); err == nil {
			return v, true
		}
	}
	return false, false
}

// scimString reads a SCIM string attribute.
func scimString(raw json.RawMessage) (string, bool) {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return strings.TrimSpace(s), true
}

// statusFromActive maps the SCIM active flag to a user status. nil → "" so
// callers can leave the status untouched.
func statusFromActive(active *bool) string {
	if active == nil {
		return ""
	}
	if *active {
		return "active"
	}
	return "suspended"
}

// recordUserEvidence writes the audit row and outbox event for a SCIM user
// change inside the caller's transaction. The actor is the organization's SCIM
// credential (scimActor).
func recordUserEvidence(ctx context.Context, tx pgx.Tx, actor audit.Actor, organizationID, userID uuid.UUID, action string, metadata map[string]any) error {
	if err := audit.Record(ctx, tx, actor.Event(organizationID, action, "user", userID, metadata)); err != nil {
		return err
	}
	payload := map[string]any{"user_id": userID, "organization_id": organizationID, "source": "scim"}
	for k, v := range metadata {
		payload[k] = v
	}
	return outbox.Enqueue(ctx, tx, outbox.Event{
		AggregateID: userID,
		Topic:       "user.events",
		EventType:   action,
		Payload:     payload,
	})
}

// userChange is a SCIM change to a user: the update, the directory's mapped
// profile (nil: none), an external ID tagging the account as provisioned (nil:
// keep the tag), a new address ("": keep it), and whether a create adopted the
// existing account.
type userChange struct {
	in      user.UpdateInput
	profile map[string]any
	tag     *string
	email   string
	adopted bool
}

// applyUserChange runs a SCIM-driven user change and its evidence in one
// transaction (Service.applyUserChange), answering a refusal with its SCIM
// error, and reports whether it ran.
func (h *Handler) applyUserChange(w http.ResponseWriter, r *http.Request, organizationID, userID uuid.UUID, c userChange, action string) bool {
	if err := h.Service.applyUserChange(r.Context(), scimActor(r), organizationID, userID, c, action); err != nil {
		writeRefusal(w, err)
		return false
	}
	return true
}

// applyUserChange runs a SCIM-driven user change and its evidence, recorded as actor's, in one
// transaction, so no provisioning change lasts without its record. A new address must be on a domain
// the organization manages; it counts as verified (the directory vouches for it) and links sent to the
// old one stop working. Every error is a *scimRefusal.
func (s *Service) applyUserChange(ctx context.Context, actor audit.Actor, organizationID, userID uuid.UUID, c userChange, action string) error {
	in := c.in
	// UpdateTx matches on the user ID alone, so without this check one organization's
	// SCIM token could suspend or rename a user in any organization.
	current, err := s.getProvisioned(ctx, organizationID, userID)
	if err != nil {
		return refusal(http.StatusNotFound, "", "user not found")
	}
	if strings.EqualFold(c.email, current.Email) {
		c.email = ""
	}
	failed := refusal(http.StatusInternalServerError, "", "update failed")
	if err := s.checkNewAddress(ctx, organizationID, c.email, failed); err != nil {
		return err
	}
	tx, err := s.users.Pool().Begin(ctx)
	if err != nil {
		return failed
	}
	defer tx.Rollback(ctx)
	q := s.q.WithTx(tx)
	state, err := s.lockForChange(ctx, tx, q, organizationID, userID, c.email, failed)
	if err != nil {
		return err
	}
	// The directory lifts only a suspension it set: one an administrator, a
	// policy or another directory set stands, and the rest of the change
	// applies.
	if in.Status != nil && *in.Status == "active" && state.Status == "suspended" && state.SuspensionSource != "scim" {
		in.Status = nil
	}
	if _, err := s.users.UpdateTx(ctx, tx, userID, in); err != nil {
		return refusal(http.StatusNotFound, "", "user not found")
	}
	if err := s.applyDirectoryVouching(ctx, tx, q, actor, organizationID, userID, c, failed); err != nil {
		return err
	}
	if in.Status != nil && *in.Status == "suspended" {
		if err := q.ClaimUnattributedSuspension(ctx, dbgen.ClaimUnattributedSuspensionParams{OrganizationID: &organizationID, ID: userID}); err != nil {
			return failed
		}
		// Every way in ends, as an administrator's suspension ends them, so a
		// later reactivation revives none.
		if _, err := authentication.EndSignIns(ctx, tx, s.signals, userID, sessionsignal.ReasonDeprovisioned); err != nil {
			return failed
		}
	}
	if c.profile != nil {
		if err := s.mapper.StoreProfile(ctx, tx, organizationID, userID, "scim:"+organizationID.String(), c.profile); err != nil {
			return refusal(http.StatusInternalServerError, "", "Profile mapping could not be saved")
		}
	}
	if err := recordUserEvidence(ctx, tx, actor, organizationID, userID, action, changeMetadata(in, c)); err != nil {
		return failed
	}
	if err := tx.Commit(ctx); err != nil {
		return failed
	}
	return nil
}

// checkNewAddress refuses a new address ("" for none) unless it is on a
// domain organizationID has verified; failed answers a fault.
func (s *Service) checkNewAddress(ctx context.Context, organizationID uuid.UUID, email string, failed error) error {
	if email == "" {
		return nil
	}
	manager, managed, err := domainverify.ManagerOf(postgres.AcrossOrganizations(ctx), s.users.Pool(), email)
	if err != nil {
		return failed
	}
	if !managed || manager != organizationID {
		return refusal(http.StatusBadRequest, "invalidValue", "userName must be on a domain the organization has verified")
	}
	return nil
}

// lockForChange locks the account the directory changes and returns its
// state, refusing an owner, and a new address (email, "" for none) for an
// account that administers the organization, as single sign-on doesn't move
// one either (ssosync): their password reset would then go there.
func (s *Service) lockForChange(ctx context.Context, tx pgx.Tx, q *dbgen.Queries, organizationID, userID uuid.UUID, email string, failed error) (dbgen.ProvisionedUserStateRow, error) {
	state, err := q.ProvisionedUserState(ctx, dbgen.ProvisionedUserStateParams{OrganizationID: organizationID, ID: userID})
	if err != nil {
		return state, refusal(http.StatusNotFound, "", "user not found")
	}
	if state.Owner {
		return state, refusal(http.StatusForbidden, "", ownerUnchangeable)
	}
	if email != "" {
		admin, err := identitylink.Administers(ctx, tx, userID, organizationID)
		if err != nil {
			return state, failed
		}
		if admin {
			return state, refusal(http.StatusForbidden, "", administratorAddressUnchangeable)
		}
	}
	return state, nil
}

// applyDirectoryVouching applies what the directory vouches for in c: the account tagged as its own,
// and a new, verified address, which ends links sent to the old one; either vouches for it from now
// on. An account nobody vouched for yet (address never proved, not directory-provisioned) keeps
// nothing whoever registered the address first set up, whichever request does it.
func (s *Service) applyDirectoryVouching(ctx context.Context, tx pgx.Tx, q *dbgen.Queries, actor audit.Actor, organizationID, userID uuid.UUID, c userChange, failed error) error {
	if c.adopted || c.tag != nil || c.email != "" {
		if err := s.forgetUnvouched(ctx, tx, actor, organizationID, userID); err != nil {
			return failed
		}
	}
	if c.tag != nil {
		if err := s.tagProvisionedTx(ctx, tx, userID, *c.tag); err != nil {
			return failed
		}
	}
	if c.email != "" {
		if err := authentication.ExpireRecoveryLinks(ctx, tx, userID); err != nil {
			return failed
		}
		if err := q.SetProvisionedUserEmail(ctx, dbgen.SetProvisionedUserEmailParams{ID: userID, OrganizationID: &organizationID, Email: c.email}); err != nil {
			if postgres.IsUnique(err) {
				return refusal(http.StatusConflict, "uniqueness", "userName already exists")
			}
			return failed
		}
	}
	return nil
}

// changeMetadata is what the audit row of a directory change records.
func changeMetadata(in user.UpdateInput, c userChange) map[string]any {
	metadata := map[string]any{}
	if in.Status != nil {
		metadata["status"] = *in.Status
	}
	if in.DisplayName != nil {
		metadata["display_name_changed"] = true
	}
	if c.email != "" {
		metadata["email_changed"] = true
	}
	if c.adopted {
		metadata["adopted"] = true
	}
	return metadata
}

// forgetUnvouched removes, inside tx, every credential and sign-in of an
// account the directory is about to vouch for when nothing vouched for its
// address yet, and records the removal, as actor's, in organizationID's trail.
func (s *Service) forgetUnvouched(ctx context.Context, tx pgx.Tx, actor audit.Actor, organizationID, userID uuid.UUID) error {
	vouched, err := identitylink.AddressVerified(ctx, tx, userID)
	if err != nil || vouched {
		return err
	}
	removed, err := authentication.ForgetCredentials(ctx, tx, userID, false)
	if err != nil {
		return err
	}
	if _, err := authentication.EndSignIns(ctx, tx, s.signals, userID, sessionsignal.ReasonAdminRevokedAll); err != nil {
		return err
	}
	// Audited only, as the other first proofs are: no event leaves for webhooks.
	return audit.Record(ctx, tx, actor.Event(organizationID, "auth.credentials_removed", "user", userID,
		map[string]any{"proof": "scim_adoption", "removed": removed}))
}

// ownerUnchangeable is the refusal of a directory change to an account that
// owns the organization: owners are changed only by people, in the console.
const ownerUnchangeable = "This account owns the organization, so the directory can't change it."

// administratorAddressUnchangeable is the refusal of a directory change to the
// address of an account that administers the organization.
const administratorAddressUnchangeable = "This account administers the organization, so the directory can't change its address. Change it in the console."
